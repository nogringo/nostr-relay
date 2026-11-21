import os from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { finalizeEvent, getPublicKey } from "@nostr/tools";
import { openWebSocket, WsClient } from "../utils/websocketClient.js";
import { writeConfig, cleanDb, runStrfry, runRelaySuite, config } from "../utils/relay.js";
import ids from "../utils/dummyIds.json" with { type: "json" };
import { signEvent, hexToBytes } from "../utils/events.js";

// NIP-59: the sender of a gift wrap must not learn when its recipient deleted it

const workDir = path.join(os.tmpdir(), "strfry-tests");
const relayDbDir = path.join(workDir, "relay-db");
const syncDbDir = path.join(workDir, "sync-db");
const relayCfgPath = path.join(workDir, "giftWrapPrivacyRelay.conf");
const syncCfgPath = path.join(workDir, "giftWrapPrivacySync.conf");
const relayPort = 40553;

const sender = ids[0];
const recipient = ids[1];
const throwaway = ids[2];

const pass = (msg) => console.log(`Pass: ${msg}`);

function expect(cond, msg) {
  if (!cond) throw new Error(msg);
}

let ts = Math.floor(Date.now() / 1000) - 1000;

function sign(key, { kind, tags = [], content = "" }) {
  return finalizeEvent({ kind, tags, content, created_at: ts++ }, hexToBytes(key.sec));
}

async function connect(wsUrl) {
  return new WsClient(await openWebSocket(wsUrl));
}

async function authenticate(client, key) {
  client.send(["REQ", "auth-trigger", { kinds: [1059] }]);
  const challenge = (await client.waitFor((m) => m[0] === "AUTH"))[1];
  await client.waitFor((m) => m[0] === "CLOSED" && m[1] === "auth-trigger");
  client.send(["AUTH", signEvent(challenge, "wss://relay.test", key.sec)]);
  await client.waitFor((m) => m[0] === "OK" && m[3] === "successfully authenticated", 10_000);
}

async function publish(client, event) {
  client.send(["EVENT", event]);
  return await client.waitFor((m) => m[0] === "OK" && m[1] === event.id, 5_000);
}

async function query(client, subId, filter) {
  client.send(["REQ", subId, filter]);
  const msgs = await client.collectUntil((m) => m[0] === "EOSE" && m[1] === subId, 4_000);
  client.send(["CLOSE", subId]);
  return msgs.filter((m) => m[0] === "EVENT" && m[1] === subId).map((m) => m[2]);
}

async function count(client, subId, filter) {
  client.send(["COUNT", subId, filter]);
  const msg = await client.waitFor((m) => m[1] === subId, 4_000);
  expect(msg[0] === "COUNT", `COUNT ${subId} was refused: ${JSON.stringify(msg)}`);
  return msg[2].count;
}

function syncNeeds(wsUrl, filter) {
  cleanDb(syncDbDir);
  writeConfig(config(syncDbDir, 40555), syncCfgPath);

  const res = runStrfry(
    ["--config", syncCfgPath, "sync", wsUrl, "--filter", JSON.stringify(filter), "--print-missing", "--timeout", "10"],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  if (res.status !== 0) throw new Error(`negentropy sync failed: ${res.stderr || res.stdout}`);

  return res.stdout
    .trim()
    .split("\n")
    .filter((line) => line.startsWith("need,"))
    .map((line) => line.slice("need,".length));
}

async function tests({ wsUrl, client: observer }) {
  expect(getPublicKey(hexToBytes(recipient.sec)) === recipient.pub, "dummy keys must match");

  const recipientClient = await connect(wsUrl);
  const throwawayClient = await connect(wsUrl);

  try {
    await authenticate(recipientClient, recipient);
    await authenticate(throwawayClient, throwaway);

    const wrap = sign(throwaway, { kind: 1059, tags: [["p", recipient.pub]], content: "wrapped" });
    expect((await publish(observer, wrap))[2] === true, "gift wrap must be accepted");

    expect((await query(recipientClient, "recipient-wraps", { kinds: [1059], "#p": [recipient.pub] })).some((ev) => ev.id === wrap.id), "recipient must read the gift wrap");
    expect((await query(throwawayClient, "throwaway-wraps", { kinds: [1059], authors: [throwaway.pub] })).length === 0, "the throwaway signing key must not read the gift wrap");
    pass("only the recipient reads a gift wrap");

    expect((await count(observer, "count-by-id", { ids: [wrap.id] })) === 0, "COUNT without kinds must not count a hidden gift wrap");
    expect((await count(observer, "count-by-p", { "#p": [recipient.pub] })) === 0, "COUNT without kinds must not count the recipient's private events");
    expect((await count(recipientClient, "count-own", { kinds: [1059], "#p": [recipient.pub] })) === 1, "the recipient must count its own gift wrap");
    pass("COUNT only counts what the client can read");

    const note = sign(sender, { kind: 1, content: "public note" });
    await publish(observer, note);
    const publicDeletion = sign(sender, { kind: 5, tags: [["e", note.id]] });
    await publish(observer, publicDeletion);

    observer.send(["REQ", "live-deletions", { kinds: [5], "#e": [wrap.id] }]);
    await observer.waitFor((m) => m[0] === "EOSE" && m[1] === "live-deletions");

    const deletion = sign(recipient, { kind: 5, tags: [["e", wrap.id]] });
    expect((await publish(recipientClient, deletion))[2] === true, "recipient deletion must be accepted");
    expect((await query(recipientClient, "wrap-gone", { kinds: [1059], "#p": [recipient.pub] })).length === 0, "the gift wrap must be deleted");

    await delay(1_500);
    observer.send(["CLOSE", "live-deletions"]);
    const live = [];
    while (observer.queue.length) live.push(observer.queue.shift());
    expect(!live.some((m) => m[0] === "EVENT" && m[1] === "live-deletions"), "a live REQ must not deliver the gift wrap deletion");

    expect((await query(observer, "stored-deletions", { kinds: [5] })).every((ev) => ev.id !== deletion.id), "a REQ must not return the gift wrap deletion");
    expect((await count(observer, "count-deletions", { kinds: [5], "#e": [wrap.id] })) === 0, "COUNT must not count the gift wrap deletion");
    expect((await query(recipientClient, "own-deletions", { kinds: [5], authors: [recipient.pub] })).some((ev) => ev.id === deletion.id), "the recipient must read its own deletion");
    expect((await query(observer, "public-deletion", { kinds: [5], authors: [sender.pub] })).some((ev) => ev.id === publicDeletion.id), "other deletions must stay public");
    pass("a gift wrap deletion is only served to its author");

    const needs = syncNeeds(wsUrl, { kinds: [5] });
    expect(needs.includes(publicDeletion.id) && !needs.includes(deletion.id), "negentropy must not expose the gift wrap deletion");
    pass("negentropy hides the gift wrap deletion");

    const resent = await publish(observer, wrap);
    expect(resent[2] === true && resent[3] === "duplicate: have this event", `re-sent deleted wrap must look like a duplicate, got ${JSON.stringify(resent)}`);
    expect((await query(recipientClient, "wrap-still-gone", { kinds: [1059], "#p": [recipient.pub] })).length === 0, "the re-sent gift wrap must stay deleted");
    pass("re-sending a deleted gift wrap answers duplicate");

    const redeletion = sign(recipient, { kind: 5, tags: [["e", wrap.id]] });
    await publish(recipientClient, redeletion);
    expect((await query(observer, "redeletion", { kinds: [5], "#e": [wrap.id] })).length === 0, "a second deletion of the same gift wrap must stay hidden");
    pass("a second deletion of a gift wrap stays hidden");

    const elsewhere = sign(recipient, { kind: 5, tags: [["e", "f".repeat(64)], ["k", "1059"]] });
    await publish(recipientClient, elsewhere);
    expect((await query(observer, "k-tag", { kinds: [5], authors: [recipient.pub] })).length === 0, "a deletion naming kind 1059 must stay hidden");
    pass("a deletion naming kind 1059 stays hidden");
  } finally {
    await recipientClient.close();
    await throwawayClient.close();
  }
}

async function main() {
  console.log("* gift wrap privacy relay integration tests");

  writeConfig(config(relayDbDir, relayPort, true), relayCfgPath);

  await runRelaySuite({ relayConfigPath: relayCfgPath, relayPort, relayDbPath: relayDbDir, tests });

  console.log("All gift wrap privacy tests passed!");
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
});
