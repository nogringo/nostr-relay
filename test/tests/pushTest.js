import { spawn, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { finalizeEvent, getPublicKey } from "@nostr/tools";
import { openWebSocket, waitForRelay, WsClient } from "../utils/websocketClient.js";
import { writeConfig, cleanDb, config } from "../utils/relay.js";
import ids from "../utils/dummyIds.json" with { type: "json" };
import { signEvent, hexToBytes } from "../utils/events.js";

// NIP-9a: a push subscription (kind 30390) makes the relay POST the events it matches to its callback

const workDir = path.join(os.tmpdir(), "strfry-tests");
const relayDbDir = path.join(workDir, "relay-db");
const relayCfgPath = path.join(workDir, "pushRelay.conf");
const relayPort = 40553;
const wsUrl = `ws://127.0.0.1:${relayPort}`;

const fromSecret = (sec) => ({ sec, pub: getPublicKey(hexToBytes(sec)) });

const alice = fromSecret(ids[0].sec);
const bob = fromSecret(ids[1].sec);
const throwaway = fromSecret(ids[2].sec);

const pass = (msg) => console.log(`Pass: ${msg}`);

function expect(cond, msg) {
  if (!cond) throw new Error(msg);
}

let ts = Math.floor(Date.now() / 1000) - 1000;

function sign(key, { kind = 1, tags = [], content = "" }) {
  return finalizeEvent({ kind, tags, content, created_at: ts++ }, hexToBytes(key.sec));
}

function subscription(key, { d, relay = "wss://relay.test", callback, filters = [], ignore = [], includeEvent = false, ignoreSelf = false }) {
  const tags = [["d", d], ["relay", relay]];
  for (const f of filters) tags.push(["filter", typeof f === "string" ? f : JSON.stringify(f)]);
  for (const f of ignore) tags.push(["ignore", JSON.stringify(f)]);
  if (callback !== undefined) tags.push(["callback", callback]);
  if (includeEvent) tags.push(["include_event"]);
  if (ignoreSelf) tags.push(["ignore_self"]);
  return sign(key, { kind: 30390, tags });
}

function relayConfig(pushConfig) {
  return config(relayDbDir, relayPort, true, "", `\n  push {\n${pushConfig}\n  }\n`);
}

async function startRelay(env = {}) {
  const proc = spawn("./strfry", ["--config", relayCfgPath, "relay"], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } });
  let logs = "";
  proc.stdout.on("data", (d) => (logs += d.toString()));
  proc.stderr.on("data", (d) => (logs += d.toString()));
  const exited = new Promise((resolve) => proc.once("exit", resolve));

  await waitForRelay(wsUrl);

  return {
    logs: () => logs,
    async stop() {
      proc.kill("SIGTERM");
      if (await Promise.race([exited.then(() => true), delay(2_000)])) return;
      proc.kill("SIGKILL");
      await exited;
    },
  };
}

// GETs are challenges: /deaf/ answers something else, /missing/ answers 404, /chunked/ answers in two chunks
function startCallbackServer(tls) {
  const received = [];
  const challenges = [];

  const server = (tls ? https : http).createServer(tls ?? {}, (req, res) => {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      const { pathname, searchParams } = new URL(req.url, "http://callback");

      if (req.method === "GET") {
        const challenge = searchParams.get("challenge") ?? "";
        challenges.push({ path: req.url, challenge });
        if (pathname.startsWith("/deaf/")) return res.end("ok");
        if (pathname.startsWith("/missing/")) res.statusCode = 404;
        if (pathname.startsWith("/chunked/")) res.write(challenge.slice(0, 5));
        return res.end(challenge.slice(pathname.startsWith("/chunked/") ? 5 : 0));
      }

      received.push({ method: req.method, path: req.url, contentType: req.headers["content-type"], body: JSON.parse(body) });
      res.statusCode = pathname.startsWith("/gone/") ? 404 : 200;
      res.end();
    });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, received, challenges, port: server.address().port }));
  });
}

async function connect() {
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

async function expectAccepted(client, event, what) {
  const ok = await publish(client, event);
  expect(ok[2] === true, `${what} must be accepted: ${JSON.stringify(ok)}`);
}

async function expectRejected(client, event, reason, what) {
  const ok = await publish(client, event);
  expect(ok[2] === false && ok[3].startsWith(reason), `${what} must be rejected with "${reason}": ${JSON.stringify(ok)}`);
}

async function query(client, subId, filter) {
  client.send(["REQ", subId, filter]);
  const msgs = await client.collectUntil((m) => (m[0] === "EOSE" || m[0] === "CLOSED") && m[1] === subId, 4_000);
  client.send(["CLOSE", subId]);
  const closed = msgs.find((m) => m[0] === "CLOSED");
  return { closed, events: msgs.filter((m) => m[0] === "EVENT" && m[1] === subId).map((m) => m[2]) };
}

async function supportedNips() {
  const res = await fetch(`http://127.0.0.1:${relayPort}/`, { headers: { Accept: "application/nostr+json" } });
  return (await res.json()).supported_nips;
}

async function waitForPush(callbacks, eventId, pathPrefix, timeoutMs = 4_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const found = callbacks.received.find((r) => r.body.id === eventId && r.path.startsWith(pathPrefix));
    if (found) return found;
    await delay(50);
  }
  throw new Error(`no push of ${eventId} to ${pathPrefix}`);
}

async function expectNoPush(callbacks, eventId, waitMs = 1_500, pathPrefix = "") {
  await delay(waitMs);
  const found = callbacks.received.filter((r) => r.body.id === eventId && r.path.startsWith(pathPrefix));
  expect(found.length === 0, `${eventId} must not be pushed to ${pathPrefix || "any callback"}: ${JSON.stringify(found)}`);
}

async function mainSuite(callbacks) {
  const cb = `http://127.0.0.1:${callbacks.port}`;

  writeConfig(relayConfig("    allowPrivateCallbacks = true"), relayCfgPath);
  let relay = await startRelay();

  const observer = await connect();
  let aliceClient = await connect();
  const bobClient = await connect();

  try {
    await authenticate(aliceClient, alice);
    await authenticate(bobClient, bob);

    expect((await supportedNips()).includes("9a"), "NIP-11 must list 9a");
    pass("NIP-11 lists 9a");

    const filter = { kinds: [1], "#t": ["push-test"] };
    await expectRejected(observer, subscription(alice, { d: "x", relay: "wss://other.example", callback: `${cb}/ok/x`, filters: [filter] }), "invalid: push subscription does not name this relay", "a subscription for another relay");
    await expectRejected(observer, subscription(alice, { d: "x", filters: [filter] }), "invalid: push subscription has no callback", "a subscription without callback");
    await expectRejected(observer, subscription(alice, { d: "x", callback: "ftp://example.com/x", filters: [filter] }), "invalid: bad callback", "a subscription with an ftp callback");
    await expectRejected(observer, subscription(alice, { d: "x", callback: `${cb}/ok/x` }), "invalid: push subscription has no filter", "a subscription without filter");
    await expectRejected(observer, subscription(alice, { d: "x", callback: `${cb}/ok/x`, filters: ["{not json"] }), "invalid: bad filter tag", "a subscription with a malformed filter");
    await expectRejected(observer, subscription(alice, { d: "x", callback: `${cb}/ok/x`, filters: [{ search: "nostr" }] }), "invalid: bad filter tag", "a subscription with an unsupported filter");
    pass("subscriptions the relay can't fulfill are rejected");

    await expectRejected(observer, subscription(alice, { d: "x", callback: `${cb}/deaf/x`, filters: [filter] }), "invalid: callback verification failed: the response is not the challenge", "a callback that doesn't echo the challenge");
    await expectRejected(observer, subscription(alice, { d: "x", callback: `${cb}/missing/x`, filters: [filter] }), "invalid: callback verification failed: answered 404", "a callback that answers the challenge with 404");
    await expectRejected(observer, subscription(alice, { d: "x", callback: "http://127.0.0.1:1/x", filters: [filter] }), "invalid: callback verification failed: can't connect to 127.0.0.1", "an unreachable callback");
    expect((await query(aliceClient, "refused", { kinds: [30390], authors: [alice.pub], "#d": ["x"] })).events.length === 0, "a subscription that failed the challenge must not be stored");
    pass("subscriptions whose callback fails the challenge are rejected");

    await expectAccepted(observer, subscription(alice, { d: "chunked", callback: `${cb}/chunked/x`, filters: [{ kinds: [1], "#t": ["never"] }] }), "a callback that echoes the challenge in chunks");
    await expectAccepted(observer, subscription(alice, { d: "query", callback: `${cb}/ok/query?token=abc`, filters: [{ kinds: [1], "#t": ["never"] }] }), "a callback with a query string");
    const queryChallenge = callbacks.challenges.find((c) => c.path.startsWith("/ok/query?"));
    expect(queryChallenge && queryChallenge.path === `/ok/query?token=abc&challenge=${queryChallenge.challenge}` && queryChallenge.challenge.length >= 20, `the challenge must be appended to the query: ${JSON.stringify(queryChallenge)}`);
    pass("the challenge is appended to the callback, and a chunked answer is read");

    const notes = subscription(alice, { d: "notes", callback: `${cb}/ok/notes`, filters: [filter], ignore: [{ "#t": ["muted"] }], includeEvent: true });
    await expectAccepted(observer, notes, "a valid subscription");
    const notesChallenge = callbacks.challenges.find((c) => c.path.startsWith("/ok/notes?"));
    expect(notesChallenge && notesChallenge.path === `/ok/notes?challenge=${notesChallenge.challenge}`, `the relay must send a challenge before accepting: ${JSON.stringify(callbacks.challenges)}`);

    const anonymous = await query(observer, "anon", { kinds: [30390] });
    expect(anonymous.closed && anonymous.closed[2].startsWith("auth-required:"), `reading push subscriptions must require AUTH: ${JSON.stringify(anonymous)}`);
    expect((await query(observer, "anon-by-id", { ids: [notes.id] })).events.length === 0, "an unauthenticated client must not read a push subscription by id");
    expect((await query(bobClient, "bob", { kinds: [30390], authors: [alice.pub] })).events.length === 0, "another user must not read a push subscription");
    expect((await query(aliceClient, "alice", { kinds: [30390], authors: [alice.pub] })).events.some((ev) => ev.id === notes.id), "the author must read its push subscription");

    bobClient.send(["COUNT", "bob-count", { kinds: [30390] }]);
    const bobCount = await bobClient.waitFor((m) => m[1] === "bob-count");
    expect(bobCount[0] === "CLOSED", `another user must not count push subscriptions: ${JSON.stringify(bobCount)}`);
    pass("only the author reads its push subscription");

    const note = sign(bob, { tags: [["t", "push-test"]], content: "hello" });
    await expectAccepted(bobClient, note, "a matching note");
    const push = await waitForPush(callbacks, note.id, "/ok/notes");
    expect(push.method === "POST" && push.contentType === "application/json", `push must be a JSON POST: ${JSON.stringify(push)}`);
    expect(push.body.relay === "wss://relay.test/", `push must name the relay: ${JSON.stringify(push.body)}`);
    expect(push.body.event && push.body.event.id === note.id && push.body.event.sig === note.sig, `push must include the event: ${JSON.stringify(push.body)}`);
    pass("a matching event is POSTed with the event included");

    const muted = sign(bob, { tags: [["t", "push-test"], ["t", "muted"]] });
    const unrelated = sign(bob, { tags: [["t", "other"]] });
    await expectAccepted(bobClient, muted, "a muted note");
    await expectAccepted(bobClient, unrelated, "an unrelated note");
    await expectNoPush(callbacks, muted.id);
    await expectNoPush(callbacks, unrelated.id, 0);
    pass("ignored and unmatched events are not pushed");

    await expectAccepted(observer, subscription(alice, { d: "reactions", relay: "wss://Alias.Test:443", callback: `${cb}/ok/reactions`, filters: [{ kinds: [7] }] }), "a subscription naming the relay alias");
    const reaction = sign(bob, { kind: 7, tags: [["e", note.id]], content: "+" });
    await expectAccepted(bobClient, reaction, "a reaction");
    const idsOnly = await waitForPush(callbacks, reaction.id, "/ok/reactions");
    expect(JSON.stringify(Object.keys(idsOnly.body).sort()) === '["id","relay"]', `push without include_event must only carry id and relay: ${JSON.stringify(idsOnly.body)}`);
    expect(idsOnly.body.relay === "wss://alias.test/", `push must name the relay as the subscription did, normalized: ${JSON.stringify(idsOnly.body)}`);
    pass("without include_event only the id and the relay are sent");

    await expectAccepted(observer, subscription(alice, { d: "wraps", callback: `${cb}/ok/wraps`, filters: [{ kinds: [1059] }] }), "a gift wrap subscription");
    const wrapToAlice = sign(throwaway, { kind: 1059, tags: [["p", alice.pub]], content: "for alice" });
    const wrapToBob = sign(throwaway, { kind: 1059, tags: [["p", bob.pub]], content: "for bob" });
    await expectAccepted(observer, wrapToBob, "a gift wrap to bob");
    await expectAccepted(observer, wrapToAlice, "a gift wrap to alice");
    await waitForPush(callbacks, wrapToAlice.id, "/ok/wraps");
    await expectNoPush(callbacks, wrapToBob.id, 0);
    pass("events are only pushed to subscribers allowed to read them");

    await expectAccepted(observer, subscription(alice, { d: "dms", callback: `${cb}/ok/dms`, filters: [{ kinds: [1059], "#p": [alice.pub] }], ignoreSelf: true }), "a gift wrap subscription with ignore_self");
    const selfCopy = sign(throwaway, { kind: 1059, tags: [["p", alice.pub]], content: "alice's own copy" });
    const wrapFromBob = sign(throwaway, { kind: 1059, tags: [["p", alice.pub]], content: "from bob" });
    const unauthedWrap = sign(throwaway, { kind: 1059, tags: [["p", alice.pub]], content: "from anyone" });
    await expectAccepted(aliceClient, selfCopy, "a gift wrap published over alice's connection");
    await expectAccepted(bobClient, wrapFromBob, "a gift wrap published over bob's connection");
    await expectAccepted(observer, unauthedWrap, "a gift wrap published without AUTH");
    await waitForPush(callbacks, wrapFromBob.id, "/ok/dms");
    await waitForPush(callbacks, unauthedWrap.id, "/ok/dms");
    await waitForPush(callbacks, selfCopy.id, "/ok/wraps");
    await expectNoPush(callbacks, selfCopy.id, 500, "/ok/dms");
    pass("ignore_self skips events received over the author's authenticated connection");

    await expectAccepted(observer, subscription(alice, { d: "notes", callback: `${cb}/ok/notes-v2`, filters: [{ kinds: [1], "#t": ["push-test-2"] }] }), "a replacing subscription");
    const oldFilter = sign(bob, { tags: [["t", "push-test"]] });
    const newFilter = sign(bob, { tags: [["t", "push-test-2"]] });
    await expectAccepted(bobClient, oldFilter, "a note for the replaced filter");
    await expectAccepted(bobClient, newFilter, "a note for the new filter");
    await waitForPush(callbacks, newFilter.id, "/ok/notes-v2");
    await expectNoPush(callbacks, oldFilter.id, 0);
    pass("a replaced subscription stops, its replacement takes over");

    await expectAccepted(aliceClient, sign(alice, { kind: 5, tags: [["a", `30390:${alice.pub}:notes`]] }), "a deletion of the subscription");
    const afterDeletion = sign(bob, { tags: [["t", "push-test-2"]] });
    await expectAccepted(bobClient, afterDeletion, "a note after the deletion");
    await expectNoPush(callbacks, afterDeletion.id);
    pass("a deleted subscription stops");

    await expectAccepted(observer, subscription(alice, { d: "gone", callback: `${cb}/gone/x`, filters: [{ kinds: [1], "#t": ["gone-test"] }] }), "a subscription whose callback answers 404");
    const first = sign(bob, { tags: [["t", "gone-test"]] });
    await expectAccepted(bobClient, first, "a note for the 404 callback");
    await waitForPush(callbacks, first.id, "/gone/x");
    await delay(500);
    expect((await query(aliceClient, "gone", { kinds: [30390], authors: [alice.pub], "#d": ["gone"] })).events.length === 0, "a subscription whose callback answered 404 must be deleted");
    const second = sign(bob, { tags: [["t", "gone-test"]] });
    await expectAccepted(bobClient, second, "a second note for the 404 callback");
    await expectNoPush(callbacks, second.id);
    pass("a 404 from the callback deletes the subscription");

    await expectAccepted(observer, subscription(alice, { d: "persist", callback: `${cb}/ok/persist`, filters: [{ kinds: [1], "#t": ["after-restart"] }] }), "a subscription before the restart");
    await aliceClient.close();
    await relay.stop();
    relay = await startRelay();
    aliceClient = await connect();
    const afterRestart = sign(bob, { tags: [["t", "after-restart"]] });
    await expectAccepted(aliceClient, afterRestart, "a note after the restart");
    await waitForPush(callbacks, afterRestart.id, "/ok/persist");
    pass("subscriptions survive a restart");
  } catch (e) {
    throw new Error(`${e.message}\n\nRelay logs:\n${relay.logs()}`);
  } finally {
    await Promise.allSettled([observer.close(), aliceClient.close(), bobClient.close()]);
    await relay.stop();
  }
}

async function defaultsSuite(callbacks) {
  writeConfig(relayConfig("    enabled = true"), relayCfgPath);
  const relay = await startRelay();
  const client = await connect();

  try {
    const filter = { kinds: [1], "#t": ["private-test"] };
    await expectRejected(client, subscription(alice, { d: "v4", callback: `http://127.0.0.1:${callbacks.port}/ok/v4`, filters: [filter] }), "invalid: callback is not a public address", "a loopback IPv4 callback");
    await expectRejected(client, subscription(alice, { d: "v6", callback: `http://[::1]:${callbacks.port}/ok/v6`, filters: [filter] }), "invalid: callback is not a public address", "a loopback IPv6 callback");
    await expectRejected(client, subscription(alice, { d: "lan", callback: "https://192.168.1.10/ok/lan", filters: [filter] }), "invalid: callback is not a public address", "a private network callback");

    await expectRejected(client, subscription(alice, { d: "name", callback: `http://localhost:${callbacks.port}/ok/name`, filters: [filter] }), "invalid: callback verification failed: can't connect to localhost: refusing to connect to a non-public address", "a callback whose name resolves to a private address");
    expect(!callbacks.challenges.some((c) => c.path.startsWith("/ok/name")), "the relay must not reach a callback that resolves to a private address");
    pass("callbacks on private addresses are refused by default");

    writeConfig(relayConfig("    enabled = false"), relayCfgPath);
    const deadline = Date.now() + 5_000;
    while ((await supportedNips()).includes("9a")) {
      expect(Date.now() < deadline, "NIP-11 must drop 9a once push is disabled");
      await delay(100);
    }
    await expectRejected(client, subscription(alice, { d: "disabled", callback: "https://push.example.com/x", filters: [filter] }), "invalid: push subscriptions are not accepted here", "a subscription while push is disabled");
    pass("disabling push drops 9a from NIP-11 and rejects subscriptions");
  } catch (e) {
    throw new Error(`${e.message}\n\nRelay logs:\n${relay.logs()}`);
  } finally {
    await client.close();
    await relay.stop();
  }
}

function selfSignedCert(name, subjectAltName) {
  const keyPath = path.join(workDir, `${name}.key`);
  const certPath = path.join(workDir, `${name}.crt`);
  const res = spawnSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
    "-subj", `/CN=${name}`, "-addext", `subjectAltName=${subjectAltName}`, "-keyout", keyPath, "-out", certPath,
  ], { stdio: ["ignore", "ignore", "pipe"], encoding: "utf-8" });
  if (res.status !== 0) throw new Error(`openssl failed: ${res.stderr}`);
  return { key: readFileSync(keyPath), cert: readFileSync(certPath), certPath };
}

async function tlsSuite() {
  const trusted = selfSignedCert("localhost", "DNS:localhost,IP:127.0.0.1");
  const otherName = selfSignedCert("other.test", "DNS:other.test");
  const bundlePath = path.join(workDir, "push-ca-bundle.crt");
  writeFileSync(bundlePath, Buffer.concat([trusted.cert, otherName.cert]));

  const good = await startCallbackServer(trusted);
  const mismatched = await startCallbackServer(otherName);

  writeConfig(relayConfig("    allowPrivateCallbacks = true"), relayCfgPath);
  const relay = await startRelay({ SSL_CERT_FILE: bundlePath });
  const client = await connect();

  try {
    const filter = { kinds: [1], "#t": ["tls-test"] };
    await expectAccepted(client, subscription(alice, { d: "name", callback: `https://localhost:${good.port}/ok/name`, filters: [filter] }), "an https callback");
    await expectAccepted(client, subscription(alice, { d: "ip", callback: `https://127.0.0.1:${good.port}/ok/ip`, filters: [filter] }), "an https callback on an IP address");
    await expectRejected(client, subscription(alice, { d: "mismatch", callback: `https://localhost:${mismatched.port}/ok/mismatch`, filters: [filter] }), "invalid: callback verification failed: TLS: ", "an https callback with a certificate for another name");
    pass("a certificate for another name is refused");

    const note = sign(bob, { tags: [["t", "tls-test"]] });
    await expectAccepted(client, note, "a matching note");
    await waitForPush(good, note.id, "/ok/name");
    await waitForPush(good, note.id, "/ok/ip");
    pass("events are POSTed over https to verified hosts");
  } catch (e) {
    throw new Error(`${e.message}\n\nRelay logs:\n${relay.logs()}`);
  } finally {
    await client.close();
    await relay.stop();
    good.server.close();
    mismatched.server.close();
  }
}

const callbacks = await startCallbackServer();

try {
  cleanDb(relayDbDir);
  await mainSuite(callbacks);
  cleanDb(relayDbDir);
  await defaultsSuite(callbacks);
  cleanDb(relayDbDir);
  await tlsSuite();
} finally {
  callbacks.server.close();
}
