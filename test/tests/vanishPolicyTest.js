import { writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { finalizeEvent, generateSecretKey, getPublicKey } from "@nostr/tools";
import { writeConfig, runStrfry, runRelaySuite, config } from "../utils/relay.js";

// NIP-62: a request to vanish skips the write policy plugin only when it has events to delete

const workDir = path.join(os.tmpdir(), "strfry-tests");
const relayDbDir = path.join(workDir, "relay-db");
const relayCfgPath = path.join(workDir, "vanishPolicyRelay.conf");
const pluginPath = path.join(workDir, "rejectAll.cjs");
const relayPort = 40553;

const pass = (msg) => console.log(`Pass: ${msg}`);

function expect(cond, msg) {
  if (!cond) throw new Error(msg);
}

function randomKey() {
  const sec = generateSecretKey();
  return { sec, pub: getPublicKey(sec) };
}

let ts = Math.floor(Date.now() / 1000) - 1000;

function sign(key, { kind = 1, tags = [], content = "" }) {
  return finalizeEvent({ kind, tags, content, created_at: ts++ }, key.sec);
}

const vanish = (key) => sign(key, { kind: 62, tags: [["relay", "ALL_RELAYS"]] });

// strfry import skips the write policy plugin
function importEvents(...events) {
  const res = runStrfry(["--config", relayCfgPath, "import"], { input: events.map((ev) => JSON.stringify(ev)).join("\n") + "\n", stdio: ["pipe", "ignore", "pipe"] });
  expect(res.status === 0, `import failed: ${res.stderr}`);
}

function isStored(id) {
  const res = runStrfry(["--config", relayCfgPath, "scan", JSON.stringify({ ids: [id] })], { stdio: ["ignore", "pipe", "pipe"] });
  expect(res.status === 0, `scan failed: ${res.stderr}`);
  return res.stdout.includes(id);
}

async function publish(client, event) {
  client.send(["EVENT", event]);
  return await client.waitFor((m) => m[0] === "OK" && m[1] === event.id, 5_000);
}

async function expectAccepted(client, event, what) {
  const ok = await publish(client, event);
  expect(ok[2] === true, `${what} must be accepted: ${JSON.stringify(ok)}`);
}

async function expectRejected(client, event, prefix, what) {
  const ok = await publish(client, event);
  expect(ok[2] === false && ok[3].startsWith(prefix), `${what} must be rejected with "${prefix}": ${JSON.stringify(ok)}`);
}

async function tests({ client }) {
  const alice = randomKey();
  const carol = randomKey();
  const dave = randomKey();

  await expectRejected(client, sign(alice, { content: "hello" }), "blocked: closed relay", "a note");
  pass("the plugin rejects ordinary events");

  const stranger = vanish(randomKey());
  await expectRejected(client, stranger, "blocked: closed relay", "a request to vanish from a pubkey with nothing stored");
  expect(!isStored(stranger.id), "a refused request to vanish must not be stored");
  pass("a request to vanish with nothing to delete goes through the plugin");

  const note = sign(alice, { content: "stored before the plugin" });
  importEvents(note);
  const aliceVanish = vanish(alice);
  await expectAccepted(client, aliceVanish, "a request to vanish from a pubkey with a stored note");
  expect(!isStored(note.id) && isStored(aliceVanish.id), "the request to vanish must delete the note and be stored");
  await expectRejected(client, vanish(alice), "blocked: closed relay", "a second request to vanish with nothing left to delete");
  pass("a request to vanish that deletes events skips the plugin, once");

  const wrapToCarol = sign(randomKey(), { kind: 1059, tags: [["p", carol.pub]], content: "for carol" });
  importEvents(wrapToCarol);
  await expectAccepted(client, vanish(carol), "a request to vanish from the recipient of a stored gift wrap");
  expect(!isStored(wrapToCarol.id), "the request to vanish must delete the gift wrap addressed to the pubkey");
  pass("a gift wrap addressed to the pubkey counts as something to delete");

  const wrapFromDave = sign(dave, { kind: 1059, tags: [["p", carol.pub]], content: "signed by dave" });
  importEvents(wrapFromDave);
  await expectRejected(client, vanish(dave), "blocked: closed relay", "a request to vanish from the signer of a gift wrap");
  expect(isStored(wrapFromDave.id), "a gift wrap belongs to its recipient, not to its signer");
  pass("a gift wrap signed by the pubkey doesn't count");
}

writeFileSync(
  pluginPath,
  `#!/usr/bin/env node
const rl = require("readline").createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const req = JSON.parse(line);
  console.log(JSON.stringify({ id: req.event.id, action: "reject", msg: "blocked: closed relay" }));
});
`,
  { mode: 0o755 },
);

writeConfig(config(relayDbDir, relayPort, true, "", `\n  writePolicy {\n    plugin = "${pluginPath}"\n  }\n`), relayCfgPath);

await runRelaySuite({
  relayConfigPath: relayCfgPath,
  relayPort,
  relayDbPath: relayDbDir,
  tests,
});

console.log("All vanish policy tests passed.");
