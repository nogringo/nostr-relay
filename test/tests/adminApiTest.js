import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { finalizeEvent, generateSecretKey, getPublicKey } from "@nostr/tools";
import { openWebSocket, WsClient } from "../utils/websocketClient.js";
import { writeConfig, runStrfry, runRelaySuite, config } from "../utils/relay.js";
import ids from "../utils/dummyIds.json" with { type: "json" };
import { buildEvent, bytesToHex, hexToBytes, sha256, signEvent } from "../utils/events.js";

// NIP-86 relay management API, authorized with NIP-98

const workDir = path.join(os.tmpdir(), "strfry-tests");
const relayDbDir = path.join(workDir, "relay-db");
const relayCfgPath = path.join(workDir, "adminApiRelay.conf");
const relayPort = 40553;
const httpUrl = `http://127.0.0.1:${relayPort}/`;

const fromSecret = (sec) => ({ sec, pub: getPublicKey(hexToBytes(sec)) });

const admin = fromSecret(ids[0].sec);
const alice = fromSecret(ids[1].sec);
const bob = fromSecret(ids[2].sec);

function randomKey() {
  return fromSecret(bytesToHex(generateSecretKey()));
}

const pass = (msg) => console.log(`Pass: ${msg}`);

function expect(cond, msg) {
  if (!cond) throw new Error(msg);
}

const now = () => Math.floor(Date.now() / 1000);
let ts = now() - 1000;

function sign(key, { kind = 1, tags = [], content = "" }) {
  return finalizeEvent({ kind, tags, content, created_at: ts++ }, hexToBytes(key.sec));
}

function authorization(key, body, overrides = {}) {
  const { u = "wss://relay.test", method = "POST", payload = sha256(body), kind = 27235, created_at = now() } = overrides;
  const event = finalizeEvent({ kind, created_at, content: "", tags: [["u", u], ["method", method], ["payload", payload]] }, hexToBytes(key.sec));
  return "Nostr " + Buffer.from(JSON.stringify(event)).toString("base64");
}

async function rpc(method, params = [], { key = admin, auth, body } = {}) {
  body ??= JSON.stringify({ method, params });
  const headers = { "Content-Type": "application/nostr+json+rpc" };
  const authHeader = auth === undefined ? authorization(key, body) : auth;
  if (authHeader !== null) headers.Authorization = authHeader;

  const res = await fetch(httpUrl, { method: "POST", headers, body });
  return { status: res.status, ...(await res.json()) };
}

async function call(method, params = []) {
  const res = await rpc(method, params);
  expect(res.status === 200 && res.error === undefined, `${method} failed: ${JSON.stringify(res)}`);
  return res.result;
}

async function connect(wsUrl) {
  return new WsClient(await openWebSocket(wsUrl));
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

async function query(client, subId, filter) {
  client.send(["REQ", subId, filter]);
  const msgs = await client.collectUntil((m) => m[0] === "EOSE" && m[1] === subId, 4_000);
  client.send(["CLOSE", subId]);
  return msgs.filter((m) => m[0] === "EVENT" && m[1] === subId).map((m) => m[2]);
}

async function isStored(client, id) {
  return (await query(client, `stored-${id.slice(0, 8)}`, { ids: [id] })).length === 1;
}

async function waitForClose(ws, timeoutMs = 4_000) {
  if (ws.readyState === ws.CLOSED) return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("websocket was not closed")), timeoutMs);
    ws.addEventListener("close", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

async function authorizationTests() {
  const body = JSON.stringify({ method: "supportedmethods", params: [] });

  expect((await rpc("supportedmethods", [], { auth: null })).status === 401, "a request without Authorization must get 401");

  const notAdmin = await rpc("supportedmethods", [], { key: alice });
  expect(notAdmin.status === 401 && notAdmin.error.includes("not an admin"), `a non-admin must get 401: ${JSON.stringify(notAdmin)}`);

  const refusals = [
    [{ u: "wss://other.test" }, "a u tag naming another relay"],
    [{ method: "GET" }, "a method tag other than POST"],
    [{ payload: sha256("something else") }, "a payload tag that is not the body hash"],
    [{ created_at: now() - 120 }, "a stale created_at"],
    [{ kind: 1 }, "an event that is not kind 27235"],
  ];

  for (const [overrides, what] of refusals) {
    const res = await rpc("supportedmethods", [], { body, auth: authorization(admin, body, overrides) });
    expect(res.status === 401, `${what} must get 401: ${JSON.stringify(res)}`);
  }

  const methods = await call("supportedmethods");
  expect(methods.includes("banpubkey") && methods.includes("stats"), "supportedmethods must list the methods");

  for (const u of ["https://relay.test/", "wss://alias.test:443"]) {
    const res = await rpc("supportedmethods", [], { body, auth: authorization(admin, body, { u }) });
    expect(res.status === 200, `u tag ${u} must be accepted: ${JSON.stringify(res)}`);
  }

  const unknown = await rpc("nosuchmethod");
  expect(unknown.status === 200 && unknown.error.includes("unsupported method"), "an unknown method must return an error");

  const malformed = await rpc(null, null, { body: "[]" });
  expect(malformed.status === 400, "a body that is not an object must get 400");

  const tooLarge = await rpc(null, null, { body: JSON.stringify({ method: "supportedmethods", params: ["x".repeat(70_000)] }) });
  expect(tooLarge.status === 413, "a body over the size limit must get 413");

  pass("only a NIP-98 authorization signed by an admin for this relay is accepted");
}

async function pubkeyBanTests(client) {
  const note = sign(alice, { content: "alice before ban" });
  await expectAccepted(client, note, "alice's note");
  await expectAccepted(client, sign(bob, { content: "bob keeps the latest levId" }), "bob's note");

  await call("banpubkey", [alice.pub, "spam"]);
  const banned = await call("listbannedpubkeys");
  expect(banned.some((b) => b.pubkey === alice.pub && b.reason === "spam"), "the ban must be listed with its reason");

  expect(!(await isStored(client, note.id)), "a banned pubkey's events must be deleted");
  await expectRejected(client, sign(alice, { content: "alice after ban" }), "blocked:", "a banned pubkey's new event");

  const vanish = sign(alice, { kind: 62, tags: [["relay", "ALL_RELAYS"]] });
  await expectAccepted(client, vanish, "a banned pubkey's request to vanish");

  await call("unbanpubkey", [alice.pub]);
  expect((await call("listbannedpubkeys")).length === 0, "unbanpubkey must empty the ban list");
  await expectAccepted(client, sign(alice, { content: "alice after unban" }), "an unbanned pubkey's event");

  pass("banpubkey deletes and blocks a pubkey, unbanpubkey lifts the ban");
}

async function eventBanTests(client) {
  const note = sign(bob, { content: "to be banned" });
  await expectAccepted(client, note, "bob's note");
  await expectAccepted(client, sign(bob, { content: "bob keeps the latest levId" }), "bob's next note");

  await call("banevent", [note.id, "off-topic"]);
  expect((await call("listbannedevents")).some((b) => b.id === note.id && b.reason === "off-topic"), "the banned event must be listed");
  expect(!(await isStored(client, note.id)), "a banned event must be deleted");
  await expectRejected(client, note, "blocked:", "a banned event's re-broadcast");

  await call("unbanevent", [note.id]);
  await expectAccepted(client, note, "an unbanned event");

  const latest = sign(bob, { content: "banned while it is the latest event" });
  await expectAccepted(client, latest, "the latest event");
  await call("banevent", [latest.id]);
  await expectAccepted(client, sign(bob, { content: "a newer event" }), "a newer event");

  const deadline = Date.now() + 15_000;
  while (await isStored(client, latest.id)) {
    expect(Date.now() < deadline, "the banned latest event must be deleted once a newer event is stored");
    await delay(500);
  }

  pass("banevent deletes and blocks an event, even the latest one");
}

async function allowListTests(client) {
  const throwaway = randomKey();

  await call("allowpubkey", [bob.pub, "member"]);
  expect((await call("listallowedpubkeys")).some((a) => a.pubkey === bob.pub && a.reason === "member"), "the allowed pubkey must be listed");

  await expectAccepted(client, sign(bob, { content: "member" }), "an allowed pubkey's event");
  await expectAccepted(client, sign(admin, { content: "admin" }), "an admin's event");
  await expectRejected(client, sign(alice, { content: "outsider" }), "restricted:", "a pubkey outside the allow list");

  await expectAccepted(client, sign(throwaway, { kind: 1059, tags: [["p", bob.pub]] }), "a gift wrap for an allowed recipient");
  await expectRejected(client, sign(throwaway, { kind: 1059, tags: [["p", alice.pub]] }), "restricted:", "a gift wrap for an outsider");

  const info = await (await fetch(httpUrl, { headers: { Accept: "application/nostr+json" } })).json();
  expect(info.limitation.restricted_writes === true, "NIP-11 must announce restricted writes");

  await call("banpubkey", [bob.pub]);
  expect((await call("listallowedpubkeys")).length === 0, "banpubkey must remove the pubkey from the allow list");
  await call("allowpubkey", [bob.pub]);
  expect((await call("listbannedpubkeys")).length === 0, "allowpubkey must remove the pubkey from the ban list");

  await call("unallowpubkey", [bob.pub]);
  await expectAccepted(client, sign(alice, { content: "open again" }), "any pubkey once the allow list is empty");

  pass("allowpubkey turns the relay into an allow list, admins and recipients of gift wraps included");
}

async function kindTests(client) {
  await call("disallowkind", [7]);
  expect(JSON.stringify(await call("listdisallowedkinds")) === "[7]", "the disallowed kind must be listed");
  await expectRejected(client, sign(bob, { kind: 7, content: "+" }), "blocked:", "a disallowed kind");
  await expectAccepted(client, sign(bob, { kind: 1 }), "another kind");

  await call("undisallowkind", [7]);
  await expectAccepted(client, sign(bob, { kind: 7, content: "+" }), "a kind no longer disallowed");

  await call("allowkind", [1]);
  expect(JSON.stringify(await call("listallowedkinds")) === "[1]", "the allowed kind must be listed");
  await expectAccepted(client, sign(bob, { kind: 1 }), "an allowed kind");
  await expectRejected(client, sign(bob, { kind: 7, content: "+" }), "blocked:", "a kind outside the allow list");
  await expectAccepted(client, sign(bob, { kind: 62, tags: [["relay", "wss://relay.test"]] }), "a request to vanish outside the allow list");

  await call("disallowkind", [1]);
  expect((await call("listallowedkinds")).length === 0, "disallowkind must remove the kind from the allow list");
  await call("allowkind", [1]);
  expect((await call("listdisallowedkinds")).length === 0, "allowkind must remove the kind from the disallow list");
  await call("unallowkind", [1]);

  pass("kinds can be allowed and disallowed");
}

async function protectedEventTests(wsUrl, client) {
  const supportedNips = async () => (await (await fetch(httpUrl, { headers: { Accept: "application/nostr+json" } })).json()).supported_nips;
  const protectedNote = (key) => sign(key, { tags: [["-"]] });
  const repostOf = (event) => sign(alice, { kind: 6, tags: [["e", event.id], ["p", event.pubkey]], content: JSON.stringify(event) });

  const bobClient = await connect(wsUrl);
  const challenge = (await bobClient.waitFor((m) => m[0] === "AUTH"))[1];
  const auth = signEvent(challenge, "wss://relay.test", bob.sec);
  bobClient.send(["AUTH", auth]);
  const authOk = await bobClient.waitFor((m) => m[0] === "OK" && m[1] === auth.id);
  expect(authOk[2] === true, `bob must authenticate: ${JSON.stringify(authOk)}`);

  const bobsProtected = protectedNote(bob);

  expect((await call("settings")).nip70 === true, "NIP-70 must be on by default");
  expect((await supportedNips()).includes(70), "NIP-11 must list NIP-70");
  await expectAccepted(bobClient, bobsProtected, "a protected event from its authenticated author");
  await expectRejected(bobClient, protectedNote(alice), "restricted:", "a protected event from someone else");
  await expectRejected(client, protectedNote(alice), "auth-required:", "a protected event without authentication");
  await expectRejected(client, repostOf(bobsProtected), "blocked:", "a repost that embeds a protected event");

  await call("changesetting", ["nip70", false]);
  expect((await call("settings")).nip70 === false, "settings must show NIP-70 off");
  expect(!(await supportedNips()).includes(70), "NIP-11 must no longer list NIP-70");
  await expectAccepted(bobClient, protectedNote(alice), "a protected event from someone else while NIP-70 is off");
  await expectAccepted(client, protectedNote(alice), "a protected event without authentication while NIP-70 is off");
  await expectAccepted(client, repostOf(bobsProtected), "a repost that embeds a protected event while NIP-70 is off");

  expect((await rpc("changesetting", ["nosuchsetting", true])).error, "an unknown setting must be refused");
  expect((await rpc("changesetting", ["nip70", "false"])).error, "a setting value that is not a boolean must be refused");

  await call("changesetting", ["nip70", true]);
  expect((await supportedNips()).includes(70), "NIP-11 must list NIP-70 again");
  await expectRejected(client, protectedNote(alice), "auth-required:", "a protected event without authentication once NIP-70 is back on");

  await bobClient.close();
  pass("with NIP-70 off, the - tag is ignored");
}

async function relayInfoTests() {
  const nip11 = async () => (await fetch(httpUrl, { headers: { Accept: "application/nostr+json" } })).json();

  const configured = (await nip11()).name;

  await call("changerelayname", ["Admin Test"]);
  await call("changerelaydescription", ["Managed with NIP-86"]);
  await call("changerelayicon", ["https://relay.test/icon.png"]);

  let info = await nip11();
  expect(info.name === "Admin Test" && info.description === "Managed with NIP-86" && info.icon === "https://relay.test/icon.png", `NIP-11 must show the new info: ${JSON.stringify(info)}`);
  expect(info.supported_nips.includes(86), "NIP-11 must list NIP-86");

  const landing = await (await fetch(httpUrl)).text();
  expect(landing.includes("Admin Test"), "the landing page must show the new name");

  const badIcon = await rpc("changerelayicon", ["javascript:alert(1)"]);
  expect(badIcon.error, "an icon that is not an http(s) URL must be refused");

  await call("changerelayname", [""]);
  info = await nip11();
  expect(info.name === configured, "an empty name must go back to the configured one");

  pass("changerelayname, changerelaydescription and changerelayicon update NIP-11");
}

async function moderationTests(client) {
  const reporter = randomKey();
  const note = sign(bob, { content: "reported note" });
  await expectAccepted(client, note, "the reported note");
  await expectAccepted(client, sign(reporter, { kind: 1984, tags: [["e", note.id, "spam"], ["p", bob.pub]], content: "scam link" }), "the report");
  await expectAccepted(client, sign(randomKey(), { kind: 1984, tags: [["e", "f".repeat(64), "spam"]] }), "a report of an event this relay does not store");

  const queue = await call("listeventsneedingmoderation");
  const entry = queue.find((e) => e.id === note.id);
  expect(queue.length === 1 && entry && entry.reason.includes("spam") && entry.reason.includes("scam link"), `the reported event must need moderation: ${JSON.stringify(queue)}`);

  await call("allowevent", [note.id, "reviewed"]);
  expect((await call("listeventsneedingmoderation")).length === 0, "an allowed event no longer needs moderation");
  expect((await call("listallowedevents")).some((a) => a.id === note.id && a.reason === "reviewed"), "the allowed event must be listed");

  await call("banevent", [note.id]);
  expect((await call("listallowedevents")).length === 0, "banevent must remove the event from the allow list");
  await call("unbanevent", [note.id]);

  pass("reported events wait in listeventsneedingmoderation until allowed or banned");
}

async function ipTests(wsUrl, client) {
  await call("blockip", ["127.0.0.1", "abuse"]);
  expect((await call("listblockedips")).some((b) => b.ip === "127.0.0.1" && b.reason === "abuse"), "the blocked IP must be listed");

  await waitForClose(client.ws);
  const refused = await openWebSocket(wsUrl).catch(() => null);
  if (refused) await waitForClose(refused);

  await call("unblockip", ["127.0.0.1"]);
  const reconnected = await connect(wsUrl);
  await expectAccepted(reconnected, sign(bob, { content: "back" }), "an event from an unblocked IP");
  await reconnected.close();

  expect((await rpc("blockip", ["not an ip"])).error, "an invalid IP must be refused");

  pass("blockip disconnects and refuses an IP, unblockip lets it back");
}

async function statsTests() {
  const stats = await call("stats");
  expect(stats.storedEvents > 0 && stats.storedEventsByKind["1"] > 0, `stats must count stored events: ${JSON.stringify(stats)}`);
  expect(stats.connections >= 1 && stats.authenticatedConnections >= 0, "stats must count connections");
  expect(stats.dbSize > 0 && typeof stats.version === "string", "stats must report the DB size and version");
  pass("stats reports the relay activity");
}

async function adminPageTests() {
  const page = await fetch(`${httpUrl}admin`);
  const html = await page.text();
  expect(page.status === 200 && page.headers.get("content-type").startsWith("text/html"), "/admin must serve the page");
  expect(html.includes('content="wss://relay.test"') && html.includes('content="true"'), "the page must know the relay URL and that the API is enabled");
  expect(page.headers.get("x-frame-options") === "DENY", "the page must refuse to be framed");

  for (const asset of ["admin/app.js", "admin/nostr.js"]) {
    const res = await fetch(`${httpUrl}${asset}`);
    expect(res.status === 200 && res.headers.get("content-type").startsWith("text/javascript"), `${asset} must be served`);
  }

  const preflight = await fetch(httpUrl, { method: "OPTIONS" });
  expect(preflight.status === 204 && preflight.headers.get("access-control-allow-headers").includes("Authorization"), "the CORS preflight must allow the Authorization header");

  pass("the /admin page and its scripts are served");
}

async function importTests(client) {
  await call("banpubkey", [alice.pub]);

  const event = buildEvent({ sec: alice.sec, pub: alice.pub, content: "imported", created_at: ts++ });
  const res = runStrfry(["--config", relayCfgPath, "import", "--no-verify"], { input: JSON.stringify(event) + "\n", stdio: ["pipe", "ignore", "pipe"] });
  expect(res.status === 0, `import failed: ${res.stderr}`);
  expect(!(await isStored(client, event.id)), "import must honor the bans");

  await call("unbanpubkey", [alice.pub]);
  pass("strfry import honors the bans");
}

async function backupTests(client) {
  const event = sign(alice, { content: "in the backup" });
  await expectAccepted(client, event, "an event to back up");

  const banned = randomKey();
  await call("banpubkey", [banned.pub]);

  const { token } = await call("backup");
  const link = `${httpUrl}admin/backup?token=${token}`;
  const res = await fetch(link);
  expect(res.status === 200 && res.headers.get("content-type") === "application/octet-stream", `the backup must download: HTTP ${res.status}`);
  expect(/^attachment; filename="strfry-backup-\d{8}-\d{6}\.mdb"$/.test(res.headers.get("content-disposition")), "the backup must be named as a dated .mdb file");
  const snapshot = Buffer.from(await res.arrayBuffer());

  expect((await fetch(link)).status === 403, "a backup link must work only once");
  expect((await fetch(`${httpUrl}admin/backup?token=nope`)).status === 403, "an unknown backup token must be refused");
  expect((await fetch(`${httpUrl}admin/backup`)).status === 403, "a backup link without a token must be refused");

  const restoredDbDir = path.join(workDir, "restored-db");
  const restoredCfgPath = path.join(workDir, "restored.conf");
  rmSync(restoredDbDir, { recursive: true, force: true });
  mkdirSync(restoredDbDir, { recursive: true });
  writeFileSync(path.join(restoredDbDir, "data.mdb"), snapshot);
  writeConfig(config(restoredDbDir, relayPort, true, admin.pub), restoredCfgPath);

  const fromBanned = buildEvent({ sec: banned.sec, pub: banned.pub, content: "after the restore", created_at: ts++ });
  const imported = runStrfry(["--config", restoredCfgPath, "import", "--no-verify"], { input: JSON.stringify(fromBanned) + "\n", stdio: ["pipe", "ignore", "pipe"] });
  expect(imported.status === 0, `import into the restored DB failed: ${imported.stderr}`);

  const exported = runStrfry(["--config", restoredCfgPath, "export"], { stdio: ["ignore", "pipe", "pipe"] });
  expect(exported.status === 0, `export from the restored DB failed: ${exported.stderr}`);
  expect(exported.stdout.includes(event.id), "the restored DB must hold the events");
  expect(!exported.stdout.includes(fromBanned.id), "the restored DB must keep the bans");

  await call("unbanpubkey", [banned.pub]);
  pass("backup downloads a snapshot that restores the events and the bans");
}

async function importUpload(token, body) {
  const headers = token === null ? {} : { Authorization: `Bearer ${token}` };
  const res = await fetch(`${httpUrl}admin/import`, { method: "POST", headers, body });
  return { status: res.status, ...(await res.json()) };
}

async function adminImportTests(client) {
  const banned = randomKey();
  await call("banpubkey", [banned.pub]);

  const stored = sign(alice, { content: "stored before the import" });
  await expectAccepted(client, stored, "an event stored before the import");

  const added = sign(alice, { content: "imported from the admin page" });
  const old = finalizeEvent({ kind: 1, tags: [], content: "older than the relay accepts", created_at: now() - 5 * 365 * 86_400 }, hexToBytes(randomKey().sec));
  const fromBanned = sign(banned, { content: "from a banned pubkey" });
  const badSig = buildEvent({ sec: alice.sec, pub: alice.pub, content: "bad signature", created_at: ts++ });

  const { token } = await call("import");
  const lines = [added, old, stored, fromBanned, badSig].map((e) => JSON.stringify(e));
  const res = await importUpload(token, [...lines, "", "not json"].join("\n") + "\n");
  expect(res.status === 200 && res.added === 2 && res.duplicates === 1, `the batch must add 2 events and skip 1: ${JSON.stringify(res)}`);
  expect(
    res.refused["blocked: this pubkey is banned"] === 1 && res.refused["invalid: bad signature"] === 1 && res.refused["invalid: not JSON"] === 1,
    `the batch must count the refused lines by reason: ${JSON.stringify(res)}`,
  );
  expect((await isStored(client, added.id)) && (await isStored(client, old.id)), "the imported events must be stored, however old");
  expect(!(await isStored(client, fromBanned.id)), "the import must honor the bans");

  const again = await importUpload(token, JSON.stringify(added) + "\r\n");
  expect(again.status === 200 && again.added === 0 && again.duplicates === 1, `the token must work for the next batches: ${JSON.stringify(again)}`);

  expect((await importUpload("nope", "")).status === 401, "an unknown import token must be refused");
  expect((await importUpload(null, "")).status === 401, "an import without a token must be refused");
  expect((await importUpload(token, "x".repeat((8 << 20) + 1))).status === 413, "a batch over 8 MiB must be refused");

  await call("unbanpubkey", [banned.pub]);
  pass("import writes JSONL batches, checks signatures but not dates, and honors the bans");
}

async function tests({ wsUrl, client }) {
  await authorizationTests();
  await pubkeyBanTests(client);
  await eventBanTests(client);
  await allowListTests(client);
  await kindTests(client);
  await protectedEventTests(wsUrl, client);
  await relayInfoTests();
  await moderationTests(client);
  await statsTests();
  await adminPageTests();
  await importTests(client);
  await backupTests(client);
  await adminImportTests(client);
  await ipTests(wsUrl, client);
}

writeConfig(config(relayDbDir, relayPort, true, admin.pub), relayCfgPath);

await runRelaySuite({
  relayConfigPath: relayCfgPath,
  relayPort,
  relayDbPath: relayDbDir,
  tests,
});

console.log("All admin API tests passed.");
