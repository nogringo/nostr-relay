import {
  BunkerSigner,
  bytesToHex,
  createNostrConnectURI,
  generateSecretKey,
  getPublicKey,
  hexToBytes,
  nip19,
  parseBunkerInput,
  renderSVG,
  sha256,
} from "./nostr.js";

const meta = (name) => document.querySelector(`meta[name="${name}"]`)?.content ?? "";

const relayUrl = meta("relay-url");
const adminEnabled = meta("admin-enabled") === "true";
const basePath = location.pathname.replace(/admin\/?$/, "");
const httpEndpoint = location.origin + basePath;
const wsEndpoint = httpEndpoint.replace(/^http/, "ws");

const NOSTR_CONNECT_RELAYS = ["wss://promenade.fiatjaf.com", "wss://relay.ditto.pub", "wss://relay.primal.net"];
const SESSION_KEY = "strfry-admin-session";
const SIGNER_TIMEOUT_MS = 90_000;
const AUTH_REUSE_MS = 45_000;

const KIND_NAMES = {
  0: "Profiles",
  1: "Notes",
  3: "Follow lists",
  4: "Encrypted DMs (NIP-04)",
  5: "Deletion requests",
  6: "Reposts",
  7: "Reactions",
  8: "Badge awards",
  9: "Chat messages",
  16: "Generic reposts",
  40: "Channel creations",
  42: "Channel messages",
  62: "Requests to vanish",
  1059: "Gift wraps",
  1063: "File metadata",
  1111: "Comments",
  1984: "Reports",
  9734: "Zap requests",
  9735: "Zaps",
  9802: "Highlights",
  10000: "Mute lists",
  10002: "Relay lists",
  10050: "DM relay lists",
  13194: "Wallet info",
  21059: "Ephemeral gift wraps",
  24133: "Nostr Connect",
  27235: "HTTP auth",
  30023: "Articles",
  30078: "App data",
  31922: "Calendar events",
  31923: "Calendar events",
  34550: "Communities",
};

const $ = (id) => document.getElementById(id);

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);

  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? "" : value);
  }

  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : String(child));
  }

  return el;
}

const storage = {
  load() {
    try {
      return JSON.parse(localStorage.getItem(SESSION_KEY));
    } catch {
      return null;
    }
  },
  save(value) {
    try {
      localStorage.setItem(SESSION_KEY, JSON.stringify(value));
    } catch {}
  },
  clear() {
    try {
      localStorage.removeItem(SESSION_KEY);
    } catch {}
  },
};

const encoder = new TextEncoder();
const now = () => Math.floor(Date.now() / 1000);
const sha256Hex = (text) => bytesToHex(sha256(encoder.encode(text)));

function base64(text) {
  let binary = "";
  for (const byte of encoder.encode(text)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function withTimeout(promise, ms, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

const numberFormat = new Intl.NumberFormat();
const compactFormat = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });
const formatNumber = (n) => numberFormat.format(n);
const formatCompact = (n) => (n < 10_000 ? formatNumber(n) : compactFormat.format(n));

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value < 10 && unit > 0 ? 1 : 0)} ${units[unit]}`;
}

function formatDuration(seconds) {
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  if (days) return `${days} d ${hours} h`;
  if (hours) return `${hours} h ${minutes} min`;
  return `${minutes} min`;
}

const plural = (n, one, many) => `${formatNumber(n)} ${n === 1 ? one : many}`;
const kindLabel = (kind) => (KIND_NAMES[kind] ? `${KIND_NAMES[kind]} (${kind})` : `Kind ${kind}`);
const shorten = (text) => (text.length > 26 ? `${text.slice(0, 14)}...${text.slice(-8)}` : text);

function npub(hex) {
  try {
    return nip19.npubEncode(hex);
  } catch {
    return hex;
  }
}

function parsePubkey(input) {
  const text = input.trim();
  if (/^[0-9a-f]{64}$/i.test(text)) return text.toLowerCase();

  try {
    const decoded = nip19.decode(text);
    if (decoded.type === "npub") return decoded.data;
    if (decoded.type === "nprofile") return decoded.data.pubkey;
  } catch {}

  throw new Error("Enter a pubkey as an npub, an nprofile or 64 hex digits.");
}

function parseEventId(input) {
  const text = input.trim();
  if (/^[0-9a-f]{64}$/i.test(text)) return text.toLowerCase();

  try {
    const decoded = nip19.decode(text);
    if (decoded.type === "note") return decoded.data;
    if (decoded.type === "nevent") return decoded.data.id;
  } catch {}

  throw new Error("Enter an event as a note, an nevent or 64 hex digits.");
}

function parseKind(input) {
  const kind = Number(input);
  if (!Number.isInteger(kind) || kind < 0) throw new Error("A kind is a whole number, like 1 or 30023.");
  return kind;
}

// Signing

let session = null;
let signingCount = 0;

function trackSigning(delta) {
  signingCount += delta;
  $("signing").hidden = signingCount === 0;
}

async function sign(template) {
  trackSigning(1);
  try {
    return await withTimeout(session.signEvent(template), SIGNER_TIMEOUT_MS, "Your signer did not answer. Check that it is online, then try again.");
  } finally {
    trackSigning(-1);
  }
}

function bunkerSession(bunker, pubkey, saved) {
  return {
    pubkey,
    signEvent: (template) => bunker.signEvent(template),
    close: () => bunker.close(),
    saved,
  };
}

async function extensionSession() {
  if (!window.nostr) throw new Error("No Nostr extension was found in this browser.");
  const pubkey = await withTimeout(window.nostr.getPublicKey(), SIGNER_TIMEOUT_MS, "The extension did not answer.");
  return {
    pubkey,
    signEvent: (template) => window.nostr.signEvent(template),
    close() {},
    saved: { method: "nip07" },
  };
}

function onSignerAuth(url) {
  if (!/^https?:\/\//.test(url)) return;
  const status = $("signin-status");
  status.className = "status";
  status.replaceChildren("Your signer asks you to approve this login: ", h("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, "open the approval page"), ".");
}

async function restoreSession(saved) {
  if (saved?.method === "nip07") {
    await waitForExtension();
    return await extensionSession();
  }

  if (saved?.method === "nip46") {
    const bunker = BunkerSigner.fromBunker(hexToBytes(saved.clientSecret), saved.bunker, { onauth: onSignerAuth });
    return bunkerSession(bunker, saved.pubkey, saved);
  }

  return null;
}

async function waitForExtension(ms = 1_500) {
  const deadline = Date.now() + ms;
  while (!window.nostr && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
}

// NIP-86 calls, authorized with NIP-98

class Unauthorized extends Error {}

const authCache = new Map();

async function authorization(body, reuse) {
  const cached = reuse && authCache.get(body);
  if (cached && cached.expires > Date.now()) return cached.header;

  const event = await sign({
    kind: 27235,
    created_at: now(),
    content: "",
    tags: [["u", relayUrl], ["method", "POST"], ["payload", sha256Hex(body)]],
  });

  const header = `Nostr ${base64(JSON.stringify(event))}`;
  if (reuse) authCache.set(body, { header, expires: Date.now() + AUTH_REUSE_MS });
  return header;
}

async function rpc(method, params = [], { reuse = false } = {}) {
  const body = JSON.stringify({ method, params });

  const res = await fetch(httpEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/nostr+json+rpc", Authorization: await authorization(body, reuse) },
    body,
  });

  const data = await res.json().catch(() => ({}));
  const error = typeof data.error === "string" ? data.error.replace(/^unauthorized: /, "") : "";

  if (res.status === 401) throw new Unauthorized(error || "The relay refused the authorization.");
  if (!res.ok || error) throw new Error(error || `The relay answered with HTTP ${res.status}.`);

  return data.result;
}

// Reads are signed once and reused for a few seconds, so moving between tabs doesn't ask the signer every time
const read = (method) => rpc(method, [], { reuse: true });

function forgetReads() {
  authCache.clear();
}

// Reading events from the relay itself

function fetchEvents(filter, timeoutMs = 6_000) {
  return new Promise((resolve) => {
    const events = [];
    let ws;
    let timer;

    const done = () => {
      clearTimeout(timer);
      try {
        ws?.close();
      } catch {}
      resolve(events);
    };

    timer = setTimeout(done, timeoutMs);

    try {
      ws = new WebSocket(wsEndpoint);
    } catch {
      done();
      return;
    }

    ws.onopen = () => ws.send(JSON.stringify(["REQ", "admin", filter]));
    ws.onerror = done;
    ws.onmessage = (message) => {
      let msg;
      try {
        msg = JSON.parse(message.data);
      } catch {
        return;
      }
      if (msg[0] === "EVENT" && msg[1] === "admin") events.push(msg[2]);
      else if ((msg[0] === "EOSE" || msg[0] === "CLOSED") && msg[1] === "admin") done();
    };
  });
}

async function fetchProfiles(pubkeys) {
  const names = new Map();
  if (!pubkeys.length) return names;

  for (const event of await fetchEvents({ kinds: [0], authors: pubkeys })) {
    try {
      const profile = JSON.parse(event.content);
      const name = profile.display_name || profile.name;
      if (typeof name === "string" && name.trim()) names.set(event.pubkey, name.trim());
    } catch {}
  }

  return names;
}

// Feedback

function showError(error) {
  $("error-text").textContent = error?.message || String(error);
  $("error").hidden = false;
}

$("error-close").addEventListener("click", () => {
  $("error").hidden = true;
});

async function busy(button, task) {
  if (button) button.disabled = true;
  try {
    await task();
  } catch (error) {
    showError(error);
  } finally {
    if (button) button.disabled = false;
  }
}

// Relay identity

let relayInfo = {};

async function loadRelayInfo() {
  try {
    const res = await fetch(httpEndpoint, { headers: { Accept: "application/nostr+json" } });
    relayInfo = await res.json();
  } catch {
    relayInfo = {};
  }
  renderIdentity();
}

function renderIdentity() {
  const name = relayInfo.name || "Nostr relay";

  for (const container of document.querySelectorAll("[data-identity]")) {
    const fallback = h("div", { class: "relay-icon", "aria-hidden": "true" }, name.trim().charAt(0).toUpperCase() || "R");
    let icon = fallback;

    if (relayInfo.icon) {
      icon = h("img", { class: "relay-icon", src: relayInfo.icon, alt: "" });
      icon.addEventListener("error", () => icon.replaceWith(fallback), { once: true });
    }

    container.replaceChildren(icon, h("div", { class: "identity-text" }, h("h1", { class: "relay-name" }, name), h("p", { class: "relay-url mono" }, relayUrl)));
  }

  document.title = `${name} admin`;
}

// Sign-in

let pendingConnect = null;

function setSigninStatus(text, isError = false) {
  const status = $("signin-status");
  status.className = isError ? "status error" : "status";
  status.textContent = text;
}

async function completeSignin(newSession) {
  session = newSession;
  setSigninStatus("Checking that this key can manage the relay");

  try {
    await rpc("supportedmethods");
  } catch (error) {
    session.close();
    session = null;
    const hint = error instanceof Unauthorized && error.message.includes("not an admin") ? " Add it to relay.admin.pubkeys in strfry.conf, or sign in with another key." : "";
    setSigninStatus(`${shorten(npub(newSession.pubkey))} can't manage this relay: ${error.message}${hint}`, true);
    return;
  }

  storage.save({ ...newSession.saved, pubkey: newSession.pubkey });
  setSigninStatus("");
  showConsole();
}

function cancelNostrConnect() {
  pendingConnect?.abort();
  pendingConnect = null;
  $("nostrconnect").hidden = true;
  $("nostrconnect-button").hidden = false;
}

async function showSignin() {
  $("console").hidden = true;
  $("signin").hidden = false;

  await waitForExtension();

  if (!window.nostr) {
    $("nip07-note").textContent = "No Nostr extension was found in this browser. Install one such as Alby or nos2x, then reload.";
    $("nip07-button").disabled = true;
  }
}

$("nip07-button").addEventListener("click", (event) =>
  busy(event.currentTarget, async () => {
    try {
      await completeSignin(await extensionSession());
    } catch (error) {
      setSigninStatus(error.message, true);
    }
  }),
);

$("bunker-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button");

  busy(button, async () => {
    try {
      setSigninStatus("Looking up the remote signer");
      const pointer = await parseBunkerInput($("bunker-input").value.trim());
      if (!pointer) throw new Error("This is not a bunker link, nor a NIP-05 address that names a remote signer.");
      if (!pointer.relays.length) throw new Error("This bunker link names no relay to reach the signer.");

      const clientSecret = generateSecretKey();
      const bunker = BunkerSigner.fromBunker(clientSecret, pointer, { onauth: onSignerAuth });

      setSigninStatus("Waiting for the remote signer to accept the connection");
      await withTimeout(bunker.connect(), SIGNER_TIMEOUT_MS, "The remote signer did not answer.");
      const pubkey = await withTimeout(bunker.getPublicKey(), SIGNER_TIMEOUT_MS, "The remote signer did not send its pubkey.");

      const saved = { method: "nip46", clientSecret: bytesToHex(clientSecret), bunker: { pubkey: pointer.pubkey, relays: bunker.bp.relays, secret: null } };
      await completeSignin(bunkerSession(bunker, pubkey, saved));
    } catch (error) {
      setSigninStatus(error.message || String(error), true);
    }
  });
});

$("nostrconnect-button").addEventListener("click", async () => {
  cancelNostrConnect();

  const clientSecret = generateSecretKey();
  const secret = bytesToHex(generateSecretKey()).slice(0, 16);
  const uri = createNostrConnectURI({
    clientPubkey: getPublicKey(clientSecret),
    relays: NOSTR_CONNECT_RELAYS,
    secret,
    perms: ["sign_event:27235"],
    name: `${relayInfo.name || "Relay"} admin`,
    url: location.origin,
  });

  $("nostrconnect-qr").innerHTML = renderSVG(uri, { border: 1 });
  const copy = $("nostrconnect-copy");
  copy.textContent = "Copy link";
  copy.onclick = () =>
    busy(copy, async () => {
      await navigator.clipboard.writeText(uri);
      copy.textContent = "Link copied";
    });
  $("nostrconnect-button").hidden = true;
  $("nostrconnect").hidden = false;
  setSigninStatus("Waiting for your signer app to connect");

  const abort = new AbortController();
  pendingConnect = abort;

  try {
    const bunker = await BunkerSigner.fromURI(clientSecret, uri, { onauth: onSignerAuth }, abort.signal);
    if (abort.signal.aborted) return;

    const pubkey = await withTimeout(bunker.getPublicKey(), SIGNER_TIMEOUT_MS, "The signer app did not send its pubkey.");
    const saved = { method: "nip46", clientSecret: bytesToHex(clientSecret), bunker: { pubkey: bunker.bp.pubkey, relays: bunker.bp.relays, secret: null } };

    cancelNostrConnect();
    await completeSignin(bunkerSession(bunker, pubkey, saved));
  } catch (error) {
    if (abort.signal.aborted) return;
    cancelNostrConnect();
    setSigninStatus(error.message || String(error), true);
  }
});

$("nostrconnect-cancel").addEventListener("click", () => {
  cancelNostrConnect();
  setSigninStatus("");
});

$("signout").addEventListener("click", () => {
  session?.close();
  session = null;
  forgetReads();
  storage.clear();
  loaded.clear();
  showSignin();
});

// Console

const TABS = ["overview", "moderation", "access", "info"];
const TAB_STALE_MS = 120_000;
const loaded = new Map();

const loaders = {
  overview: loadOverview,
  moderation: loadModeration,
  access: loadAccess,
  info: loadInfoForm,
};

function showConsole() {
  $("signin").hidden = true;
  $("console").hidden = false;
  $("account-npub").textContent = shorten(npub(session.pubkey));
  $("account-npub").title = npub(session.pubkey);

  const initial = TABS.includes(location.hash.slice(1)) ? location.hash.slice(1) : "overview";
  showTab(initial);

  if (initial !== "moderation") busy(null, refreshQueueCount);
}

function showTab(name) {
  for (const tab of TABS) {
    const selected = tab === name;
    $(`tab-${tab}`).setAttribute("aria-selected", String(selected));
    $(`tab-${tab}`).tabIndex = selected ? 0 : -1;
    $(`view-${tab}`).hidden = !selected;
  }

  history.replaceState(null, "", `#${name}`);

  if (!(Date.now() - loaded.get(name) < TAB_STALE_MS)) {
    loaded.set(name, Date.now());
    busy(null, loaders[name]);
  }
}

for (const tab of document.querySelectorAll('[role="tab"]')) {
  tab.addEventListener("click", () => showTab(tab.dataset.tab));
  tab.addEventListener("keydown", (event) => {
    const step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (!step) return;
    const next = TABS[(TABS.indexOf(tab.dataset.tab) + step + TABS.length) % TABS.length];
    showTab(next);
    $(`tab-${next}`).focus();
  });
}

function rows(items, render, emptyText) {
  if (!items.length) return emptyText ? h("p", { class: "empty" }, emptyText) : document.createDocumentFragment();
  return h("ul", { class: "rows" }, items.map(render));
}

function row(main, reason, action) {
  return h("li", { class: "row" }, h("div", { class: "row-main" }, main, reason ? h("p", { class: "reason" }, reason) : null), action);
}

function actionButton(label, onClick, className = "") {
  const button = h("button", { type: "button", class: className }, label);
  button.addEventListener("click", () => busy(button, onClick));
  return button;
}

function pubkeyLabel(hex, names) {
  const encoded = npub(hex);
  const name = names?.get(hex);
  return h("p", {}, name ? h("strong", {}, name, " ") : null, h("span", { class: "mono", title: encoded }, shorten(encoded)));
}

function eventLabel(hex) {
  const encoded = nip19.noteEncode(hex);
  return h("p", { class: "mono", title: hex }, shorten(encoded));
}

// Overview

async function loadOverview() {
  const stats = await read("stats");

  const kpi = (label, value, detail) => h("div", { class: "kpi" }, h("dt", {}, label), h("dd", {}, value, detail ? h("div", { class: "detail" }, detail) : null));

  const bans = [
    plural(stats.bannedPubkeys, "banned pubkey", "banned pubkeys"),
    plural(stats.bannedEvents, "banned event", "banned events"),
    plural(stats.blockedIps, "blocked address", "blocked addresses"),
  ];

  const access = stats.allowedPubkeys ? `Only ${plural(stats.allowedPubkeys, "listed pubkey", "listed pubkeys")} and admins can publish.` : "Anyone can publish.";

  $("overview-stats").replaceChildren(
    h(
      "dl",
      { class: "kpis" },
      kpi("Events stored", formatCompact(stats.storedEvents)),
      kpi("Database size", formatBytes(stats.dbSize)),
      kpi("Open connections", formatNumber(stats.connections), `${formatNumber(stats.authenticatedConnections)} authenticated`),
      kpi("Uptime", formatDuration(stats.uptime)),
    ),
    h(
      "p",
      { class: "facts" },
      "Since the relay started, it stored ",
      h("strong", {}, formatNumber(stats.eventsWritten)),
      " new events, refused ",
      h("strong", {}, formatNumber(stats.eventsRejected)),
      " and skipped ",
      h("strong", {}, formatNumber(stats.eventsDuplicate)),
      " duplicates.",
    ),
    h("p", { class: "facts" }, `${access} In force: ${bans.join(", ")}.`),
    h("p", { class: "footnote" }, `strfry ${stats.version}`),
  );

  $("overview-kinds").replaceChildren(kindBars(stats.storedEventsByKind));
}

function kindBars(byKind) {
  const entries = Object.entries(byKind)
    .map(([kind, count]) => ({ label: kindLabel(Number(kind)), count }))
    .sort((a, b) => b.count - a.count);

  if (!entries.length) return h("p", { class: "empty" }, "No events are stored yet.");

  const total = entries.reduce((sum, e) => sum + e.count, 0);
  const shown = entries.slice(0, 10);
  const rest = entries.slice(10);
  if (rest.length) shown.push({ label: `${rest.length} other kinds`, count: rest.reduce((sum, e) => sum + e.count, 0) });

  const max = Math.max(...shown.map((e) => e.count));

  return h(
    "ol",
    { class: "bars" },
    shown.map((e) => {
      const share = `${((e.count / total) * 100).toFixed(e.count / total < 0.01 ? 2 : 1)}% of stored events`;
      return h(
        "li",
        { class: "bar-row", tabindex: "0", "aria-label": `${e.label}: ${formatNumber(e.count)} events, ${share}` },
        h("span", { class: "bar-label", title: e.label }, e.label),
        h("span", { class: "bar-track" }, h("span", { class: "bar", style: `width: ${(e.count / max) * 100}%` })),
        h("span", { class: "bar-value" }, formatNumber(e.count)),
        h("span", { class: "bar-tip", "aria-hidden": "true" }, share),
      );
    }),
  );
}

$("overview-refresh").addEventListener("click", (event) =>
  busy(event.currentTarget, loadOverview),
);

// A link instead of fetch(), so the browser streams the file to disk instead of holding it in memory
$("backup-button").addEventListener("click", (event) =>
  busy(event.currentTarget, async () => {
    const { token } = await rpc("backup");
    const link = h("a", { href: `${httpEndpoint}admin/backup?token=${encodeURIComponent(token)}`, download: true, hidden: true });
    document.body.append(link);
    link.click();
    link.remove();
  }),
);

// Moderation

function setQueueCount(n) {
  $("queue-count").hidden = n === 0;
  $("queue-count").textContent = String(n);
}

async function refreshQueueCount() {
  setQueueCount((await read("listeventsneedingmoderation")).length);
}

async function loadModeration() {
  await Promise.all([loadQueue(), loadBannedPubkeys(), loadBannedEvents(), loadKeptEvents()]);
}

async function loadQueue() {
  const queue = await read("listeventsneedingmoderation");
  setQueueCount(queue.length);

  if (!queue.length) {
    $("queue").replaceChildren(h("p", { class: "empty" }, "Nothing is waiting. Reported events stored on this relay show up here."));
    return;
  }

  $("queue").replaceChildren(h("p", { class: "empty" }, `Loading ${plural(queue.length, "reported event", "reported events")}`));

  const events = new Map((await fetchEvents({ ids: queue.map((q) => q.id) })).map((e) => [e.id, e]));
  const names = await fetchProfiles([...new Set([...events.values()].map((e) => e.pubkey))]);

  $("queue").replaceChildren(h("div", { class: "tickets" }, queue.map((item) => ticket(item, events.get(item.id), names))));
}

function ticket(item, event, names) {
  const author = event ? names.get(event.pubkey) || shorten(npub(event.pubkey)) : null;

  const meta = event
    ? [h("span", { class: "author", title: npub(event.pubkey) }, author), h("span", {}, kindLabel(event.kind)), h("span", {}, new Date(event.created_at * 1000).toLocaleString())]
    : [h("span", { class: "mono", title: item.id }, shorten(nip19.noteEncode(item.id)))];

  const content = event ? event.content || "(no text content)" : "This event can't be read here: only its recipient can read a private event.";

  const actions = [
    actionButton("Keep", async () => {
      await rpc("allowevent", [item.id, "kept after a report"]);
      await Promise.all([loadQueue(), loadKeptEvents()]);
    }),
    actionButton(
      "Ban event",
      async () => {
        if (!confirm("Ban this event? It is deleted from the relay and refused if published again.")) return;
        await rpc("banevent", [item.id, item.reason]);
          await Promise.all([loadQueue(), loadBannedEvents()]);
      },
      "danger-outline",
    ),
  ];

  if (event) {
    actions.push(
      actionButton(
        "Ban author",
        async () => {
          if (!confirm(`Ban ${author}? Every event they published on this relay is deleted, and new ones are refused.`)) return;
          await rpc("banpubkey", [event.pubkey, item.reason]);
          await Promise.all([loadQueue(), loadBannedPubkeys()]);
        },
        "danger",
      ),
    );
  }

  return h(
    "article",
    { class: "ticket" },
    h("div", { class: "ticket-meta" }, meta),
    h("p", { class: event ? "ticket-content" : "ticket-content muted" }, content.length > 2_000 ? `${content.slice(0, 2_000)}...` : content),
    h("p", { class: "ticket-reason" }, `Reported as ${item.reason}`),
    h("div", { class: "ticket-actions" }, actions),
  );
}

async function loadBannedPubkeys() {
  const banned = await read("listbannedpubkeys");
  const names = await fetchProfiles(banned.map((b) => b.pubkey));

  $("banned-pubkeys").replaceChildren(
    rows(
      banned,
      (b) =>
        row(
          pubkeyLabel(b.pubkey, names),
          b.reason,
          actionButton("Unban", async () => {
            await rpc("unbanpubkey", [b.pubkey]);
            await loadBannedPubkeys();
          }),
        ),
      "No pubkey is banned.",
    ),
  );
}

async function loadBannedEvents() {
  const banned = await read("listbannedevents");

  $("banned-events").replaceChildren(
    rows(
      banned,
      (b) =>
        row(
          eventLabel(b.id),
          b.reason,
          actionButton("Unban", async () => {
            await rpc("unbanevent", [b.id]);
            await loadBannedEvents();
          }),
        ),
      "No event is banned.",
    ),
  );
}

async function loadKeptEvents() {
  const kept = await read("listallowedevents");

  $("kept-events").replaceChildren(
    rows(
      kept,
      (k) =>
        row(
          eventLabel(k.id),
          k.reason,
          actionButton("Forget", async () => {
            await rpc("unallowevent", [k.id]);
            await Promise.all([loadKeptEvents(), loadQueue()]);
          }),
        ),
      "No event has been kept.",
    ),
  );
}

function onSubmit(formId, handler) {
  const form = $(formId);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    busy(form.querySelector('button[type="submit"]'), async () => {
      const fields = Object.fromEntries(new FormData(form));
      if ((await handler(fields)) !== false) form.reset();
    });
  });
}

onSubmit("ban-pubkey-form", async ({ pubkey, reason }) => {
  const hex = parsePubkey(pubkey);
  if (!confirm(`Ban ${shorten(npub(hex))}? Every event they published on this relay is deleted, and new ones are refused.`)) return false;
  await rpc("banpubkey", [hex, reason.trim()]);
  await Promise.all([loadBannedPubkeys(), loadQueue()]);
});

onSubmit("ban-event-form", async ({ id, reason }) => {
  const hex = parseEventId(id);
  if (!confirm("Ban this event? It is deleted from the relay and refused if published again.")) return false;
  await rpc("banevent", [hex, reason.trim()]);
  await Promise.all([loadBannedEvents(), loadQueue()]);
});

// Access

let allowedPubkeyCount = 0;
let allowedKindCount = 0;

async function loadAccess() {
  await Promise.all([loadAllowedPubkeys(), loadKinds(), loadSettings(), loadBlockedIps()]);
}

async function loadAllowedPubkeys() {
  const allowed = await read("listallowedpubkeys");
  const names = await fetchProfiles(allowed.map((a) => a.pubkey));
  allowedPubkeyCount = allowed.length;

  $("allow-state").replaceChildren(
    allowed.length
      ? h("p", { class: "state closed" }, "Only the pubkeys below and admins can publish. A gift wrap is accepted when its recipient is on the list.")
      : h("p", { class: "state" }, "Anyone can publish. Add a pubkey to accept events only from the pubkeys on this list."),
  );

  $("allowed-pubkeys").replaceChildren(
    rows(
      allowed,
      (a) =>
        row(
          pubkeyLabel(a.pubkey, names),
          a.reason,
          actionButton("Remove", async () => {
            if (allowed.length === 1 && !confirm("Remove the last pubkey? Anyone will be able to publish again.")) return;
            await rpc("unallowpubkey", [a.pubkey]);
            await loadAllowedPubkeys();
          }),
        ),
      "",
    ),
  );
}

onSubmit("allow-pubkey-form", async ({ pubkey, reason }) => {
  const hex = parsePubkey(pubkey);
  if (allowedPubkeyCount === 0 && !confirm("Once a pubkey is on this list, only listed pubkeys and admins can publish here. Continue?")) return false;
  await rpc("allowpubkey", [hex, reason.trim()]);
  await loadAllowedPubkeys();
});

function kindChips(kinds, method, emptyText) {
  if (!kinds.length) return h("p", { class: "empty" }, emptyText);

  return h(
    "div",
    { class: "chips" },
    kinds.map((kind) => {
      const remove = h("button", { type: "button", class: "quiet", "aria-label": `Remove ${kindLabel(kind)}` }, "Remove");
      remove.addEventListener("click", () =>
        busy(remove, async () => {
          await rpc(method, [kind]);
          await loadKinds();
        }),
      );
      return h("span", { class: "chip" }, kindLabel(kind), remove);
    }),
  );
}

async function loadKinds() {
  const [allowed, disallowed] = await Promise.all([read("listallowedkinds"), read("listdisallowedkinds")]);
  allowedKindCount = allowed.length;

  $("allowed-kinds").replaceChildren(kindChips(allowed, "unallowkind", "Empty: every kind is accepted, except the refused ones."));
  $("disallowed-kinds").replaceChildren(kindChips(disallowed, "undisallowkind", "Empty: no kind is refused."));
}

onSubmit("allow-kind-form", async ({ kind }) => {
  const k = parseKind(kind);
  if (allowedKindCount === 0 && !confirm(`Once ${kindLabel(k)} is on this list, every kind not on it is refused. Continue?`)) return false;
  await rpc("allowkind", [k]);
  await loadKinds();
});

onSubmit("disallow-kind-form", async ({ kind }) => {
  await rpc("disallowkind", [parseKind(kind)]);
  await loadKinds();
});

async function loadSettings() {
  const settings = await read("settings");
  $("nip70-toggle").checked = settings.nip70;
  $("nip70-toggle").disabled = false;
}

$("nip70-toggle").addEventListener("change", (event) => {
  const toggle = event.currentTarget;

  busy(toggle, async () => {
    try {
      await rpc("changesetting", ["nip70", toggle.checked]);
    } catch (error) {
      toggle.checked = !toggle.checked;
      throw error;
    }
  });
});

async function loadBlockedIps() {
  const blocked = await read("listblockedips");

  $("blocked-ips").replaceChildren(
    rows(
      blocked,
      (b) =>
        row(
          h("p", { class: "mono" }, b.ip),
          b.reason,
          actionButton("Unblock", async () => {
            await rpc("unblockip", [b.ip]);
            await loadBlockedIps();
          }),
        ),
      "No address is blocked.",
    ),
  );
}

onSubmit("block-ip-form", async ({ ip, reason }) => {
  await rpc("blockip", [ip.trim(), reason.trim()]);
  await loadBlockedIps();
});

// Relay info

async function loadInfoForm() {
  await loadRelayInfo();
  const form = $("info-form");
  form.elements.name.value = relayInfo.name || "";
  form.elements.description.value = relayInfo.description || "";
  form.elements.icon.value = relayInfo.icon || "";
  previewIcon();
}

function previewIcon() {
  const url = $("info-icon").value.trim();
  const preview = $("info-icon-preview");
  preview.hidden = !/^https?:\/\//.test(url);
  if (!preview.hidden) preview.src = url;
}

$("info-icon").addEventListener("input", previewIcon);
$("info-icon-preview").addEventListener("error", (event) => {
  event.currentTarget.hidden = true;
});

$("info-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;

  busy(form.querySelector('button[type="submit"]'), async () => {
    const changes = [
      ["changerelayname", "name"],
      ["changerelaydescription", "description"],
      ["changerelayicon", "icon"],
    ].filter(([, field]) => form.elements[field].value.trim() !== (relayInfo[field] || ""));

    $("info-status").textContent = "";
    for (const [method, field] of changes) await rpc(method, [form.elements[field].value.trim()]);

    await loadInfoForm();
    $("info-status").textContent = changes.length ? "Saved" : "Nothing changed";
  });
});

// Start

async function start() {
  if (!adminEnabled || !relayUrl) {
    $("disabled").hidden = false;
    return;
  }

  await loadRelayInfo();

  const saved = storage.load();

  if (saved) {
    try {
      session = await restoreSession(saved);
    } catch {
      session = null;
    }
  }

  if (session) showConsole();
  else showSignin();
}

start();
