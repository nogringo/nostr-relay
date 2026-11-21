#include "RelayServer.h"

#include "AdminStore.h"
#include "PrometheusMetrics.h"
#include "app_git_version.h"


// NIP-86 relay management API, authorized with NIP-98

static const std::vector<std::string> supportedMethods = {
    "supportedmethods",
    "banpubkey", "unbanpubkey", "listbannedpubkeys",
    "allowpubkey", "unallowpubkey", "listallowedpubkeys",
    "listeventsneedingmoderation",
    "allowevent", "unallowevent", "listallowedevents",
    "banevent", "unbanevent", "listbannedevents",
    "changerelayname", "changerelaydescription", "changerelayicon",
    "allowkind", "unallowkind", "disallowkind", "undisallowkind", "listallowedkinds", "listdisallowedkinds",
    "blockip", "unblockip", "listblockedips",
    "stats",
};

static std::string toLower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c){ return std::tolower(c); });
    return out;
}

static std::string truncateUtf8(const std::string &s, size_t maxBytes) {
    if (s.size() <= maxBytes) return s;
    while (maxBytes > 0 && (s[maxBytes] & 0xC0) == 0x80) maxBytes--;
    return s.substr(0, maxBytes);
}

// Accepts the standard and URL-safe alphabets, with or without padding
static std::string base64Decode(std::string_view in) {
    std::string out;
    uint32_t acc = 0;
    int bits = 0;

    for (char c : in) {
        int v;

        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+' || c == '-') v = 62;
        else if (c == '/' || c == '_') v = 63;
        else if (c == '=') break;
        else throw herr("invalid base64");

        acc = (acc << 6) | v;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            out.push_back(char((acc >> bits) & 0xFF));
        }
    }

    return out;
}

// Returns the pubkey of the admin who signed the authorization
static std::string verifyAuthorization(secp256k1_context *secpCtx, std::string_view authorization, std::string_view body) {
    if (parsePubkeyList(cfg().relay__admin__pubkeys).empty()) throw herr("the management API is disabled, relay.admin.pubkeys is empty");
    if (cfg().relay__auth__serviceUrl.empty()) throw herr("relay.auth.serviceUrl must be configured");

    constexpr std::string_view scheme = "nostr ";
    if (!toLower(authorization.substr(0, scheme.size())).starts_with(scheme)) throw herr("missing NIP-98 Authorization header");

    auto token = authorization.substr(scheme.size());
    while (token.size() && token.front() == ' ') token.remove_prefix(1);
    while (token.size() && token.back() == ' ') token.remove_suffix(1);

    tao::json::value eventJson;

    try {
        eventJson = tao::json::from_string(base64Decode(token));
    } catch (std::exception &e) {
        throw herr("Authorization is not a base64 encoded event");
    }

    std::string packedStr, jsonStr;
    parseAndVerifyEvent(eventJson, secpCtx, true, false, packedStr, jsonStr);
    PackedEventView packed(packedStr);

    if (packed.kind() != 27235) throw herr("wrong event kind, expected 27235");

    uint64_t now = hoytech::curr_time_s();
    if (packed.created_at() + 60 < now || packed.created_at() > now + 60) throw herr("created_at is more than 60 seconds away from the current time");

    bool urlOk = false, methodOk = false, payloadOk = false;
    auto payloadHash = to_hex(sha256(body).sv());

    for (const auto &tagj : eventJson.at("tags").get_array()) {
        const auto &tag = tagj.get_array();
        if (tag.size() < 2) continue;

        const auto &name = tag[0].get_string();
        const auto &value = tag[1].get_string();

        if (name == "u" && isServiceUrl(value)) urlOk = true;
        else if (name == "method" && toLower(value) == "post") methodOk = true;
        else if (name == "payload" && toLower(value) == payloadHash) payloadOk = true;
    }

    if (!urlOk) throw herr("u tag must be the relay URL: " + primaryServiceUrl());
    if (!methodOk) throw herr("method tag must be POST");
    if (!payloadOk) throw herr("payload tag must be the SHA-256 of the request body");

    if (!adminStore::isAdmin(packed.pubkey())) throw herr("pubkey is not an admin of this relay");

    return std::string(packed.pubkey());
}


void RelayServer::runAdmin(ThreadPool<MsgAdmin>::Thread &thr) {
    secp256k1_context *secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    Decompressor decomp;

    while (1) {
        auto newMsgs = thr.inbox.pop_all();

        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgAdmin::Rpc>(&newMsg.msg)) {
                auto reply = adminRpc(secpCtx, decomp, *msg);
                tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::HttpReply{msg->reqId, std::move(reply)}});
                hubTrigger->send();
            }
        }
    }
}

std::string RelayServer::adminRpc(secp256k1_context *secpCtx, Decompressor &decomp, const MsgAdmin::Rpc &rpc) {
    auto reply = [](int status, const tao::json::value &body){
        return httpResponse(status, "application/nostr+json+rpc", tao::json::to_string(body));
    };

    std::string admin;

    try {
        admin = verifyAuthorization(secpCtx, rpc.authorization, rpc.body);
    } catch (std::exception &e) {
        LI << "Refused NIP-86 request: " << e.what();
        return reply(401, tao::json::value({{ "error", std::string("unauthorized: ") + e.what() }}));
    }

    std::string method;
    tao::json::value params = tao::json::empty_array;

    try {
        auto req = tao::json::from_string(rpc.body);
        if (!req.is_object()) throw herr("request is not an object");

        auto *methodJson = req.find("method");
        if (!methodJson) throw herr("missing method");
        method = jsonGetString(*methodJson, "method is not a string");

        if (auto *paramsJson = req.find("params")) params = *paramsJson;
        if (!params.is_array()) throw herr("params is not an array");
    } catch (std::exception &e) {
        return reply(400, tao::json::value({{ "error", std::string("bad request: ") + e.what() }}));
    }

    LI << "[admin " << to_hex(admin) << "] " << method << " " << tao::json::to_string(params);

    try {
        return reply(200, tao::json::value({{ "result", adminMethod(decomp, method, params.get_array()) }}));
    } catch (std::exception &e) {
        return reply(200, tao::json::value({{ "error", e.what() }}));
    }
}

tao::json::value RelayServer::adminMethod(Decompressor &decomp, const std::string &method, const tao::json::value::array_t &params) {
    auto stringParam = [&](size_t i, std::string_view name) {
        if (i >= params.size()) return std::string();
        if (!params[i].is_string()) throw herr(name, " must be a string");
        return params[i].get_string();
    };

    auto hexParam = [&](std::string_view name) {
        auto val = stringParam(0, name);
        if (val.size() != 64) throw herr(name, " must be 64 hex digits");
        return from_hex(val);
    };

    auto kindParam = [&]{
        if (params.empty()) throw herr("missing kind");
        return adminStore::kindKey(jsonGetUnsigned(params[0], "kind must be a non-negative integer"));
    };

    auto ipParam = [&]{
        auto ip = parseIP(stringParam(0, "IP address"));
        if (ip.empty()) throw herr("invalid IP address");
        return adminStore::canonicalIp(ip);
    };

    auto reasonParam = [&]{ return stringParam(1, "reason"); };

    auto change = [&](const std::function<void(lmdb::txn &)> &cb) {
        {
            auto txn = env.txn_rw();
            cb(txn);
            txn.commit();
        }

        adminStore::version++;
        return tao::json::value(true);
    };

    auto deleteBanned = [](lmdb::txn &txn) {
        NegentropyFilterCache neFilterCache;
        auto numDeleted = deleteEvents(txn, neFilterCache, adminStore::bannedLevIds(txn));
        if (numDeleted) LI << "Deleted " << numDeleted << " banned events";
    };

    auto list = [](lmdb::dbi &dbi, const std::string &keyName, const std::function<tao::json::value(std::string_view)> &renderKey) {
        auto txn = env.txn_ro();
        tao::json::value output = tao::json::empty_array;

        adminStore::foreachListEntry(txn, dbi, [&](std::string_view k, std::string_view v){
            output.get_array().push_back(tao::json::value({
                { keyName, renderKey(k) },
                { "reason", std::string(v) },
            }));
        });

        return output;
    };

    auto listKinds = [](lmdb::dbi &dbi) {
        auto txn = env.txn_ro();
        tao::json::value output = tao::json::empty_array;

        adminStore::foreachListEntry(txn, dbi, [&](std::string_view k, std::string_view){
            output.get_array().push_back(lmdb::from_sv<uint64_t>(k));
        });

        return output;
    };

    auto hex = [](std::string_view k){ return tao::json::value(to_hex(k)); };

    auto changeRelayInfo = [&](const std::string &field) {
        auto val = stringParam(0, field);
        if (field == "icon" && val.size() && !val.starts_with("https://") && !val.starts_with("http://")) throw herr("icon must be an http(s) URL");

        return change([&](lmdb::txn &txn){
            // An empty value goes back to the one in the config file
            if (val.empty()) env.dbi_RelayInfo.del(txn, field);
            else env.dbi_RelayInfo.put(txn, field, val);
        });
    };

    if (method == "supportedmethods") {
        tao::json::value output = tao::json::empty_array;
        for (const auto &m : supportedMethods) output.get_array().push_back(m);
        return output;
    }

    if (method == "banpubkey") {
        auto pubkey = hexParam("pubkey");
        auto reason = reasonParam();

        return change([&](lmdb::txn &txn){
            env.dbi_BannedPubkey.put(txn, pubkey, reason);
            env.dbi_AllowedPubkey.del(txn, pubkey);
            deleteBanned(txn);
        });
    }

    if (method == "unbanpubkey") {
        auto pubkey = hexParam("pubkey");
        return change([&](lmdb::txn &txn){ env.dbi_BannedPubkey.del(txn, pubkey); });
    }

    if (method == "listbannedpubkeys") return list(env.dbi_BannedPubkey, "pubkey", hex);

    if (method == "allowpubkey") {
        auto pubkey = hexParam("pubkey");
        auto reason = reasonParam();

        return change([&](lmdb::txn &txn){
            env.dbi_AllowedPubkey.put(txn, pubkey, reason);
            env.dbi_BannedPubkey.del(txn, pubkey);
        });
    }

    if (method == "unallowpubkey") {
        auto pubkey = hexParam("pubkey");
        return change([&](lmdb::txn &txn){ env.dbi_AllowedPubkey.del(txn, pubkey); });
    }

    if (method == "listallowedpubkeys") return list(env.dbi_AllowedPubkey, "pubkey", hex);

    if (method == "banevent") {
        auto id = hexParam("event id");
        auto reason = reasonParam();

        return change([&](lmdb::txn &txn){
            env.dbi_BannedEvent.put(txn, id, reason);
            env.dbi_AllowedEvent.del(txn, id);
            deleteBanned(txn);
        });
    }

    if (method == "unbanevent") {
        auto id = hexParam("event id");
        return change([&](lmdb::txn &txn){ env.dbi_BannedEvent.del(txn, id); });
    }

    if (method == "listbannedevents") return list(env.dbi_BannedEvent, "id", hex);

    if (method == "allowevent") {
        auto id = hexParam("event id");
        auto reason = reasonParam();

        return change([&](lmdb::txn &txn){
            env.dbi_AllowedEvent.put(txn, id, reason);
            env.dbi_BannedEvent.del(txn, id);
        });
    }

    if (method == "unallowevent") {
        auto id = hexParam("event id");
        return change([&](lmdb::txn &txn){ env.dbi_AllowedEvent.del(txn, id); });
    }

    if (method == "listallowedevents") return list(env.dbi_AllowedEvent, "id", hex);

    if (method == "listeventsneedingmoderation") return eventsNeedingModeration(decomp);

    if (method == "changerelayname") return changeRelayInfo("name");
    if (method == "changerelaydescription") return changeRelayInfo("description");
    if (method == "changerelayicon") return changeRelayInfo("icon");

    if (method == "allowkind") {
        auto kind = kindParam();

        return change([&](lmdb::txn &txn){
            env.dbi_AllowedKind.put(txn, kind, "");
            env.dbi_DisallowedKind.del(txn, kind);
        });
    }

    if (method == "unallowkind") {
        auto kind = kindParam();
        return change([&](lmdb::txn &txn){ env.dbi_AllowedKind.del(txn, kind); });
    }

    if (method == "disallowkind") {
        auto kind = kindParam();

        return change([&](lmdb::txn &txn){
            env.dbi_DisallowedKind.put(txn, kind, "");
            env.dbi_AllowedKind.del(txn, kind);
        });
    }

    if (method == "undisallowkind") {
        auto kind = kindParam();
        return change([&](lmdb::txn &txn){ env.dbi_DisallowedKind.del(txn, kind); });
    }

    if (method == "listallowedkinds") return listKinds(env.dbi_AllowedKind);
    if (method == "listdisallowedkinds") return listKinds(env.dbi_DisallowedKind);

    if (method == "blockip") {
        auto ip = ipParam();
        auto reason = reasonParam();

        auto output = change([&](lmdb::txn &txn){ env.dbi_BlockedIP.put(txn, ip, reason); });

        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::CloseIP{ip}});
        hubTrigger->send();

        return output;
    }

    if (method == "unblockip") {
        auto ip = ipParam();
        return change([&](lmdb::txn &txn){ env.dbi_BlockedIP.del(txn, ip); });
    }

    if (method == "listblockedips") return list(env.dbi_BlockedIP, "ip", [](std::string_view k){ return tao::json::value(renderIP(k)); });

    if (method == "stats") return stats();

    throw herr("unsupported method: ", method);
}

// Stored events reported with NIP-56, that no admin has banned or allowed yet
tao::json::value RelayServer::eventsNeedingModeration(Decompressor &decomp) {
    static constexpr uint64_t maxReportsScanned = 10'000;
    static constexpr size_t maxEvents = 500;

    struct Reports {
        std::vector<std::string> types;
        uint64_t count = 0;
        std::string comment;
    };

    auto txn = env.txn_ro();

    std::vector<std::string> order;
    flat_hash_map<std::string, Reports> reported;
    uint64_t scanned = 0;

    env.generic_foreachFull(txn, env.dbi_Event__kind, std::string(lmdb::to_sv<uint64_t>(1984)) + std::string(8, '\xFF'), lmdb::to_sv<uint64_t>(MAX_U64), [&](auto k, auto v) {
        ParsedKey_Uint64Uint64 parsedKey(k);
        if (parsedKey.n1 != 1984 || scanned++ >= maxReportsScanned) return false;

        auto report = tao::json::from_string(getEventJson(txn, decomp, lmdb::from_sv<uint64_t>(v)));

        for (const auto &tagj : report.at("tags").get_array()) {
            const auto &tag = tagj.get_array();
            if (tag.size() < 2 || tag[0].get_string() != "e" || tag[1].get_string().size() != 64) continue;

            const auto &idHex = tag[1].get_string();
            auto it = reported.find(idHex);

            if (it == reported.end()) {
                if (order.size() >= maxEvents) continue;

                auto id = from_hex(idHex);
                if (adminStore::listContains(txn, env.dbi_AllowedEvent, id) || adminStore::listContains(txn, env.dbi_BannedEvent, id)) continue;
                if (!lookupEventById(txn, id)) continue;

                order.push_back(idHex);
                it = reported.emplace(idHex, Reports{}).first;
            }

            auto &r = it->second;
            r.count++;

            if (tag.size() >= 3 && tag[2].is_string() && tag[2].get_string().size()) {
                const auto &type = tag[2].get_string();
                if (std::find(r.types.begin(), r.types.end(), type) == r.types.end()) r.types.push_back(type);
            }

            if (r.comment.empty()) r.comment = truncateUtf8(report.at("content").get_string(), 280);
        }

        return true;
    }, true);

    tao::json::value output = tao::json::empty_array;

    for (const auto &idHex : order) {
        const auto &r = reported.at(idHex);
        std::string reason;

        for (const auto &type : r.types) {
            if (reason.size()) reason += ", ";
            reason += type;
        }

        if (reason.empty()) reason = "reported";
        reason += " (" + std::to_string(r.count) + (r.count == 1 ? " report)" : " reports)");
        if (r.comment.size()) reason += ": " + r.comment;

        output.get_array().push_back(tao::json::value({
            { "id", idHex },
            { "reason", reason },
        }));
    }

    return output;
}

tao::json::value RelayServer::stats() {
    auto &metrics = PrometheusMetrics::getInstance();
    auto txn = env.txn_ro();

    MDB_envinfo envInfo;
    MDB_stat envStat;
    mdb_env_info(env.lmdb_env.handle(), &envInfo);
    mdb_env_stat(env.lmdb_env.handle(), &envStat);

    tao::json::value storedByKind = tao::json::empty_object;
    flat_hash_map<uint64_t, uint64_t> kindCounts;

    {
        auto cursor = lmdb::cursor::open(txn, env.dbi_Event__kind);
        std::string_view k, v;

        for (bool found = cursor.get(k, v, MDB_FIRST); found; found = cursor.get(k, v, MDB_NEXT)) {
            kindCounts[ParsedKey_Uint64Uint64(k).n1]++;
        }
    }

    for (const auto &[kind, count] : kindCounts) storedByKind[std::to_string(kind)] = count;

    auto labeled = [](const PrometheusMetrics::LabeledCounter &counter) {
        tao::json::value output = tao::json::empty_object;
        for (const auto &[label, count] : counter.getAll()) output[label] = count;
        return output;
    };

    return tao::json::value({
        { "version", APP_GIT_VERSION },
        { "uptime", hoytech::curr_time_s() - startedAt },
        { "storedEvents", env.dbi_EventPayload.size(txn) },
        { "storedEventsByKind", storedByKind },
        { "dbSize", (envInfo.me_last_pgno + 1) * envStat.ms_psize },
        { "connections", metrics.activeConnections.get() },
        { "authenticatedConnections", metrics.authenticatedConnections.get() },
        { "eventsWritten", metrics.writtenEventsTotal.get() },
        { "eventsRejected", metrics.rejectedEventsTotal.get() },
        { "eventsDuplicate", metrics.dupEventsTotal.get() },
        { "eventsWrittenByKind", labeled(metrics.nostrEventsByKind) },
        { "clientMessages", labeled(metrics.nostrClientMessages) },
        { "relayMessages", labeled(metrics.nostrRelayMessages) },
        { "bannedPubkeys", env.dbi_BannedPubkey.size(txn) },
        { "allowedPubkeys", env.dbi_AllowedPubkey.size(txn) },
        { "bannedEvents", env.dbi_BannedEvent.size(txn) },
        { "allowedEvents", env.dbi_AllowedEvent.size(txn) },
        { "blockedIps", env.dbi_BlockedIP.size(txn) },
    });
}
