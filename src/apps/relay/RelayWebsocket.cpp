#include "RelayServer.h"

#include "StrfryTemplates.h"
#include "app_git_version.h"
#include "Favicon.h"
#include "Bech32Utils.h"
#include "PrometheusMetrics.h"
#include "AdminStore.h"
#include "AdminAssets.h"



static std::string preGenerateHttpResponse(const std::string &contentType, const std::string &content, const std::string &extraHeaders = "") {
    return httpResponse(200, contentType, content, extraHeaders);
};

static bool adminEnabled() {
    return cfg().relay__auth__serviceUrl.size() && parsePubkeyList(cfg().relay__admin__pubkeys).size();
}

static std::string_view httpHeader(uWS::HttpRequest &req, const char *name) {
    auto header = req.getHeader(name);
    return header ? header.toStringView() : std::string_view();
}

static bool isNip86ContentType(std::string_view contentType) {
    std::string lower(contentType);
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });
    return lower.starts_with("application/nostr+json+rpc");
}

struct RelayInfo {
    std::string name;
    std::string description;
    std::string icon;
    bool restrictedWrites;
    bool nip70;
};

static RelayInfo currentRelayInfo() {
    auto txn = env.txn_ro();

    return {
        adminStore::relayInfo(txn, "name", cfg().relay__info__name),
        adminStore::relayInfo(txn, "description", cfg().relay__info__description),
        adminStore::relayInfo(txn, "icon", cfg().relay__info__icon),
        !adminStore::listEmpty(txn, env.dbi_AllowedPubkey),
        adminStore::setting(txn, "nip70"),
    };
}

static constexpr size_t MAX_RPC_BODY_SIZE = 65536;



void RelayServer::runWebsocket(ThreadPool<MsgWebsocket>::Thread &thr) {
    struct Connection {
        uWS::WebSocket<uWS::SERVER> *websocket;
        uint64_t connId;
        uint64_t connectedTimestamp;
        std::string ipAddr;
        struct Stats {
            uint64_t bytesUp = 0;
            uint64_t bytesUpCompressed = 0;
            uint64_t bytesDown = 0;
            uint64_t bytesDownCompressed = 0;
            // Application bytes handed to uWS that have not yet been fully drained
            // to the kernel (either still queued in uWS or in-flight in a partial
            // send). Useful for diagnosing slow or stalled clients.
            uint64_t pendingOutbound = 0;
        } stats;

        Connection(uWS::WebSocket<uWS::SERVER> *p, uint64_t connId_)
            : websocket(p), connId(connId_), connectedTimestamp(hoytech::curr_time_us()) { }
        Connection(const Connection &) = delete;
        Connection(Connection &&) = delete;
    };

    uWS::Hub hub;
    uWS::Group<uWS::SERVER> *hubGroup = nullptr;
    flat_hash_map<uint64_t, Connection*> connIdToConnection;
    uint64_t nextConnectionId = 1;
    bool gracefulShutdown = false;
    uint64_t serverStart = ::time(nullptr);

    struct PendingRpc {
        uint64_t reqId;
        std::string authorization;
        std::string body;
        bool tooLarge = false;
    };

    flat_hash_map<uint64_t, uWS::HttpResponse*> pendingRpcs;
    uint64_t nextRpcId = 1;

    std::string tempBuf;
    tempBuf.reserve(cfg().events__maxEventSize + MAX_SUBID_SIZE + 100);


    auto supportedNips = [](const RelayInfo &info){
        tao::json::value output = tao::json::value::array({ 1, 2, 4, 9, 11, 28, 40, 59, 62 });

        bool authEnabled = cfg().relay__auth__enabled && cfg().relay__auth__serviceUrl.size() > 0;
        if (authEnabled) output.push_back(42);
        if (authEnabled && info.nip70) output.push_back(70);
        if (cfg().relay__maxFilterLimitCount > 0) output.push_back(45);
        if (cfg().relay__negentropy__enabled) output.push_back(77);
        if (adminEnabled()) output.push_back(86);

        std::sort(output.get_array().begin(), output.get_array().end());

        if (cfg().relay__info__nips.size() == 0) return output;

        try {
            auto parsed = tao::json::from_string(cfg().relay__info__nips);
            if (!parsed.is_array()) throw herr("not an array");
            output = parsed;
        } catch (std::exception &e) {
            LE << "Unable to parse config param relay.info.nips, using default: " << e.what();
        }

        return output;
    };

    auto getServerInfoHttpResponse = [&supportedNips, ver = uint64_t(0), adminVer = uint64_t(0), rendered = std::string("")]() mutable {
        if (ver != cfg().version() || adminVer != adminStore::version) {
            adminVer = adminStore::version;
            auto info = currentRelayInfo();

            auto maybeNpub = [](std::string_view sv){
                if (sv.starts_with("npub1")) {
                    return to_hex(decodeBech32Simple(sv));
                } else {
                    return std::string(sv);
                }
            };

            tao::json::value nip11 = tao::json::value({
                { "supported_nips", supportedNips(info) },
                { "software", "git+https://github.com/hoytech/strfry.git" },
                { "version", APP_GIT_VERSION },
                { "negentropy", negentropy::PROTOCOL_VERSION - 0x60 },
                { "limitation", tao::json::value({
                    { "max_message_length", cfg().relay__maxWebsocketPayloadSize },
                    { "max_subscriptions", cfg().relay__maxSubsPerConnection },
                    { "max_limit", cfg().relay__maxFilterLimit },
                    { "restricted_writes", info.restrictedWrites },
                }) },
            });

            if (info.name.size()) nip11["name"] = info.name;
            if (info.description.size()) nip11["description"] = info.description;
            if (cfg().relay__info__contact.size()) nip11["contact"] = cfg().relay__info__contact;
            if (cfg().relay__info__pubkey.size()) nip11["pubkey"] = maybeNpub(cfg().relay__info__pubkey);
            if (info.icon.size()) nip11["icon"] = info.icon;
            if (cfg().relay__info__banner.size()) nip11["banner"] = cfg().relay__info__banner;
            if (cfg().relay__info__self.size()) nip11["self"] = maybeNpub(cfg().relay__info__self);
            if (cfg().relay__info__privacy.size()) nip11["privacy_policy"] = cfg().relay__info__privacy;
            if (cfg().relay__info__terms.size()) nip11["terms_of_service"] = cfg().relay__info__terms;

            rendered = preGenerateHttpResponse("application/json", tao::json::to_string(nip11));
            ver = cfg().version();
        }

        return std::string_view(rendered); // memory only valid until next call
    };

    auto getLandingPageHttpResponse = [&supportedNips, &serverStart, ver = uint64_t(0), adminVer = uint64_t(0), lastUpdate = uint64_t(0), rendered = std::string("")]() mutable {
        if (ver != cfg().version() || adminVer != adminStore::version || (uint64_t)::time(nullptr) - lastUpdate > 3600) {
            adminVer = adminStore::version;
            auto info = currentRelayInfo();

            auto maybeUrl = [](std::string_view inp){
                if (inp.starts_with("http://") || inp.starts_with("https://")) {
                    std::string output = "<a href=\"";
                    output += templarInternal::htmlEscape(inp, true);
                    output += "\">";
                    output += templarInternal::htmlEscape(inp, false);
                    output += "</a>";
                    return output;
                }
                return templarInternal::htmlEscape(inp, false);
            };

            auto maybeNpub = [](std::string_view inp){
                try {
                    if (inp.size() != 64) throw herr("invalid length for pubkey");
                    return encodeBech32Simple("npub", hoytech::from_hex(inp));
                } catch(...) {
                }

                return std::string(inp);
            };

            struct {
                std::string supportedNips;
                std::string version;
                uint64_t negentropy;
                std::function<std::string(std::string_view)> maybeUrl;
                std::function<std::string(std::string_view)> maybeNpub;
                uint64_t uptime;
                RelayInfo info;
            } ctx = { tao::json::to_string(supportedNips(info)), APP_GIT_VERSION, negentropy::PROTOCOL_VERSION - 0x60, maybeUrl, maybeNpub, (uint64_t)::time(nullptr) - serverStart, info };

            rendered = preGenerateHttpResponse("text/html", ::strfrytmpl::landing(ctx).str);
            ver = cfg().version();
            lastUpdate = ::time(nullptr);
        }

        return std::string_view(rendered); // memory only valid until next call
    };

    auto getNodeInfoHttpResponse = [ver = uint64_t(0), rendered = std::string("")](std::string host) mutable {
        if (ver != cfg().version()) {
            tao::json::value nodeinfo = tao::json::value({
                { "links", tao::json::value::array({
                    tao::json::value({
                        { "rel", "http://nodeinfo.diaspora.software/ns/schema/2.1" },
                        { "href", "https://" + host + "/nodeinfo/2.1" },
                    }),
                }) },
            });

            rendered = preGenerateHttpResponse("application/json", tao::json::to_string(nodeinfo));
            ver = cfg().version();
        }

        return std::string_view(rendered); // memory only valid until next call
    };

    auto getNodeInfo21HttpResponse = [ver = uint64_t(0), rendered = std::string("")]() mutable {
        if (ver != cfg().version()) {
            // https://github.com/jhass/nodeinfo/blob/main/schemas/2.1/schema.json
            tao::json::value nodeinfo = tao::json::value({
                { "version", "2.1" },
                { "software", tao::json::value({
                    { "name", "strfry" },
                    { "version", APP_GIT_VERSION },
                    { "repository", "https://github.com/hoytech/strfry"},
                    { "homepage", "https://github.com/hoytech/strfry"},
                }) },
                { "protocols", tao::json::value::array({
                    "nostr",
                }) },
                { "services", tao::json::value({
                    { "inbound", tao::json::value::array({}) },
                    { "outbound", tao::json::value::array({}) },
                }) },
                { "openRegistrations", false },
                { "usage", tao::json::value({
                    { "users", tao::json::value({}) },
                }) },
                { "metadata", tao::json::value({
                    { "features", tao::json::value::array({
                        "nostr_relay",
                    }) },
                }) },
            });

            rendered = preGenerateHttpResponse("application/json", tao::json::to_string(nodeinfo));
            ver = cfg().version();
        }

        return std::string_view(rendered); // memory only valid until next call
    };

    std::string faviconResponse = preGenerateHttpResponse("image/x-icon", favicon(), "Cache-Control: public, max-age=31536000\r\n");

    const std::string adminHeaders =
        "Cache-Control: no-cache\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Content-Security-Policy: frame-ancestors 'none'\r\n"
        "Referrer-Policy: no-referrer\r\n";

    auto getAdminPageHttpResponse = [&adminHeaders, ver = uint64_t(0), rendered = std::string("")]() mutable {
        if (ver != cfg().version()) {
            std::string html(adminAssetIndexHtml);

            auto fill = [&](std::string_view placeholder, std::string_view value){
                auto pos = html.find(placeholder);
                if (pos != std::string::npos) html.replace(pos, placeholder.size(), templarInternal::htmlEscape(value, true));
            };

            fill("{{RELAY_URL}}", primaryServiceUrl());
            fill("{{ADMIN_ENABLED}}", adminEnabled() ? "true" : "false");

            rendered = preGenerateHttpResponse("text/html; charset=utf-8", html, adminHeaders);
            ver = cfg().version();
        }

        return std::string_view(rendered); // memory only valid until next call
    };

    std::string adminAppResponse = preGenerateHttpResponse("text/javascript; charset=utf-8", std::string(adminAssetAppJs), adminHeaders);
    std::string adminNostrResponse = preGenerateHttpResponse("text/javascript; charset=utf-8", std::string(adminAssetNostrJs), adminHeaders);

    std::string corsPreflightResponse = httpResponse(204, "", "",
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Authorization, Content-Type, Accept\r\n"
        "Access-Control-Max-Age: 86400\r\n"
    );

    auto replyRpc = [&](uint64_t reqId, std::string_view payload) {
        auto it = pendingRpcs.find(reqId);
        if (it == pendingRpcs.end()) return;

        auto *res = it->second;
        delete (PendingRpc*)res->getUserData();
        res->setUserData(nullptr);
        pendingRpcs.erase(it);

        res->write(payload.data(), payload.size());
    };

    auto receiveRpcBody = [&](uWS::HttpResponse *res, char *data, size_t length, size_t remainingBytes) {
        auto *rpc = (PendingRpc*)res->getUserData();
        if (!rpc) return;

        if (rpc->body.size() + length > MAX_RPC_BODY_SIZE) rpc->tooLarge = true;
        else rpc->body.append(data, length);

        if (remainingBytes) return;

        if (rpc->tooLarge) {
            replyRpc(rpc->reqId, httpResponse(413, "application/nostr+json+rpc", "{\"error\":\"request body too large\"}"));
            return;
        }

        tpAdmin.dispatch(0, MsgAdmin{MsgAdmin::Rpc{rpc->reqId, std::move(rpc->authorization), std::move(rpc->body)}});
    };


    {
        int extensionOptions = 0;

        if (cfg().relay__compression__enabled) extensionOptions |= uWS::PERMESSAGE_DEFLATE;
        if (cfg().relay__compression__slidingWindow) extensionOptions |= uWS::SLIDING_DEFLATE_WINDOW;

        hubGroup = hub.createGroup<uWS::SERVER>(extensionOptions, cfg().relay__maxWebsocketPayloadSize);
    }

    if (cfg().relay__autoPingSeconds) hubGroup->startAutoPing(cfg().relay__autoPingSeconds * 1'000);

    hubGroup->onHttpRequest([&](uWS::HttpResponse *res, uWS::HttpRequest req, char *data, size_t length, size_t remainingBytes){
        LI << "HTTP request for [" << req.getUrl().toString() << "]";

        std::string host = req.getHeader("host").toString();
        std::string url = req.getUrl().toString();
        std::string path = url.substr(0, url.find('?'));

        if (req.getMethod() == uWS::METHOD_OPTIONS) {
            res->write(corsPreflightResponse.data(), corsPreflightResponse.size());
        } else if (req.getMethod() == uWS::METHOD_POST && isNip86ContentType(httpHeader(req, "content-type"))) {
            auto *rpc = new PendingRpc{nextRpcId++, std::string(httpHeader(req, "authorization"))};
            res->setUserData(rpc);
            pendingRpcs.emplace(rpc->reqId, res);
            receiveRpcBody(res, data, length, remainingBytes);
        } else if (path == "/admin" || path == "/admin/") {
            auto page = getAdminPageHttpResponse();
            res->write(page.data(), page.size());
        } else if (path == "/admin/app.js") {
            res->write(adminAppResponse.data(), adminAppResponse.size());
        } else if (path == "/admin/nostr.js") {
            res->write(adminNostrResponse.data(), adminNostrResponse.size());
        } else if (url == "/metrics") {
            auto metrics = PrometheusMetrics::getInstance().render();
            auto response = preGenerateHttpResponse("text/plain; version=0.0.4", metrics);
            res->write(response.data(), response.size());
        } else if (url == "/.well-known/nodeinfo") {
            auto nodeInfo = getNodeInfoHttpResponse(host);
            res->write(nodeInfo.data(), nodeInfo.size());
        } else if (url == "/nodeinfo/2.1") {
            auto nodeInfo = getNodeInfo21HttpResponse();
            res->write(nodeInfo.data(), nodeInfo.size());
        } else if (url == "/favicon.ico") {
            res->write(faviconResponse.data(), faviconResponse.size());
        } else if (req.getHeader("accept").toStringView() == "application/nostr+json") {
            auto info = getServerInfoHttpResponse();
            res->write(info.data(), info.size());
        } else {
            auto landing = getLandingPageHttpResponse();
            res->write(landing.data(), landing.size());
        }
    });

    hubGroup->onHttpData([&](uWS::HttpResponse *res, char *data, size_t length, size_t remainingBytes){
        receiveRpcBody(res, data, length, remainingBytes);
    });

    hubGroup->onCancelledHttpRequest([&](uWS::HttpResponse *res){
        auto *rpc = (PendingRpc*)res->getUserData();
        if (!rpc) return;

        pendingRpcs.erase(rpc->reqId);
        delete rpc;
        res->setUserData(nullptr);
    });

    hubGroup->onConnection([&](uWS::WebSocket<uWS::SERVER> *ws, uWS::HttpRequest req) {
        std::string ipAddr;

        if (cfg().relay__realIpHeader.size()) {
            auto header = req.getHeader(cfg().relay__realIpHeader.c_str()).toString(); // not string_view: parseIP needs trailing 0 byte

            ipAddr = parseIP(header);
            if (ipAddr.size() == 0) LW << "Couldn't parse IP from header " << cfg().relay__realIpHeader << ": " << header;
        }

        if (ipAddr.size() == 0) ipAddr = ws->getAddressBytes();

        bool blocked;

        {
            auto txn = env.txn_ro();
            blocked = adminStore::isIpBlocked(txn, ipAddr);
        }

        if (blocked) {
            LI << "Refused connection from blocked IP " << renderIP(ipAddr);
            ws->setUserData(nullptr);
            ws->close(1008, "blocked", 7);
            return;
        }

        uint64_t connId = nextConnectionId++;

        Connection *c = new Connection(ws, connId);
        c->ipAddr = std::move(ipAddr);

        ws->setUserData((void*)c);
        connIdToConnection.emplace(connId, c);

        tpIngester.dispatch(connId, MsgIngester{MsgIngester::NewConn{connId}});

        bool compEnabled, compSlidingWindow;
        ws->getCompressionState(compEnabled, compSlidingWindow);
        LI << "[" << connId << "] Connect from " << renderIP(c->ipAddr)
           << " compression=" << (compEnabled ? 'Y' : 'N')
           << " sliding=" << (compSlidingWindow ? 'Y' : 'N')
        ;

        PrometheusMetrics::getInstance().activeConnections.inc();

        if (cfg().relay__enableTcpKeepalive) {
            int optval = 1;
            if (setsockopt(ws->getFd(), SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval))) {
                LW << "Failed to enable TCP keepalive: " << strerror(errno);
            }
        }
    });

    hubGroup->onDisconnection([&](uWS::WebSocket<uWS::SERVER> *ws, int code, char *message, size_t length) {
        auto *c = (Connection*)ws->getUserData();
        if (!c) return; // refused at connection time

        uint64_t connId = c->connId;

        auto upComp = renderPercent(1.0 - (double)c->stats.bytesUpCompressed / c->stats.bytesUp);
        auto downComp = renderPercent(1.0 - (double)c->stats.bytesDownCompressed / c->stats.bytesDown);

        LI << "[" << connId << "] Disconnect from " << renderIP(c->ipAddr)
           << " (" << code << "/" << (message ? std::string_view(message, length) : "-") << ")"
           << " UP: " << renderSize(c->stats.bytesUp) << " (" << upComp << " compressed)"
           << " DN: " << renderSize(c->stats.bytesDown) << " (" << downComp << " compressed)"
           << " Pending: " << renderSize(c->stats.pendingOutbound)
        ;

        tpIngester.dispatch(connId, MsgIngester{MsgIngester::CloseConn{connId}});

        connIdToConnection.erase(connId);
        delete c;

        PrometheusMetrics::getInstance().activeConnections.dec();

        if (gracefulShutdown) {
            LI << "Graceful shutdown in progress: " << connIdToConnection.size() << " connections remaining";
            if (connIdToConnection.size() == 0) {
                LW << "All connections closed, shutting down";
                ::exit(0);
            }
        }
    });

    hubGroup->onMessage2([&](uWS::WebSocket<uWS::SERVER> *ws, char *message, size_t length, uWS::OpCode opCode, size_t compressedSize) {
        if (!ws->getUserData()) return;
        auto &c = *(Connection*)ws->getUserData();

        c.stats.bytesDown += length;
        c.stats.bytesDownCompressed += compressedSize;

        tpIngester.dispatch(c.connId, MsgIngester{MsgIngester::ClientMessage{c.connId, c.ipAddr, std::string(message, length)}});
    });


    std::function<void()> asyncCb = [&]{
        auto newMsgs = thr.inbox.pop_all_no_wait();

        auto doSend = [&](uint64_t connId, std::string_view payload, uWS::OpCode opCode){
            auto it = connIdToConnection.find(connId);
            if (it == connIdToConnection.end()) return;
            auto &c = *it->second;

            // Track bytes still inside uWS's outbound path (either queued or
            // partially sent). Increment before send(), decrement in the
            // completion callback. The payload size is smuggled through the
            // callback's user-data pointer so the callback captures nothing and
            // decays to a plain function pointer.
            const size_t payloadSize = payload.size();
            c.stats.pendingOutbound += payloadSize;

            size_t compressedSize;

            auto cb = [](uWS::WebSocket<uWS::SERVER> *ws, void *data, bool /*cancelled*/, void * /*reserved*/){
                // uWS invokes this exactly once per send() on every path:
                //   - immediate send success          (ws != nullptr, cancelled=false)
                //   - immediate send failure          (ws != nullptr, cancelled=true)
                //   - queued drain success            (ws != nullptr, cancelled=false)
                //   - socket teardown (onEnd flush)   (ws == nullptr, cancelled=true)
                // The teardown path runs after our onDisconnection handler has
                // already logged and deleted the Connection, so we must not
                // dereference anything via ws in that case. Gate on ws.
                if (!ws) return;
                auto *conn = static_cast<Connection*>(ws->getUserData());
                if (!conn) return;
                conn->stats.pendingOutbound -= reinterpret_cast<uintptr_t>(data);
            };
            c.websocket->send(payload.data(), payloadSize, opCode, cb,
                              reinterpret_cast<void*>(static_cast<uintptr_t>(payloadSize)),
                              true, &compressedSize);
            c.stats.bytesUp += payloadSize;
            c.stats.bytesUpCompressed += compressedSize;

            // Back-pressure: if a client is too slow to read and the outbound
            // backlog inside uWS exceeds the configured cap, drop the connection
            // to bound memory. terminate() synchronously invokes our
            // onDisconnection (which logs and deletes the Connection) and then
            // drains the queued sends with cancellation callbacks, so no queue
            // entries leak. c is dangling after terminate(), so we must return.
            const uint64_t maxPending = cfg().relay__maxPendingOutboundBytes;
            if (maxPending > 0 && c.stats.pendingOutbound > maxPending) {
                LW << "[" << c.connId << "] Slow client: pendingOutbound "
                   << renderSize(c.stats.pendingOutbound)
                   << " exceeds relay.maxPendingOutboundBytes "
                   << renderSize(maxPending) << ", terminating";
                PrometheusMetrics::getInstance().slowClientTerminations.inc();
                c.websocket->terminate();
                return;
            }
        };

        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgWebsocket::Send>(&newMsg.msg)) {
                doSend(msg->connId, msg->payload, uWS::OpCode::TEXT);
            } else if (auto msg = std::get_if<MsgWebsocket::SendBinary>(&newMsg.msg)) {
                doSend(msg->connId, msg->payload, uWS::OpCode::BINARY);
            } else if (auto msg = std::get_if<MsgWebsocket::SendEventToBatch>(&newMsg.msg)) {
                tempBuf.reserve(13 + MAX_SUBID_SIZE + msg->evJson.size());
                tempBuf.resize(10 + MAX_SUBID_SIZE);
                tempBuf += "\",";
                tempBuf += msg->evJson;
                tempBuf += "]";

                for (auto &item : msg->list) {
                    PROM_INC_RELAY_MSG("EVENT");
                    auto subIdSv = item.subId.sv();
                    auto *p = tempBuf.data() + MAX_SUBID_SIZE - subIdSv.size();
                    memcpy(p, "[\"EVENT\",\"", 10);
                    memcpy(p + 10, subIdSv.data(), subIdSv.size());
                    doSend(item.connId, std::string_view(p, 13 + subIdSv.size() + msg->evJson.size()), uWS::OpCode::TEXT);
                }
            } else if (auto msg = std::get_if<MsgWebsocket::HttpReply>(&newMsg.msg)) {
                replyRpc(msg->reqId, msg->payload);
            } else if (auto msg = std::get_if<MsgWebsocket::CloseIP>(&newMsg.msg)) {
                std::vector<uint64_t> connIds;

                for (const auto &[connId, c] : connIdToConnection) {
                    if (adminStore::canonicalIp(c->ipAddr) == msg->ipAddr) connIds.push_back(connId);
                }

                for (auto connId : connIds) {
                    auto it = connIdToConnection.find(connId);
                    if (it == connIdToConnection.end()) continue;
                    LI << "[" << connId << "] Disconnecting blocked IP " << renderIP(msg->ipAddr);
                    it->second->websocket->terminate();
                }
            } else if (std::get_if<MsgWebsocket::GracefulShutdown>(&newMsg.msg)) {
                LW << "Initiating graceful shutdown: " << connIdToConnection.size() << " connections remaining";
                gracefulShutdown = true;
                hubGroup->stopListening();
            }
        }
    };

    hubTrigger = new uS::Async(hub.getLoop());
    hubTrigger->setData(&asyncCb);

    hubTrigger->start([](uS::Async *a){
        auto *r = static_cast<std::function<void()> *>(a->getData());
        (*r)();
    });



    int port = cfg().relay__port;

    std::string bindHost = cfg().relay__bind;

    if (!hub.listen(bindHost.c_str(), port, nullptr, uS::REUSE_PORT, hubGroup)) throw herr("unable to listen on port ", port);

    LI << "Started websocket server on " << bindHost << ":" << port;

    hub.run();
}
