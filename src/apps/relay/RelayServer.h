#pragma once

#include <iostream>
#include <memory>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>

#include <hoytech/time.h>
#include <hoytech/hex.h>
#include <hoytech/file_change_monitor.h>
#include <SessionToken.h>
#include <uWebSockets/src/uWS.h>
#include <tao/json.hpp>

#include "golpe.h"

#include "Subscription.h"
#include "ThreadPool.h"
#include "events.h"
#include "filters.h"
#include "jsonParseUtils.h"
#include "Decompressor.h"
#include "PrometheusMetrics.h"
#include "AuthSession.h"




struct MsgWebsocket : NonCopyable {
    struct Send {
        uint64_t connId;
        std::string payload;
    };

    struct SendBinary {
        uint64_t connId;
        std::string payload;
    };

    struct SendEventToBatch {
        RecipientList list;
        std::string evJson;
    };

    struct GracefulShutdown {
    };

    struct HttpReply {
        uint64_t reqId;
        std::string payload;
    };

    struct CloseIP {
        std::string ipAddr;
    };

    struct AllowBackup {
        std::string token;
    };

    struct BackupChunk {
        uint64_t backupId;
        std::string data;
    };

    struct BackupDone {
        uint64_t backupId;
        bool ok;
        uint64_t size;
    };

    using Var = std::variant<Send, SendBinary, SendEventToBatch, GracefulShutdown, HttpReply, CloseIP, AllowBackup, BackupChunk, BackupDone>;
    Var msg;
    MsgWebsocket(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgIngester : NonCopyable {
    struct ClientMessage {
        uint64_t connId;
        std::string ipAddr;
        std::string payload;
    };

    struct NewConn {
        uint64_t connId;
    };

    struct CloseConn {
        uint64_t connId;
    };

    using Var = std::variant<ClientMessage, NewConn, CloseConn>;
    Var msg;
    MsgIngester(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgWriter : NonCopyable {
    struct AddEvent {
        uint64_t connId;
        std::string ipAddr;
        std::string packedStr;
        std::string jsonStr;
        Bytes32 authed;
        bool callbackVerified = false; // NIP-9a subscription back from its challenge, already through the write policy
    };

    struct CloseConn {
        uint64_t connId;
    };

    using Var = std::variant<AddEvent, CloseConn>;
    Var msg;
    MsgWriter(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgReqWorker : NonCopyable {
    struct NewSub {
        Subscription sub;
    };

    struct SetAuth {
        uint64_t connId;
        Bytes32 authed;
    };

    struct RemoveSub {
        uint64_t connId;
        SubId subId;
    };

    struct CloseConn {
        uint64_t connId;
    };

    using Var = std::variant<NewSub, SetAuth, RemoveSub, CloseConn>;
    Var msg;
    MsgReqWorker(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgReqMonitor : NonCopyable {
    struct NewSub {
        Subscription sub;
    };

    struct SetAuth {
        uint64_t connId;
        Bytes32 authed;
    };

    struct RemoveSub {
        uint64_t connId;
        SubId subId;
    };

    struct CloseConn {
        uint64_t connId;
    };

    struct DBChange {
    };

    using Var = std::variant<NewSub, SetAuth, RemoveSub, CloseConn, DBChange>;
    Var msg;
    MsgReqMonitor(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgNegentropy : NonCopyable {
    struct NegOpen {
        Subscription sub;
        std::string filterStr;
        std::string negPayload;
    };

    struct NegMsg {
        uint64_t connId;
        SubId subId;
        std::string negPayload;
    };

    struct SetAuth {
        uint64_t connId;
        Bytes32 authed;
    };

    struct NegClose {
        uint64_t connId;
        SubId subId;
    };

    struct CloseConn {
        uint64_t connId;
    };

    using Var = std::variant<NegOpen, SetAuth, NegMsg, NegClose, CloseConn>;
    Var msg;
    MsgNegentropy(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgAdmin : NonCopyable {
    struct Rpc {
        uint64_t reqId;
        std::string authorization;
        std::string body;
    };

    struct Import {
        uint64_t reqId;
        std::string authorization;
        std::string body;
    };

    using Var = std::variant<Rpc, Import>;
    Var msg;
    MsgAdmin(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgPush : NonCopyable {
    struct DBChange {
    };

    struct PostDone {
        enum class Outcome { Sent, Failed, Gone, Skipped };

        uint64_t levId;
        std::string host;
        Outcome outcome;
    };

    // Sent before the commit, so the Push thread knows them before it can see the events
    struct AuthedWrites {
        struct Write {
            uint64_t levId;
            Bytes32 id;
            Bytes32 authed;
        };

        std::vector<Write> writes;
    };

    using Var = std::variant<DBChange, PostDone, AuthedWrites>;
    Var msg;
    MsgPush(Var &&msg_) : msg(std::move(msg_)) {}
};

struct MsgPushSender : NonCopyable {
    struct Post {
        uint64_t levId; // of the push subscription
        std::string callback;
        std::string host; // of the callback, without the port
        std::string payload;
    };

    using Var = std::variant<Post>;
    Var msg;
    MsgPushSender(Var &&msg_) : msg(std::move(msg_)) {}
};

inline std::string httpResponse(int status, std::string_view contentType, std::string_view content, std::string_view extraHeaders = "") {
    std::string statusText =
        status == 200 ? "OK" :
        status == 204 ? "No Content" :
        status == 400 ? "Bad Request" :
        status == 401 ? "Unauthorized" :
        status == 403 ? "Forbidden" :
        status == 409 ? "Conflict" :
        status == 413 ? "Payload Too Large" :
        "Error";

    std::string output = "HTTP/1.1 " + std::to_string(status) + " " + statusText + "\r\n";
    if (contentType.size()) output += std::string("Content-Type: ") + std::string(contentType) + "\r\n";
    output += "Access-Control-Allow-Origin: *\r\n";
    output += "Connection: keep-alive\r\n";
    output += "Server: strfry\r\n";
    output += std::string("Content-Length: ") + std::to_string(content.size()) + "\r\n";
    output += extraHeaders;
    output += "\r\n";
    output += content;
    return output;
}

// Flow control between the thread that reads a backup and the websocket thread that sends it
struct BackupStream {
    std::mutex mutex;
    std::condition_variable cv;
    uint64_t inFlight = 0; // bytes handed to uWS and not yet sent
    bool cancelled = false;
};

// NIP-9a challenge requests in flight, so that no client can take them all
struct PushVerifications {
    std::mutex mutex;
    uint64_t total = 0;
    flat_hash_map<std::string, uint64_t> perClient;

    // Empty when the check may start, otherwise the OK message to refuse the subscription with
    std::string acquire(const std::string &client) {
        std::lock_guard lock(mutex);

        auto it = perClient.find(client);
        if (it != perClient.end() && it->second >= cfg().relay__push__maxPendingVerificationsPerIp) return "rate-limited: too many push subscriptions being checked from your address, try again later";
        if (total >= cfg().relay__push__maxPendingVerifications) return "error: too many push subscriptions being checked, try again later";

        total++;
        perClient[client]++;
        return "";
    }

    void release(const std::string &client) {
        std::lock_guard lock(mutex);

        total--;
        if (auto it = perClient.find(client); it != perClient.end() && --it->second == 0) perClient.erase(it);
    }
};

struct RelayServerCtx {
    secp256k1_context *secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    FilterValidator filterValidator;
    SessionToken::Generator challengeGenerator;
    flat_hash_map<uint64_t, AuthSession> connIdToAuthSession;
};

struct RelayServer {
    uS::Async *hubTrigger = nullptr;
    uint64_t startedAt = hoytech::curr_time_s();
    std::atomic<bool> backupRunning = false;
    flat_hash_map<std::string, uint64_t> importTokens; // token -> expiry, admin thread only
    std::atomic<uint64_t> pendingPushes = 0;
    PushVerifications pushVerifications;

    // Thread Pools

    ThreadPool<MsgWebsocket> tpWebsocket;
    ThreadPool<MsgIngester> tpIngester;
    ThreadPool<MsgWriter> tpWriter;
    ThreadPool<MsgReqWorker> tpReqWorker;
    ThreadPool<MsgReqMonitor> tpReqMonitor;
    ThreadPool<MsgNegentropy> tpNegentropy;
    ThreadPool<MsgAdmin> tpAdmin;
    ThreadPool<MsgPush> tpPush;
    ThreadPool<MsgPushSender> tpPushSender;
    std::thread cronThread;
    std::thread signalHandlerThread;

    void run();

    void runWebsocket(ThreadPool<MsgWebsocket>::Thread &thr);

    void runIngester(ThreadPool<MsgIngester>::Thread &thr);
    void ingesterProcessEvent(lmdb::txn &txn, uint64_t connId, flat_hash_map<uint64_t, AuthSession*> &connIdToAuthStatus, std::string ipAddr, secp256k1_context *secpCtx, const tao::json::value &origJson, std::vector<MsgWriter> &output);
    void ingesterProcessEvent(lmdb::txn &txn, RelayServerCtx &rsctx, uint64_t connId, std::string ipAddr, const tao::json::value &origJson, std::vector<MsgWriter> &output);
    void ingesterProcessReq(lmdb::txn &txn, RelayServerCtx &rsctx, uint64_t connId, const tao::json::value &arr, bool countOnly, std::string &outSubIdStr);
    void ingesterProcessClose(lmdb::txn &txn, uint64_t connId, const tao::json::value &arr);
    void ingesterProcessAuth(RelayServerCtx &rsctx, uint64_t connId, const tao::json::value &eventJson);
    void ingesterProcessNegentropy(lmdb::txn &txn, RelayServerCtx &rsctx, uint64_t connId, const tao::json::value &origJson);

    void runWriter(ThreadPool<MsgWriter>::Thread &thr);

    void runReqWorker(ThreadPool<MsgReqWorker>::Thread &thr);

    void runReqMonitor(ThreadPool<MsgReqMonitor>::Thread &thr);

    void runNegentropy(ThreadPool<MsgNegentropy>::Thread &thr);

    void runAdmin(ThreadPool<MsgAdmin>::Thread &thr);
    std::string adminRpc(secp256k1_context *secpCtx, Decompressor &decomp, const MsgAdmin::Rpc &rpc);
    tao::json::value adminMethod(Decompressor &decomp, const std::string &method, const tao::json::value::array_t &params);
    std::string adminImport(secp256k1_context *secpCtx, const MsgAdmin::Import &msg);
    tao::json::value eventsNeedingModeration(Decompressor &decomp);
    tao::json::value stats();

    void streamBackup(uint64_t backupId, std::shared_ptr<BackupStream> stream);

    void runPush(ThreadPool<MsgPush>::Thread &thr);

    void runPushSender(ThreadPool<MsgPushSender>::Thread &thr);

    void verifyPushCallback(MsgWriter::AddEvent &&ev);

    void announceAuthedWrites(std::vector<EventToWrite> &newEvents);

    void runCron();

    void runSignalHandler();

    // Utils (can be called by any thread)

    void sendToConn(uint64_t connId, std::string &&payload) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(payload)}});
        hubTrigger->send();
    }

    void sendToConnBinary(uint64_t connId, std::string &&payload) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::SendBinary{connId, std::move(payload)}});
        hubTrigger->send();
    }

    void sendEvent(uint64_t connId, const SubId &subId, std::string_view evJson) {
        PROM_INC_RELAY_MSG("EVENT");
        auto subIdSv = subId.sv();

        std::string reply;
        reply.reserve(13 + subIdSv.size() + evJson.size());

        reply += "[\"EVENT\",\"";
        reply += subIdSv;
        reply += "\",";
        reply += evJson;
        reply += "]";

        sendToConn(connId, std::move(reply));
    }

    void sendEventToBatch(RecipientList &&list, std::string &&evJson) {
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::SendEventToBatch{std::move(list), std::move(evJson)}});
        hubTrigger->send();
    }

    void sendNoticeError(uint64_t connId, std::string &&payload) {
        PROM_INC_RELAY_MSG("NOTICE");
        LI << "sending error to [" << connId << "]: " << payload;
        auto reply = tao::json::value::array({ "NOTICE", std::string("ERROR: ") + payload });
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(tao::json::to_string(reply))}});
        hubTrigger->send();
    }

    void sendClosedError(uint64_t connId, const std::string &subId, std::string &&payload) {
        PROM_INC_RELAY_MSG("CLOSED");
        LI << "sending closed to [" << connId << "]: " << payload;
        auto reply = tao::json::value::array({ "CLOSED", subId, payload });
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(tao::json::to_string(reply))}});
        hubTrigger->send();
    }

    void sendOKResponse(uint64_t connId, std::string_view eventIdHex, bool written, std::string_view message) {
        PROM_INC_RELAY_MSG("OK");
        auto reply = tao::json::value::array({ "OK", eventIdHex, written, message });
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(tao::json::to_string(reply))}});
        hubTrigger->send();
    }

    void sendAuthChallenge(uint64_t connId, std::string_view challenge) {
        PROM_INC_RELAY_MSG("AUTH");
        PrometheusMetrics::getInstance().authChallengesSentTotal.inc();
        auto reply = tao::json::value::array({ "AUTH", challenge });
        tpWebsocket.dispatch(0, MsgWebsocket{MsgWebsocket::Send{connId, std::move(tao::json::to_string(reply))}});
        hubTrigger->send();
    }
};
