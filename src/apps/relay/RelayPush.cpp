#include <thread>

#include "RelayServer.h"

#include "ActiveMonitors.h"
#include "AdminStore.h"
#include "ReadRestrictor.h"
#include "PushSubscription.h"
#include "HttpClient.h"


// NIP-9a: POSTs new events to the callback of each push subscription (kind 30390) they match

void RelayServer::runPush(ThreadPool<MsgPush>::Thread &thr) {
    auto dbChangeWatcher = hoytech::file_change_monitor(dbDir + "/data.mdb");

    dbChangeWatcher.setDebounce(100);

    dbChangeWatcher.run([&](){
        tpPush.dispatch(0, MsgPush{MsgPush::DBChange{}});
    });

    struct ActivePush {
        Bytes32 pubkey;
        std::string relay;
        std::string callback;
        std::string host;
        bool includeEvent;
        bool ignoreSelf;
        NostrFilterGroup ignore;
        uint64_t pending = 0;
        uint64_t failures = 0; // in a row
        uint64_t failingSince = 0;
        uint64_t suspendedUntil = 0;
    };

    struct CallbackHost {
        uint64_t subscriptions = 0;
        uint64_t pending = 0;
        uint64_t failures = 0; // in a row, across its subscriptions
    };

    using Outcome = MsgPush::PostDone::Outcome;

    // Each subscription is a monitor whose connId is the levId of its event
    Decompressor decomp;
    ActiveMonitors monitors;
    flat_hash_map<uint64_t, ActivePush> pushes;
    flat_hash_map<std::string, CallbackHost> hosts;
    std::vector<uint64_t> gone; // answered 404 or kept failing, deleted once they are not the most recent event
    flat_hash_map<uint64_t, MsgPush::AuthedWrites::Write> authedWrites; // levId -> who sent it, until the scan reaches it
    const SubId subId("push");
    uint64_t currEventId;
    uint64_t lastSweep = hoytech::curr_time_s();
    uint64_t nextSender = 0;
    uint64_t lastDropWarning = 0;

    auto maxFailures = []{ return std::max<uint64_t>(cfg().relay__push__maxFailures, 1); };

    auto add = [&](lmdb::txn &txn, uint64_t levId, uint64_t latestEventId){
        try {
            PackedEventView packed(lookupEventByLevId(txn, levId).buf);
            PushSubscription sub(tao::json::from_string(getEventJson(txn, decomp, levId)));
            auto host = HttpUrl::parse(sub.callback).host;

            Subscription monitored(levId, subId.str(), std::move(sub.filters));
            monitored.latestEventId = latestEventId;
            if (!monitors.addSub(txn, std::move(monitored), latestEventId)) throw herr("relay.maxSubsPerConnection is 0");

            auto [it, inserted] = pushes.try_emplace(levId, ActivePush{ Bytes32(packed.pubkey()), std::move(sub.relay), std::move(sub.callback), host, sub.includeEvent, sub.ignoreSelf, std::move(sub.ignore) });
            if (inserted) hosts[host].subscriptions++;
        } catch (std::exception &e) {
            LW << "Ignoring push subscription levId=" << levId << ": " << e.what();
        }
    };

    auto releaseHost = [&](decltype(hosts)::iterator it){
        if (!it->second.subscriptions && !it->second.pending) hosts.erase(it);
    };

    auto remove = [&](uint64_t levId){
        monitors.removeSub(levId, subId);

        auto it = pushes.find(levId);
        if (it == pushes.end()) return;

        if (auto host = hosts.find(it->second.host); host != hosts.end()) {
            host->second.subscriptions--;
            releaseHost(host);
        }

        pushes.erase(it);
    };

    auto notify = [&](lmdb::txn &txn, uint64_t pushLevId, uint64_t levId, const PackedEventView &packed, const Bytes32 &authedSender){
        auto it = pushes.find(pushLevId);
        if (it == pushes.end()) return;

        // Replaced, deleted, expired or banned since it was loaded
        if (!env.lookup_Event(txn, pushLevId)) {
            remove(pushLevId);
            return;
        }

        auto &push = it->second;

        if (!pushEnabled()) return;
        if (push.ignoreSelf && authedSender == push.pubkey) return;
        if (push.ignore.doesMatch(packed)) return;
        if (!ReadRestrictor::shouldSendToSubscriber(txn, levId, packed, push.pubkey)) return;

        // A failing callback gets one request at a time, so it holds at most one PushSender thread
        auto &host = hosts[push.host];
        uint64_t subLimit = push.failures ? 1 : cfg().relay__push__maxPendingPerSubscription;
        uint64_t hostLimit = host.failures >= maxFailures() ? 1 : cfg().relay__push__maxPendingPerHost;

        if (push.suspendedUntil > hoytech::curr_time_s() || push.pending >= subLimit || host.pending >= hostLimit) {
            PrometheusMetrics::getInstance().pushThrottledTotal.inc();
            return;
        }

        if (pendingPushes >= cfg().relay__push__maxPendingRequests) {
            PrometheusMetrics::getInstance().pushDroppedTotal.inc();
            uint64_t now = hoytech::curr_time_s();
            if (now - lastDropWarning >= 60) {
                LW << "Dropping push notifications: " << pendingPushes << " requests pending, see relay.push.maxPendingRequests";
                lastDropWarning = now;
            }
            return;
        }

        tao::json::value payload = tao::json::value({
            { "id", to_hex(packed.id()) },
            { "relay", push.relay },
        });

        if (push.includeEvent) payload["event"] = tao::json::from_string(getEventJson(txn, decomp, levId));

        push.pending++;
        host.pending++;
        pendingPushes++;
        tpPushSender.dispatch(nextSender++, MsgPushSender{MsgPushSender::Post{pushLevId, push.callback, push.host, tao::json::to_string(payload)}});
    };

    auto postDone = [&](const MsgPush::PostDone &done){
        if (auto host = hosts.find(done.host); host != hosts.end()) {
            host->second.pending--;
            if (done.outcome == Outcome::Failed) host->second.failures++;
            else if (done.outcome != Outcome::Skipped) host->second.failures = 0;
            releaseHost(host);
        }

        auto it = pushes.find(done.levId);
        if (it == pushes.end()) return;

        auto &push = it->second;
        push.pending--;

        if (done.outcome == Outcome::Sent) {
            push.failures = 0;
            return;
        }

        if (done.outcome == Outcome::Gone) {
            remove(done.levId);
            gone.push_back(done.levId);
            return;
        }

        if (done.outcome != Outcome::Failed) return;

        uint64_t now = hoytech::curr_time_s();
        if (push.failures++ == 0) push.failingSince = now;

        uint64_t deleteAfter = cfg().relay__push__deleteAfterFailingSeconds;

        if (deleteAfter && now - push.failingSince >= deleteAfter) {
            LI << "Deleting push subscription levId=" << done.levId << ", its callback at " << done.host << " has failed every request for " << (now - push.failingSince) << "s";
            remove(done.levId);
            gone.push_back(done.levId);
            return;
        }

        if (push.failures < maxFailures()) return;

        uint64_t backoff = std::min<uint64_t>(uint64_t(60) << std::min<uint64_t>(push.failures - maxFailures(), 6), 3600);
        push.suspendedUntil = now + backoff;
        LW << "Suspending push subscription levId=" << done.levId << " for " << backoff << "s after " << push.failures << " failed requests in a row to its callback at " << done.host;
    };

    {
        auto txn = env.txn_ro();
        currEventId = getMostRecentLevId(txn);

        env.generic_foreachFull(txn, env.dbi_Event__kind, makeKey_Uint64Uint64(PUSH_SUBSCRIPTION_KIND, 0), lmdb::to_sv<uint64_t>(0), [&](auto k, auto v) {
            ParsedKey_Uint64Uint64 parsedKey(k);
            if (parsedKey.n1 != PUSH_SUBSCRIPTION_KIND) return false;
            add(txn, lmdb::from_sv<uint64_t>(v), currEventId);
            return true;
        });

        if (pushes.size()) LI << "Loaded " << pushes.size() << " push subscriptions";
    }

    auto handle = [&](std::deque<MsgPush> newMsgs){
        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgPush::PostDone>(&newMsg.msg)) {
                postDone(*msg);
            } else if (auto msg = std::get_if<MsgPush::AuthedWrites>(&newMsg.msg)) {
                for (auto &write : msg->writes) authedWrites.insert_or_assign(write.levId, write);
            }
        }
    };

    while (1) {
        handle(thr.inbox.pop_all());

        if (gone.size()) {
            auto txn = env.txn_rw();
            uint64_t mostRecent = getMostRecentLevId(txn);

            std::vector<uint64_t> levIds;
            std::erase_if(gone, [&](uint64_t levId){
                if (levId == mostRecent) return false;
                levIds.push_back(levId);
                return true;
            });

            if (levIds.size()) {
                NegentropyFilterCache neFilterCache;
                uint64_t numDeleted = deleteEvents(txn, neFilterCache, levIds);
                txn.commit();

                if (numDeleted) LI << "Deleted " << numDeleted << " push subscriptions whose callback answered 404 or kept failing";
            }
        }

        auto txn = env.txn_ro();

        // Every write this txn can see was announced before its commit
        handle(thr.inbox.pop_all_no_wait());

        uint64_t latestEventId = getMostRecentLevId(txn);
        if (currEventId > latestEventId) currEventId = latestEventId;

        env.foreach_Event(txn, [&](auto &ev){
            PackedEventView packed(ev.buf);
            Bytes32 authedSender;

            // The id check covers a levId reused after a failed commit
            if (auto it = authedWrites.find(ev.primaryKeyId); it != authedWrites.end()) {
                if (it->second.id == packed.id()) authedSender = it->second.authed;
                authedWrites.erase(it);
            }

            monitors.process(txn, ev, [&](RecipientList &&recipients, uint64_t levId){
                for (const auto &recipient : recipients) notify(txn, recipient.connId, levId, packed, authedSender);
            });

            if (packed.kind() == PUSH_SUBSCRIPTION_KIND) add(txn, ev.primaryKeyId, ev.primaryKeyId);

            return true;
        }, false, currEventId + 1);

        currEventId = latestEventId;

        // Events deleted before the scan reached them
        if (authedWrites.size()) {
            std::vector<uint64_t> passed;
            for (const auto &[levId, write] : authedWrites) {
                if (levId <= latestEventId) passed.push_back(levId);
            }
            for (auto levId : passed) authedWrites.erase(levId);
        }

        // Frees subscriptions deleted without ever matching again
        if (hoytech::curr_time_s() - lastSweep >= 60) {
            std::vector<uint64_t> deleted;

            for (const auto &[levId, push] : pushes) {
                if (!env.lookup_Event(txn, levId)) deleted.push_back(levId);
            }

            for (auto levId : deleted) remove(levId);

            lastSweep = hoytech::curr_time_s();
        }
    }
}


// NIP-9a: the callback must echo a random challenge, so a subscription can't aim the relay at a server that never asked for it
static void verifyCallback(const std::string &callback) {
    auto url = HttpUrl::parse(callback);
    auto challenge = SessionToken::Generator().get();

    if (!url.target.ends_with('?') && !url.target.ends_with('&')) url.target += url.target.find('?') == std::string::npos ? '?' : '&';
    url.target += "challenge=" + challenge;

    auto res = httpGet(url, 1024, cfg().relay__push__verifyTimeoutSeconds, cfg().relay__push__allowPrivateCallbacks);

    if (res.status < 200 || res.status >= 300) throw herr("answered ", res.status);
    if (res.body != challenge) throw herr("the response is not the challenge");
}

// IPv6 clients usually hold a whole /64, so they are counted by network
static std::string verificationClient(std::string_view ipAddr) {
    auto ip = adminStore::canonicalIp(ipAddr);
    if (ip.size() == 16) ip.resize(8);
    return ip;
}

// Each check gets its own thread, so a callback that never answers holds up neither the other checks nor the pushes
void RelayServer::verifyPushCallback(MsgWriter::AddEvent &&ev) {
    auto idHex = to_hex(PackedEventView(ev.packedStr).id());
    auto client = verificationClient(ev.ipAddr);

    if (auto refusal = pushVerifications.acquire(client); refusal.size()) {
        LI << "[" << ev.connId << "] Push subscription " << idHex << " refused: " << refusal;
        sendOKResponse(ev.connId, idHex, false, refusal);
        return;
    }

    auto check = [this, idHex, client](MsgWriter::AddEvent &ev){
        try {
            verifyCallback(PushSubscription(tao::json::from_string(ev.jsonStr)).callback);
            ev.callbackVerified = true;
        } catch (std::exception &e) {
            LI << "[" << ev.connId << "] Push subscription " << idHex << " refused, its callback failed the challenge: " << e.what();
            sendOKResponse(ev.connId, idHex, false, std::string("invalid: callback verification failed: ") + e.what());
        }

        pushVerifications.release(client);
        if (ev.callbackVerified) tpWriter.dispatch(0, MsgWriter{std::move(ev)});
    };

    auto connId = ev.connId;

    try {
        std::thread([check, ev = std::move(ev)]() mutable { check(ev); }).detach();
    } catch (std::exception &e) {
        LE << "Can't start a thread to check a push callback: " << e.what();
        pushVerifications.release(client);
        sendOKResponse(connId, idHex, false, "error: could not check the callback, try again later");
    }
}

// An answer after more than half of the timeout is a failure: it holds a PushSender thread nearly as long as no answer
static MsgPush::PostDone::Outcome postToCallback(const MsgPushSender::Post &post) {
    using Outcome = MsgPush::PostDone::Outcome;
    std::string host = "?";

    try {
        auto url = HttpUrl::parse(post.callback);
        host = url.hostHeader(); // the path is left out of logs, it often holds a secret token

        uint64_t timeout = cfg().relay__push__timeoutSeconds;
        auto start = std::chrono::steady_clock::now();
        int status = httpPost(url, "application/json", post.payload, timeout, cfg().relay__push__allowPrivateCallbacks);
        auto elapsed = std::chrono::steady_clock::now() - start;

        if (status >= 200 && status < 300) {
            PrometheusMetrics::getInstance().pushSentTotal.inc();
            if (elapsed * 2 <= std::chrono::seconds(timeout)) return Outcome::Sent;

            LW << "Push callback at " << host << " took " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << "ms to answer";
            return Outcome::Failed;
        }

        PrometheusMetrics::getInstance().pushFailedTotal.inc();
        LW << "Push callback at " << host << " answered " << status;
        return status == 404 ? Outcome::Gone : Outcome::Failed;
    } catch (std::exception &e) {
        PrometheusMetrics::getInstance().pushFailedTotal.inc();
        LW << "Push to callback at " << host << " failed: " << e.what();
        return Outcome::Failed;
    }
}

void RelayServer::runPushSender(ThreadPool<MsgPushSender>::Thread &thr) {
    while (1) {
        auto newMsgs = thr.inbox.pop_all();

        for (auto &newMsg : newMsgs) {
            auto &post = std::get<MsgPushSender::Post>(newMsg.msg);

            // Queued behind slow callbacks, the subscription may have been deleted or replaced since
            bool stored;
            {
                auto txn = env.txn_ro();
                stored = !!env.lookup_Event(txn, post.levId);
            }

            auto outcome = stored ? postToCallback(post) : MsgPush::PostDone::Outcome::Skipped;

            pendingPushes--;
            tpPush.dispatch(0, MsgPush{MsgPush::PostDone{post.levId, std::move(post.host), outcome}});
        }
    }
}
