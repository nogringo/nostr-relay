#include "RelayServer.h"

#include "ActiveMonitors.h"
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
        bool includeEvent;
        NostrFilterGroup ignore;
    };

    // Each subscription is a monitor whose connId is the levId of its event
    Decompressor decomp;
    ActiveMonitors monitors;
    flat_hash_map<uint64_t, ActivePush> pushes;
    std::vector<uint64_t> gone; // answered 404, deleted once they are not the most recent event
    const SubId subId("push");
    uint64_t currEventId;
    uint64_t lastSweep = hoytech::curr_time_s();
    uint64_t nextSender = 0;
    uint64_t lastDropWarning = 0;

    auto add = [&](lmdb::txn &txn, uint64_t levId, uint64_t latestEventId){
        try {
            PackedEventView packed(lookupEventByLevId(txn, levId).buf);
            PushSubscription sub(tao::json::from_string(getEventJson(txn, decomp, levId)));

            Subscription monitored(levId, subId.str(), std::move(sub.filters));
            monitored.latestEventId = latestEventId;
            if (!monitors.addSub(txn, std::move(monitored), latestEventId)) throw herr("relay.maxSubsPerConnection is 0");

            pushes.try_emplace(levId, ActivePush{ Bytes32(packed.pubkey()), std::move(sub.relay), std::move(sub.callback), sub.includeEvent, std::move(sub.ignore) });
        } catch (std::exception &e) {
            LW << "Ignoring push subscription levId=" << levId << ": " << e.what();
        }
    };

    auto remove = [&](uint64_t levId){
        monitors.removeSub(levId, subId);
        pushes.erase(levId);
    };

    auto notify = [&](lmdb::txn &txn, uint64_t pushLevId, uint64_t levId, const PackedEventView &packed){
        auto it = pushes.find(pushLevId);
        if (it == pushes.end()) return;

        // Replaced, deleted, expired or banned since it was loaded
        if (!env.lookup_Event(txn, pushLevId)) {
            remove(pushLevId);
            return;
        }

        const auto &push = it->second;

        if (!pushEnabled()) return;
        if (push.ignore.doesMatch(packed)) return;
        if (!ReadRestrictor::shouldSendToSubscriber(txn, levId, packed, push.pubkey)) return;

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

        pendingPushes++;
        tpPushSender.dispatch(nextSender++, MsgPushSender{MsgPushSender::Post{pushLevId, push.callback, tao::json::to_string(payload)}});
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

    while (1) {
        auto newMsgs = thr.inbox.pop_all();

        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgPush::CallbackGone>(&newMsg.msg)) {
                if (!pushes.contains(msg->levId)) continue;
                remove(msg->levId);
                gone.push_back(msg->levId);
            }
        }

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

                if (numDeleted) LI << "Deleted " << numDeleted << " push subscriptions whose callback answered 404";
            }
        }

        auto txn = env.txn_ro();

        uint64_t latestEventId = getMostRecentLevId(txn);
        if (currEventId > latestEventId) currEventId = latestEventId;

        env.foreach_Event(txn, [&](auto &ev){
            PackedEventView packed(ev.buf);

            monitors.process(txn, ev, [&](RecipientList &&recipients, uint64_t levId){
                for (const auto &recipient : recipients) notify(txn, recipient.connId, levId, packed);
            });

            if (packed.kind() == PUSH_SUBSCRIPTION_KIND) add(txn, ev.primaryKeyId, ev.primaryKeyId);

            return true;
        }, false, currEventId + 1);

        currEventId = latestEventId;

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


void RelayServer::runPushSender(ThreadPool<MsgPushSender>::Thread &thr) {
    while (1) {
        auto newMsgs = thr.inbox.pop_all();

        for (auto &newMsg : newMsgs) {
            auto &post = std::get<MsgPushSender::Post>(newMsg.msg);
            std::string host = "?";

            try {
                auto url = HttpUrl::parse(post.callback);
                host = url.hostHeader(); // the path is left out of logs, it often holds a secret token

                int status = httpPost(url, "application/json", post.payload, cfg().relay__push__timeoutSeconds, cfg().relay__push__allowPrivateCallbacks);

                if (status >= 200 && status < 300) {
                    PrometheusMetrics::getInstance().pushSentTotal.inc();
                } else {
                    PrometheusMetrics::getInstance().pushFailedTotal.inc();
                    LW << "Push callback at " << host << " answered " << status;
                    if (status == 404) tpPush.dispatch(0, MsgPush{MsgPush::CallbackGone{post.levId}});
                }
            } catch (std::exception &e) {
                PrometheusMetrics::getInstance().pushFailedTotal.inc();
                LW << "Push to callback at " << host << " failed: " << e.what();
            }

            pendingPushes--;
        }
    }
}
