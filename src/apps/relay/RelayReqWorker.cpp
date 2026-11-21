#include "RelayServer.h"
#include "QueryScheduler.h"
#include "ReadRestrictor.h"


void RelayServer::runReqWorker(ThreadPool<MsgReqWorker>::Thread &thr) {
    Decompressor decomp;
    QueryScheduler queries;
    flat_hash_map<uint64_t, Bytes32> connIdToAuthedPubkey;

    queries.onEvent = [&](lmdb::txn &txn, const auto &sub, uint64_t levId, std::string_view eventPayload){
        auto it = connIdToAuthedPubkey.find(sub.connId);
        auto ev = lookupEventByLevId(txn, levId);
        PackedEventView packed(ev.buf);
        Bytes32 subscriberAuthedPubkey = it == connIdToAuthedPubkey.end() ? Bytes32() : it->second;
        if (!ReadRestrictor::shouldSendToSubscriber(txn, levId, packed, subscriberAuthedPubkey)) {
            return;
        }

        if (sub.countOnly) {
            sub.visibleCount++;
            return;
        }

        sendEvent(sub.connId, sub.subId, decodeEventPayload(txn, decomp, eventPayload, nullptr, nullptr));
    };

    queries.onComplete = [&](lmdb::txn &, Subscription &sub, uint64_t total){
        if (sub.countOnly) {
            // total also counts the events this client can't see, it only tells if the scan stopped at the limit
            bool limited = total > cfg().relay__maxFilterLimitCount;

            tao::json::value countBody = tao::json::value({
                { "count", std::min(sub.visibleCount, cfg().relay__maxFilterLimitCount) },
            });

            if (limited) countBody["limited"] = true;

            sendToConn(sub.connId, tao::json::to_string(tao::json::value::array({ "COUNT", sub.subId.str(), countBody })));
        } else {
            PROM_INC_RELAY_MSG("EOSE");
            sendToConn(sub.connId, tao::json::to_string(tao::json::value::array({ "EOSE", sub.subId.str() })));
            tpReqMonitor.dispatch(sub.connId, MsgReqMonitor{MsgReqMonitor::NewSub{std::move(sub)}});
        }
    };

    while(1) {
        auto newMsgs = queries.running.empty() ? thr.inbox.pop_all() : thr.inbox.pop_all_no_wait();

        auto txn = env.txn_ro();

        for (auto &newMsg : newMsgs) {
            if (auto msg = std::get_if<MsgReqWorker::NewSub>(&newMsg.msg)) {
                auto connId = msg->sub.connId;

                if (!queries.addSub(txn, std::move(msg->sub))) {
                    sendNoticeError(connId, std::string("too many concurrent REQs"));
                }

                queries.process(txn);
            } else if (auto msg = std::get_if<MsgReqWorker::SetAuth>(&newMsg.msg)) {
                connIdToAuthedPubkey[msg->connId] = msg->authed;
            } else if (auto msg = std::get_if<MsgReqWorker::RemoveSub>(&newMsg.msg)) {
                queries.removeSub(msg->connId, msg->subId);
                tpReqMonitor.dispatch(msg->connId, MsgReqMonitor{MsgReqMonitor::RemoveSub{msg->connId, msg->subId}});
            } else if (auto msg = std::get_if<MsgReqWorker::CloseConn>(&newMsg.msg)) {
                connIdToAuthedPubkey.erase(msg->connId);
                queries.closeConn(msg->connId);
                tpReqMonitor.dispatch(msg->connId, MsgReqMonitor{MsgReqMonitor::CloseConn{msg->connId}});
            }
        }

        queries.process(txn);

        txn.abort();
    }
}
