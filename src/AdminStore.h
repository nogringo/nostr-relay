#pragma once

#include <atomic>
#include <functional>

#include "golpe.h"

#include "events.h"


// State managed through the NIP-86 relay management API

namespace adminStore {

// Bumped on every change, so cached NIP-11 responses get rebuilt
inline std::atomic<uint64_t> version = 0;

inline std::string kindKey(uint64_t kind) {
    return std::string(lmdb::to_sv<uint64_t>(kind));
}

inline bool listContains(lmdb::txn &txn, lmdb::dbi &dbi, std::string_view key) {
    std::string_view val;
    return dbi.get(txn, key, val);
}

inline bool listEmpty(lmdb::txn &txn, lmdb::dbi &dbi) {
    return dbi.size(txn) == 0;
}

inline void foreachListEntry(lmdb::txn &txn, lmdb::dbi &dbi, const std::function<void(std::string_view, std::string_view)> &cb) {
    auto cursor = lmdb::cursor::open(txn, dbi);
    std::string_view k, v;

    for (bool found = cursor.get(k, v, MDB_FIRST); found; found = cursor.get(k, v, MDB_NEXT)) cb(k, v);
}

inline bool isAdmin(std::string_view pubkey) {
    thread_local uint64_t configVer = MAX_U64;
    thread_local flat_hash_set<std::string> admins;

    if (configVer != cfg().version()) {
        admins = parsePubkeyList(cfg().relay__admin__pubkeys);
        configVer = cfg().version();
    }

    return admins.contains(std::string(pubkey));
}

inline bool isAllowedWriter(lmdb::txn &txn, std::string_view pubkey) {
    return isAdmin(pubkey) || listContains(txn, env.dbi_AllowedPubkey, pubkey);
}

inline bool isAllowedAuthor(lmdb::txn &txn, const PackedEventView &packed) {
    // NIP-59: a gift wrap is signed by a throwaway key, so its recipient is the one to allow
    if (!isGiftWrapKind(packed.kind())) return isAllowedWriter(txn, packed.pubkey());

    bool allowed = false;

    packed.foreachTag([&](char tagName, std::string_view tagVal){
        if (tagName == 'p' && isAllowedWriter(txn, tagVal)) allowed = true;
        return !allowed;
    });

    return allowed;
}

// Empty when the event may be stored, otherwise the OK message to reject it with
inline std::string writeRejection(lmdb::txn &txn, const PackedEventView &packed) {
    // NIP-62: relays that restrict who can post MUST still honor a request to vanish
    if (packed.kind() == 62) return "";

    if (listContains(txn, env.dbi_BannedEvent, packed.id())) return "blocked: this event is banned";
    if (listContains(txn, env.dbi_AllowedEvent, packed.id())) return "";
    if (listContains(txn, env.dbi_BannedPubkey, packed.pubkey())) return "blocked: this pubkey is banned";

    auto kind = kindKey(packed.kind());

    if (listContains(txn, env.dbi_DisallowedKind, kind) || (!listEmpty(txn, env.dbi_AllowedKind) && !listContains(txn, env.dbi_AllowedKind, kind))) {
        return "blocked: this kind is not accepted";
    }

    if (!listEmpty(txn, env.dbi_AllowedPubkey) && !isAllowedAuthor(txn, packed)) return "restricted: this pubkey is not allowed to write here";

    return "";
}

// Stored events that a ban covers. The most recent event is left out: deleting it would let the next insert reuse its levId
inline std::vector<uint64_t> bannedLevIds(lmdb::txn &txn) {
    std::vector<uint64_t> levIds;
    uint64_t mostRecent = getMostRecentLevId(txn);

    auto collect = [&](uint64_t levId){
        if (levId != mostRecent) levIds.push_back(levId);
    };

    foreachListEntry(txn, env.dbi_BannedEvent, [&](std::string_view id, std::string_view){
        if (auto ev = lookupEventById(txn, id)) collect(ev->primaryKeyId);
    });

    foreachListEntry(txn, env.dbi_BannedPubkey, [&](std::string_view pubkey, std::string_view){
        env.generic_foreachFull(txn, env.dbi_Event__pubkey, makeKey_StringUint64(pubkey, 0), lmdb::to_sv<uint64_t>(0), [&](auto k, auto v) {
            ParsedKey_StringUint64 parsedKey(k);
            if (parsedKey.s != pubkey) return false;

            auto levId = lmdb::from_sv<uint64_t>(v);
            PackedEventView packed(lookupEventByLevId(txn, levId).buf);

            // Requests to vanish keep blocking re-broadcasts, and gift wraps belong to their recipient (NIP-59)
            if (packed.kind() != 62 && !isGiftWrapKind(packed.kind()) && !listContains(txn, env.dbi_AllowedEvent, packed.id())) collect(levId);
            return true;
        });
    });

    return levIds;
}

// An IPv4 address reached through an IPv6 socket (::ffff:a.b.c.d) is stored and matched as plain IPv4
inline std::string canonicalIp(std::string_view ipBytes) {
    static const std::string_view v4MappedPrefix("\0\0\0\0\0\0\0\0\0\0\xff\xff", 12);
    if (ipBytes.size() == 16 && ipBytes.starts_with(v4MappedPrefix)) return std::string(ipBytes.substr(12));
    return std::string(ipBytes);
}

inline bool isIpBlocked(lmdb::txn &txn, std::string_view ipBytes) {
    return listContains(txn, env.dbi_BlockedIP, canonicalIp(ipBytes));
}

inline const flat_hash_map<std::string, bool> settingDefaults = {
    { "nip70", true }, // when false, the "-" tag is ignored
};

inline bool setting(lmdb::txn &txn, const std::string &name) {
    std::string_view val;
    if (env.dbi_RelaySetting.get(txn, name, val)) return val == "1";
    return settingDefaults.at(name);
}

inline std::string relayInfo(lmdb::txn &txn, std::string_view field, const std::string &configured) {
    std::string_view val;
    if (env.dbi_RelayInfo.get(txn, field, val)) return std::string(val);
    return configured;
}

}
