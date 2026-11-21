#pragma once

#include <string_view>

#include "PackedEvent.h"
#include "config.h"
#include "events.h"
#include "filters.h"

#include "golpe.h"

struct ReadRestrictor {
private:
    inline static uint64_t configVer = 0;
    inline static flat_hash_set<uint64_t> restrictedKinds_;

public:
    static void init(){
        parseCommaSeparatedKinds(cfg().relay__auth__restrictedReadKinds, restrictedKinds_);
    }

    static flat_hash_set<uint64_t>& restrictedKinds() {
        if (configVer != cfg().version()) {
            init();
            configVer = cfg().version();
        }
        return restrictedKinds_;
    }

    static bool isFilterGroupFullyRestricted(const NostrFilterGroup &fg) {
        if (restrictedKinds().empty() || fg.filters.empty()) return false;
        for (const auto& f : fg.filters) {
            if (!isFilterFullyRestricted(f)) return false;
        }
        return true;
    }

    static bool isFilterFullyRestricted(const NostrFilter &filter) {
        if (!filter.kinds) return false;

        for (size_t i = 0; i < filter.kinds->size(); ++i) {
            uint64_t kind = filter.kinds->at(i);

            if (!restrictedKinds().contains(kind)) {
                return false;
            }
        }
        return true;
    }

    static bool isFilterAllowedToCount(const NostrFilterGroup &fg, Bytes32 pubkey) {
        if (restrictedKinds().empty()) return true;

        bool pubkeyIsNull = pubkey.isNull();

        for (const auto &f: fg.filters) {
            if (!f.kinds) continue;
            bool hasSomeRestrictedKind = false;
            for (size_t i = 0; i < f.kinds->size(); ++i) {
                uint64_t kind = f.kinds->at(i);
                if (restrictedKinds().contains(kind)) {
                    hasSomeRestrictedKind = true;
                    break;
                }
            }
            if (hasSomeRestrictedKind) {
                if (pubkeyIsNull) {
                    return false;
                }
                if (!cfg().relay__auth__restrictReadToInvolvedPubkey) {
                    continue;
                }
                bool authorScoped = f.authors && allPubkeysMatch(*f.authors, pubkey);
                bool pScoped = false;
                if (auto it = f.tags.find('p'); it != f.tags.end()) {
                    pScoped = allPubkeysMatch(it->second, pubkey);
                }
                if (!authorScoped && !pScoped) return false;
            }
        }
        return true;
    }

    static bool allPubkeysMatch(const FilterSetBytes& set, Bytes32 authed) {
        if (set.size() == 0) return false;

        for (size_t i = 0; i < set.size(); ++i) {
            Bytes32 val(set.at(i));
            if (val != authed) return false;
        }
        return true;
    }

    // False means the event is public, true that shouldSendToSubscriber must decide
    static bool mayBeRestricted(const PackedEventView &packed) {
        return restrictedKinds().contains(packed.kind()) || (packed.kind() == 5 && restrictedKinds().contains(1059));
    }

    // A gift wrap deletion is as private as the wrap, or it would tell the sender when the wrap was deleted
    static bool isGiftWrapDeletion(lmdb::txn &txn, uint64_t levId, const PackedEventView &packed) {
        if (packed.kind() != 5 || !restrictedKinds().contains(1059)) return false;
        if (deletedGiftWrap(txn, levId)) return true;

        bool namesGiftWrapKind = false;

        packed.foreachTag([&](char tagName, std::string_view tagVal) {
            if (tagName == 'k' && (tagVal == "1059" || tagVal == "21059")) namesGiftWrapKind = true;
            return !namesGiftWrapKind;
        });

        return namesGiftWrapKind;
    }

    // Returns true if the event should be sent to the subscriber
    static bool shouldSendToSubscriber(lmdb::txn &txn, uint64_t levId, const PackedEventView &packed, const Bytes32 &subscriberAuthedPubkey) {
        bool giftWrapDeletion = isGiftWrapDeletion(txn, levId, packed);

        if (!giftWrapDeletion && !restrictedKinds().contains(packed.kind())) {
            return true;
        }

        if (subscriberAuthedPubkey.isNull()) {
            return false;
        }

        if(!cfg().relay__auth__restrictReadToInvolvedPubkey) return true;

        // NIP-59: a gift wrap is signed by a throwaway key, only its recipient is involved
        bool involved = !isGiftWrapKind(packed.kind()) && subscriberAuthedPubkey == packed.pubkey();

        if (giftWrapDeletion) return involved;

        packed.foreachTag([&](char tagName, std::string_view tagVal) {
            if (tagName == 'p' && tagVal.size() == 32) {
                if (subscriberAuthedPubkey == Bytes32(tagVal)) {
                    involved = true;
                    return false;
                }
            }

            return true;
        });

        return involved;
    }
};
