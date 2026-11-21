#pragma once

#include <parallel_hashmap/phmap.h>
#include <parallel_hashmap/btree.h>

#include <functional>
#include <string_view>

using namespace phmap;


#include "constants.h"
#include "Bytes32.h"


Bytes32 sha256(std::string_view inp);
std::string renderIP(std::string_view ipBytes);
std::string renderSize(uint64_t si);
std::string renderPercent(double p);
uint64_t parseUint64(const std::string &s);
std::string parseIP(const std::string &ip);
uint64_t getDBVersion(lmdb::txn &txn);
void exitOnSigPipe();
void foreachCommaSeparated(std::string_view str, const std::function<bool(std::string_view)> &cb);
void parseCommaSeparatedKinds(std::string_view str, flat_hash_set<uint64_t> &out);
std::string parsePubkey(std::string_view str);
flat_hash_set<std::string> parsePubkeyList(std::string_view str);
std::string normalizeRelayUrl(std::string_view url);
bool isServiceUrl(std::string_view url);
std::string primaryServiceUrl();

extern lmdb::dbi negentropyDbi;
