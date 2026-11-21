#include <arpa/inet.h>
#ifdef __FreeBSD__
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <signal.h>

#include <algorithm>
#include <functional>
#include <string>

#include <openssl/sha.h>

#include "golpe.h"

#include "Bech32Utils.h"



Bytes32 sha256(std::string_view inp) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(inp.data()), inp.size(), hash);

    return Bytes32(std::string_view(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH));
}

std::string renderIP(std::string_view ipBytes) {
    char buf[128];

    if (ipBytes.size() == 4) {
        inet_ntop(AF_INET, ipBytes.data(), buf, sizeof(buf));
    } else if (ipBytes.size() == 16) {
        inet_ntop(AF_INET6, ipBytes.data(), buf, sizeof(buf));
    } else {
        throw herr("invalid size of ipBytes, unable to render IP");
    }

    return std::string(buf);
}

std::string parseIP(const std::string &ip) {
    int af = ip.find(':') != std::string::npos ? AF_INET6 : AF_INET;
    unsigned char buf[16];

    int ret = inet_pton(af, ip.c_str(), &buf[0]);
    if (ret == 0) return "";

    return std::string((const char*)&buf[0], af == AF_INET6 ? 16 : 4);
}


std::string renderSize(uint64_t si) {
    if (si < 1024) return std::to_string(si) + "b";

    double s = si;
    char buf[128];
    char unit;

    do {
        s /= 1024;
        if (s < 1024) {
            unit = 'K';
            break;
        }

        s /= 1024;
        if (s < 1024) {
            unit = 'M';
            break;
        }

        s /= 1024;
        if (s < 1024) {
            unit = 'G';
            break;
        }

        s /= 1024;
        unit = 'T';
    } while(0);

    ::snprintf(buf, sizeof(buf), "%.2f%c", s, unit);
    return std::string(buf);
}



std::string renderPercent(double p) {
    char buf[128];
    ::snprintf(buf, sizeof(buf), "%.1f%%", p * 100);
    return std::string(buf);
}



uint64_t parseUint64(const std::string &s) {
    auto digitChar = [](char c){
        return c >= '0' && c <= '9';
    };

    if (!std::all_of(s.begin(), s.end(), digitChar)) throw herr("non-digit character");

    return std::stoull(s);
}



uint64_t getDBVersion(lmdb::txn &txn) {
    uint64_t dbVersion;

    {
        auto s = env.lookup_Meta(txn, 1);

        if (s) {
            dbVersion = s->dbVersion();
        } else {
            dbVersion = 0;
        }
    }

    return dbVersion;
}


void exitOnSigPipe() {
    struct sigaction act;
    memset(&act, 0, sizeof act);
    act.sa_sigaction = [](int, siginfo_t*, void*){ ::exit(1); };
    if (sigaction(SIGPIPE, &act, nullptr)) throw herr("couldn't run sigaction(): ", strerror(errno));
}


void foreachCommaSeparated(std::string_view str, const std::function<bool(std::string_view)> &cb) {
    size_t pos = 0;
    while (pos < str.size()) {
        size_t nextComma = str.find(',', pos);
        if (nextComma == std::string::npos) nextComma = str.size();

        std::string_view item = str.substr(pos, nextComma - pos);
        size_t start = item.find_first_not_of(" \t");
        size_t end = item.find_last_not_of(" \t");
        if (start != std::string::npos && end != std::string::npos) {
            if (!cb(item.substr(start, end - start + 1))) return;
        }

        pos = nextComma + 1;
    }
}


void parseCommaSeparatedKinds(std::string_view str, flat_hash_set<uint64_t> &out) {
    out.clear();
    foreachCommaSeparated(str, [&](std::string_view kindStr){
        out.insert(std::stoull(std::string(kindStr)));
        return true;
    });
}


std::string normalizeRelayUrl(std::string_view input) {
    std::string url(input);
    std::transform(url.begin(), url.end(), url.begin(), [](unsigned char c){ return std::tolower(c); });

    std::string_view defaultPort;
    if (url.starts_with("wss://") || url.starts_with("https://")) defaultPort = ":443";
    else if (url.starts_with("ws://") || url.starts_with("http://")) defaultPort = ":80";

    auto pos = url.find("://");
    if (pos != std::string::npos) url.erase(0, pos + 3);
    pos = url.find_first_of("/?#");
    if (pos != std::string::npos) url.erase(pos);
    if (defaultPort.size() && url.ends_with(defaultPort)) url.erase(url.size() - defaultPort.size());

    return url;
}

bool isServiceUrl(std::string_view url) {
    auto normalized = normalizeRelayUrl(url);
    bool found = false;

    foreachCommaSeparated(cfg().relay__auth__serviceUrl, [&](std::string_view serviceUrl){
        found = normalizeRelayUrl(serviceUrl) == normalized;
        return !found;
    });

    return found;
}

std::string primaryServiceUrl() {
    std::string primary;

    foreachCommaSeparated(cfg().relay__auth__serviceUrl, [&](std::string_view serviceUrl){
        primary = serviceUrl;
        return false;
    });

    return primary;
}


std::string parsePubkey(std::string_view str) {
    if (str.starts_with("npub1")) return decodeBech32Simple(str);

    if (str.size() != 64) throw herr("pubkey must be an npub or 64 hex digits");
    return from_hex(str);
}

flat_hash_set<std::string> parsePubkeyList(std::string_view str) {
    flat_hash_set<std::string> pubkeys;

    foreachCommaSeparated(str, [&](std::string_view item){
        try {
            pubkeys.insert(parsePubkey(item));
        } catch (...) {
        }
        return true;
    });

    return pubkeys;
}
