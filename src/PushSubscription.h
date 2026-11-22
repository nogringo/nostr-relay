#pragma once

#include <algorithm>
#include <cctype>

#include "golpe.h"

#include "filters.h"
#include "HttpClient.h"


inline bool pushEnabled() {
    return cfg().relay__push__enabled && cfg().relay__auth__serviceUrl.size();
}

// NIP-9a payloads name the relay as clients normalize it: lowercase, no default port, "/" for an empty path
inline std::string canonicalRelayUrl(std::string_view input) {
    std::string url(input.substr(0, input.find('#')));
    std::transform(url.begin(), url.end(), url.begin(), [](unsigned char c){ return std::tolower(c); });

    auto schemeEnd = url.find("://");
    size_t pathStart = url.find_first_of("/?", schemeEnd == std::string::npos ? 0 : schemeEnd + 3);
    if (pathStart == std::string::npos) pathStart = url.size();

    std::string_view defaultPort = url.starts_with("wss://") ? ":443" : url.starts_with("ws://") ? ":80" : "";

    if (defaultPort.size() && std::string_view(url).substr(0, pathStart).ends_with(defaultPort)) {
        pathStart -= defaultPort.size();
        url.erase(pathStart, defaultPort.size());
    }

    if (pathStart == url.size() || url[pathStart] == '?') url.insert(pathStart, "/");

    return url;
}

// A kind 30390 event. The constructor throws the reason when this relay can't fulfill it.
struct PushSubscription : NonCopyable {
    std::string relay;
    std::string callback;
    bool includeEvent = false;
    NostrFilterGroup filters;
    NostrFilterGroup ignore;

    explicit PushSubscription(const tao::json::value &ev) {
        for (const auto &tagJson : ev.at("tags").get_array()) {
            const auto &tag = tagJson.get_array();
            if (tag.empty() || !tag[0].is_string()) continue;

            const auto &name = tag[0].get_string();

            if (name == "include_event") {
                includeEvent = true;
                continue;
            }

            if (tag.size() < 2 || !tag[1].is_string()) continue;

            const auto &val = tag[1].get_string();

            if (name == "relay") {
                if (relay.empty() && isServiceUrl(val)) relay = canonicalRelayUrl(val);
            } else if (name == "callback") {
                if (callback.size()) throw herr("push subscription has more than one callback");
                callback = val;
            } else if (name == "filter" || name == "ignore") {
                try {
                    (name == "filter" ? filters : ignore).addFilter(tao::json::from_string(val));
                } catch (std::exception &e) {
                    throw herr("bad ", name, " tag: ", e.what());
                }
            }
        }

        if (relay.empty()) throw herr("push subscription does not name this relay");
        if (callback.empty()) throw herr("push subscription has no callback");
        if (filters.size() == 0) throw herr("push subscription has no filter that can match");

        HttpUrl url;

        try {
            url = HttpUrl::parse(callback);
        } catch (std::exception &e) {
            throw herr("bad callback: ", e.what());
        }

        if (!cfg().relay__push__allowPrivateCallbacks && url.hostIsIp() && !isPublicIp(url.host)) {
            throw herr("callback is not a public address");
        }
    }
};
