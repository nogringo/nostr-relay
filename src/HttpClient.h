#pragma once

#include <stdint.h>

#include <string>
#include <string_view>


struct HttpUrl {
    bool tls = false;
    std::string host; // IPv6 literals without brackets
    uint16_t port = 0;
    std::string target; // path and query

    static HttpUrl parse(std::string_view url);

    bool hostIsIp() const;
    std::string hostHeader() const;
};

// False for loopback, private, link-local, multicast and other special-purpose addresses
bool isPublicIp(const std::string &ip);

struct HttpResponse {
    int status;
    std::string body; // only read for a 2xx status
};

// Redirects are not followed by either
int httpPost(const HttpUrl &url, std::string_view contentType, std::string_view body, uint64_t timeoutSeconds, bool allowPrivateAddresses);
HttpResponse httpGet(const HttpUrl &url, size_t maxBodySize, uint64_t timeoutSeconds, bool allowPrivateAddresses);
