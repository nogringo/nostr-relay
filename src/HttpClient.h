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

// Returns the response status. Redirects are not followed.
int httpPost(const HttpUrl &url, std::string_view contentType, std::string_view body, uint64_t timeoutSeconds, bool allowPrivateAddresses);
