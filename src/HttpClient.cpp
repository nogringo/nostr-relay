#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <memory>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "golpe.h"

#include "HttpClient.h"


HttpUrl HttpUrl::parse(std::string_view input) {
    HttpUrl url;

    for (unsigned char c : input) {
        if (c <= 0x20 || c >= 0x7F) throw herr("URL contains a space or a control character");
    }

    std::string lower(input.substr(0, 8));
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return std::tolower(c); });

    std::string_view rest;

    if (lower.starts_with("https://")) {
        url.tls = true;
        rest = input.substr(8);
    } else if (lower.starts_with("http://")) {
        rest = input.substr(7);
    } else {
        throw herr("URL must start with https:// or http://");
    }

    auto authorityEnd = rest.find_first_of("/?#");
    auto authority = rest.substr(0, authorityEnd);
    std::string_view target = authorityEnd == std::string_view::npos ? "" : rest.substr(authorityEnd);
    target = target.substr(0, target.find('#'));

    if (authority.find('@') != std::string_view::npos) throw herr("URL must not contain credentials");

    std::string_view portStr;

    if (authority.starts_with('[')) {
        auto close = authority.find(']');
        if (close == std::string_view::npos) throw herr("bad IPv6 address in URL");
        url.host = authority.substr(1, close - 1);
        auto after = authority.substr(close + 1);
        if (after.size()) {
            if (after[0] != ':') throw herr("bad host in URL");
            portStr = after.substr(1);
        }

        in6_addr addr;
        if (inet_pton(AF_INET6, url.host.c_str(), &addr) != 1) throw herr("bad IPv6 address in URL");
    } else {
        auto colon = authority.find(':');
        url.host = authority.substr(0, colon);
        if (colon != std::string_view::npos) portStr = authority.substr(colon + 1);

        for (unsigned char c : url.host) {
            if (!std::isalnum(c) && c != '.' && c != '-') throw herr("bad host in URL");
        }
    }

    if (url.host.empty()) throw herr("URL has no host");
    std::transform(url.host.begin(), url.host.end(), url.host.begin(), [](unsigned char c){ return std::tolower(c); });

    if (portStr.size()) {
        if (portStr.size() > 5 || !std::all_of(portStr.begin(), portStr.end(), [](unsigned char c){ return std::isdigit(c); })) throw herr("bad port in URL");
        auto port = std::stoul(std::string(portStr));
        if (port == 0 || port > 65535) throw herr("bad port in URL");
        url.port = port;
    } else {
        url.port = url.tls ? 443 : 80;
    }

    if (target.empty()) url.target = "/";
    else if (target.starts_with('?')) url.target = "/" + std::string(target);
    else url.target = target;

    return url;
}

bool HttpUrl::hostIsIp() const {
    unsigned char buf[16];
    return inet_pton(AF_INET, host.c_str(), buf) == 1 || inet_pton(AF_INET6, host.c_str(), buf) == 1;
}

std::string HttpUrl::hostHeader() const {
    std::string output = host.find(':') == std::string::npos ? host : "[" + host + "]";
    if (port != (tls ? 443 : 80)) output += ":" + std::to_string(port);
    return output;
}



// Special-purpose ranges from the IANA registries (RFC 6890)

static bool isPublicIPv4(const uint8_t *a) {
    uint32_t ip = (uint32_t(a[0]) << 24) | (uint32_t(a[1]) << 16) | (uint32_t(a[2]) << 8) | uint32_t(a[3]);

    static const struct { uint32_t net; int bits; } blocked[] = {
        { 0x00000000, 8 }, { 0x0A000000, 8 }, { 0x64400000, 10 }, { 0x7F000000, 8 },
        { 0xA9FE0000, 16 }, { 0xAC100000, 12 }, { 0xC0000000, 24 }, { 0xC0000200, 24 },
        { 0xC0A80000, 16 }, { 0xC6120000, 15 }, { 0xC6336400, 24 }, { 0xCB007100, 24 },
        { 0xE0000000, 4 }, { 0xF0000000, 4 },
    };

    for (const auto &b : blocked) {
        if ((ip >> (32 - b.bits)) == (b.net >> (32 - b.bits))) return false;
    }

    return true;
}

static bool isPublicIPv6(const uint8_t *a) {
    static const uint8_t v4Mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
    static const uint8_t nat64[12] = { 0x00, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0 };

    if (!memcmp(a, v4Mapped, 12) || !memcmp(a, nat64, 12)) return isPublicIPv4(a + 12);
    if ((a[0] & 0xE0) != 0x20) return false; // outside global unicast
    if (a[0] == 0x20 && a[1] == 0x02) return isPublicIPv4(a + 2); // 6to4
    if (a[0] == 0x20 && a[1] == 0x01 && a[2] < 0x02) return false; // IETF protocol assignments, Teredo
    if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0D && a[3] == 0xB8) return false; // documentation

    return true;
}

static bool isPublicAddress(const sockaddr *addr) {
    if (addr->sa_family == AF_INET) return isPublicIPv4(reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in*>(addr)->sin_addr));
    if (addr->sa_family == AF_INET6) return isPublicIPv6(reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr.s6_addr);
    return false;
}

bool isPublicIp(const std::string &ip) {
    uint8_t buf[16];
    if (inet_pton(AF_INET, ip.c_str(), buf) == 1) return isPublicIPv4(buf);
    if (inet_pton(AF_INET6, ip.c_str(), buf) == 1) return isPublicIPv6(buf);
    return false;
}



namespace {

using Clock = std::chrono::steady_clock;

void waitFor(int fd, short events, Clock::time_point deadline) {
    while (1) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        if (ms <= 0) throw herr("timed out");

        pollfd p = { fd, events, 0 };
        int r = ::poll(&p, 1, (int)ms);
        if (r > 0) return;
        if (r == 0) throw herr("timed out");
        if (errno != EINTR) throw herr("poll: ", strerror(errno));
    }
}

std::string tlsError(SSL *ssl) {
    long verify = SSL_get_verify_result(ssl);
    if (verify != X509_V_OK) return X509_verify_cert_error_string(verify);

    unsigned long err = ERR_get_error();
    if (!err) return "connection closed";

    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return buf;
}

SSL_CTX *tlsContext() {
    static SSL_CTX *ctx = []{
        SSL_CTX *c = SSL_CTX_new(TLS_client_method());
        if (!c) throw herr("can't create a TLS context");
        SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);
        SSL_CTX_set_verify(c, SSL_VERIFY_PEER, nullptr);
        if (SSL_CTX_set_default_verify_paths(c) != 1) throw herr("can't load the system CA certificates");
        return c;
    }();

    return ctx;
}

struct Connection : NonCopyable {
    int fd = -1;
    SSL *ssl = nullptr;
    Clock::time_point deadline;

    Connection(Clock::time_point deadline) : deadline(deadline) {}

    ~Connection() {
        if (ssl) SSL_free(ssl);
        if (fd >= 0) ::close(fd);
    }

    void connect(const HttpUrl &url, bool allowPrivateAddresses) {
        addrinfo hints = {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo *res = nullptr;
        int err = ::getaddrinfo(url.host.c_str(), std::to_string(url.port).c_str(), &hints, &res);
        if (err) throw herr("can't resolve ", url.host, ": ", gai_strerror(err));
        std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> resGuard(res, ::freeaddrinfo);

        std::string lastError = "no address";

        // Checked on the address actually connected to, so a DNS answer can't swap in a private one later
        for (auto *ai = res; ai; ai = ai->ai_next) {
            if (!allowPrivateAddresses && !isPublicAddress(ai->ai_addr)) {
                lastError = "refusing to connect to a non-public address";
                continue;
            }

            int s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (s < 0) {
                lastError = strerror(errno);
                continue;
            }

            ::fcntl(s, F_SETFD, FD_CLOEXEC);
            ::fcntl(s, F_SETFL, ::fcntl(s, F_GETFL) | O_NONBLOCK);

            try {
                if (::connect(s, ai->ai_addr, ai->ai_addrlen) < 0 && errno != EINPROGRESS) throw herr(strerror(errno));
                waitFor(s, POLLOUT, deadline);

                int soError = 0;
                socklen_t len = sizeof(soError);
                ::getsockopt(s, SOL_SOCKET, SO_ERROR, &soError, &len);
                if (soError) throw herr(strerror(soError));
            } catch (std::exception &e) {
                ::close(s);
                lastError = e.what();
                continue;
            }

            fd = s;
            break;
        }

        if (fd < 0) throw herr("can't connect to ", url.host, ": ", lastError);

        if (url.tls) {
            ssl = SSL_new(tlsContext());
            if (!ssl) throw herr("can't create a TLS session");
            SSL_set_fd(ssl, fd);

            auto *param = SSL_get0_param(ssl);

            if (url.hostIsIp()) {
                X509_VERIFY_PARAM_set1_ip_asc(param, url.host.c_str());
            } else {
                SSL_set_tlsext_host_name(ssl, url.host.c_str());
                X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
                X509_VERIFY_PARAM_set1_host(param, url.host.c_str(), 0);
            }

            tlsCall([&]{ return SSL_connect(ssl); });
        }
    }

    // Retries a non-blocking SSL call until it completes. Returns 0 when the peer closed the connection.
    template <typename F>
    int tlsCall(F f) {
        while (1) {
            ERR_clear_error();
            int r = f();
            if (r > 0) return r;

            int e = SSL_get_error(ssl, r);
            if (e == SSL_ERROR_WANT_READ) waitFor(fd, POLLIN, deadline);
            else if (e == SSL_ERROR_WANT_WRITE) waitFor(fd, POLLOUT, deadline);
            else if (e == SSL_ERROR_ZERO_RETURN) return 0;
            else throw herr("TLS: ", tlsError(ssl));
        }
    }

    void writeAll(std::string_view data) {
        while (data.size()) {
            ssize_t n;

            if (ssl) {
                n = tlsCall([&]{ return SSL_write(ssl, data.data(), (int)data.size()); });
                if (n == 0) throw herr("connection closed while sending");
            } else {
                waitFor(fd, POLLOUT, deadline);
                n = ::write(fd, data.data(), data.size());
                if (n < 0) {
                    if (errno == EAGAIN || errno == EINTR) continue;
                    throw herr("write: ", strerror(errno));
                }
            }

            data.remove_prefix(n);
        }
    }

    size_t readSome(char *buf, size_t size) {
        if (ssl) return tlsCall([&]{ return SSL_read(ssl, buf, (int)size); });

        while (1) {
            waitFor(fd, POLLIN, deadline);
            ssize_t n = ::read(fd, buf, size);
            if (n >= 0) return n;
            if (errno != EAGAIN && errno != EINTR) throw herr("read: ", strerror(errno));
        }
    }
};

}


int httpPost(const HttpUrl &url, std::string_view contentType, std::string_view body, uint64_t timeoutSeconds, bool allowPrivateAddresses) {
    Connection conn(Clock::now() + std::chrono::seconds(timeoutSeconds));

    conn.connect(url, allowPrivateAddresses);

    std::string request = "POST " + url.target + " HTTP/1.1\r\n";
    request += "Host: " + url.hostHeader() + "\r\n";
    request += "User-Agent: strfry\r\n";
    request += "Content-Type: " + std::string(contentType) + "\r\n";
    request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    request += "Connection: close\r\n\r\n";
    request += body;

    conn.writeAll(request);

    std::string head;
    char buf[1024];

    while (head.find("\r\n") == std::string::npos) {
        if (head.size() > 8192) throw herr("response status line too long");
        size_t n = conn.readSome(buf, sizeof(buf));
        if (n == 0) throw herr("connection closed before the response");
        head.append(buf, n);
    }

    // "HTTP/1.1 200 OK"
    if (!head.starts_with("HTTP/1.") || head.size() < 12 || head[8] != ' ' ||
        !std::all_of(head.begin() + 9, head.begin() + 12, [](unsigned char c){ return std::isdigit(c); })) {
        throw herr("bad HTTP response");
    }

    return std::stoi(head.substr(9, 3));
}
