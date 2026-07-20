#pragma once

#include <openssl/ssl.h>
#include <sys/socket.h>

#include <cstddef>
#include <string>
#include <vector>

namespace c2s {

struct ResolvedAddress {
    sockaddr_storage address{};
    socklen_t length{0};
    std::string numeric_ip;
};

bool resolve_host(const std::string& host, const std::string& port,
                  std::vector<ResolvedAddress>& addresses, std::string& error);

class TlsClient {
public:
    TlsClient();
    ~TlsClient();
    TlsClient(const TlsClient&) = delete;
    TlsClient& operator=(const TlsClient&) = delete;

    bool connect_to(const std::string& hostname, const ResolvedAddress& address,
                    int timeout_ms, std::string& error);
    bool write_all(const void* data, std::size_t size, std::string& error);
    int read_some(void* data, std::size_t size, std::string& error);
    int fd() const { return fd_; }
    void close();

private:
    SSL_CTX* context_{nullptr};
    SSL* ssl_{nullptr};
    int fd_{-1};
    bool insecure_{false};
};

} // namespace c2s
