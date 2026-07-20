#include "tls.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>

namespace c2s {
namespace {

std::once_flag openssl_once;

std::string openssl_error(const std::string& prefix) {
    unsigned long code = ERR_get_error();
    if (code == 0) {
        return prefix;
    }
    char buffer[256]{};
    ERR_error_string_n(code, buffer, sizeof(buffer));
    return prefix + ": " + buffer;
}

} // namespace

bool resolve_host(const std::string& host, const std::string& port,
                  std::vector<ResolvedAddress>& addresses, std::string& error) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* results = nullptr;
    const int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &results);
    if (rc != 0) {
        error = gai_strerror(rc);
        return false;
    }
    for (addrinfo* current = results; current != nullptr; current = current->ai_next) {
        if (current->ai_addrlen > sizeof(sockaddr_storage)) {
            continue;
        }
        ResolvedAddress address;
        std::memcpy(&address.address, current->ai_addr, current->ai_addrlen);
        address.length = static_cast<socklen_t>(current->ai_addrlen);
        char host_buffer[NI_MAXHOST]{};
        if (getnameinfo(current->ai_addr, current->ai_addrlen, host_buffer, sizeof(host_buffer),
                        nullptr, 0, NI_NUMERICHOST) == 0) {
            address.numeric_ip = host_buffer;
        }
        addresses.push_back(address);
    }
    freeaddrinfo(results);
    if (addresses.empty()) {
        error = "no usable addresses";
        return false;
    }
    return true;
}

TlsClient::TlsClient() {
    std::call_once(openssl_once, [] {
        OPENSSL_init_ssl(0, nullptr);
    });
    context_ = SSL_CTX_new(TLS_client_method());
    if (context_ == nullptr) {
        return;
    }
    SSL_CTX_set_min_proto_version(context_, TLS1_2_VERSION);
    insecure_ = std::getenv("C2S_INSECURE") != nullptr;
    if (insecure_) {
        SSL_CTX_set_verify(context_, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(context_, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_default_verify_paths(context_);
    }
}

TlsClient::~TlsClient() {
    close();
    if (context_ != nullptr) {
        SSL_CTX_free(context_);
    }
}

bool TlsClient::connect_to(const std::string& hostname, const ResolvedAddress& address,
                           int timeout_ms, std::string& error) {
    close();
    if (context_ == nullptr) {
        error = "unable to create TLS context";
        return false;
    }
    fd_ = socket(address.address.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd_ < 0) {
        error = socket_error("socket");
        return false;
    }
    const int old_flags = fcntl(fd_, F_GETFL, 0);
    if (old_flags < 0 || fcntl(fd_, F_SETFL, old_flags | O_NONBLOCK) < 0) {
        error = socket_error("fcntl");
        close();
        return false;
    }
    int rc = ::connect(fd_, reinterpret_cast<const sockaddr*>(&address.address), address.length);
    if (rc < 0 && errno != EINPROGRESS) {
        error = socket_error("connect");
        close();
        return false;
    }
    if (rc < 0) {
        pollfd descriptor{};
        descriptor.fd = fd_;
        descriptor.events = POLLOUT;
        rc = poll(&descriptor, 1, timeout_ms);
        if (rc <= 0) {
            error = rc == 0 ? "connect timeout" : socket_error("poll");
            close();
            return false;
        }
        int socket_status = 0;
        socklen_t status_size = sizeof(socket_status);
        if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &socket_status, &status_size) < 0 || socket_status != 0) {
            errno = socket_status == 0 ? errno : socket_status;
            error = socket_error("connect");
            close();
            return false;
        }
    }
    fcntl(fd_, F_SETFL, old_flags);
    timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    ssl_ = SSL_new(context_);
    if (ssl_ == nullptr) {
        error = openssl_error("SSL_new");
        close();
        return false;
    }
    SSL_set_fd(ssl_, fd_);
    SSL_set_tlsext_host_name(ssl_, hostname.c_str());
    if (!insecure_ && SSL_set1_host(ssl_, hostname.c_str()) != 1) {
        error = openssl_error("SSL_set1_host");
        close();
        return false;
    }
    if (SSL_connect(ssl_) != 1) {
        error = openssl_error("TLS handshake failed");
        close();
        return false;
    }
    return true;
}

bool TlsClient::write_all(const void* data, std::size_t size, std::string& error) {
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::size_t written = 0;
    while (written < size) {
        const int chunk = static_cast<int>(std::min<std::size_t>(size - written, 1U << 20U));
        const int rc = SSL_write(ssl_, bytes + written, chunk);
        if (rc <= 0) {
            error = openssl_error("SSL_write");
            return false;
        }
        written += static_cast<std::size_t>(rc);
    }
    return true;
}

int TlsClient::read_some(void* data, std::size_t size, std::string& error) {
    const int chunk = static_cast<int>(std::min<std::size_t>(size, 1U << 20U));
    const int rc = SSL_read(ssl_, data, chunk);
    if (rc > 0) {
        return rc;
    }
    const int ssl_error_code = SSL_get_error(ssl_, rc);
    if (ssl_error_code == SSL_ERROR_ZERO_RETURN) {
        return 0;
    }
    if (ssl_error_code == SSL_ERROR_SYSCALL && rc == 0) {
        return 0;
    }
    error = openssl_error("SSL_read");
    return -1;
}

void TlsClient::close() {
    if (ssl_ != nullptr) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    close_socket(fd_);
}

} // namespace c2s
