#include "acl.hpp"
#include "http.hpp"
#include "tls.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr std::size_t kMaxHeaderBytes = 64U * 1024U;
constexpr int kIoTimeoutMs = 30000;
constexpr int kConnectTimeoutMs = 10000;
constexpr int kMaximumClients = 50;

int signal_write_fd = -1;

extern "C" void sigint_handler(int) {
    if (signal_write_fd >= 0) {
        const unsigned char byte = 1;
        const ssize_t ignored = write(signal_write_fd, &byte, sizeof(byte));
        (void) ignored;
    }
}

struct ActiveConnection {
    std::string host;
    std::string ip;
    int client_fd{-1};
    int upstream_fd{-1};
};

class ActiveRegistry {
public:
    std::uint64_t add(const ActiveConnection& connection) {
        std::lock_guard lock(mutex_);
        const auto id = next_id_++;
        connections_[id] = connection;
        return id;
    }

    void update_upstream(std::uint64_t id, int upstream_fd, const std::string& ip) {
        std::lock_guard lock(mutex_);
        auto it = connections_.find(id);
        if (it != connections_.end()) {
            it->second.upstream_fd = upstream_fd;
            it->second.ip = ip;
        }
    }

    void remove(std::uint64_t id) {
        std::lock_guard lock(mutex_);
        connections_.erase(id);
    }

    void close_blocked(const c2s::AccessControlList& acl) {
        std::lock_guard lock(mutex_);
        for (auto& [id, connection] : connections_) {
            (void) id;
            if (acl.blocked(connection.host) || (!connection.ip.empty() && acl.blocked(connection.ip))) {
                if (connection.upstream_fd >= 0) {
                    shutdown(connection.upstream_fd, SHUT_RDWR);
                }
                if (connection.client_fd >= 0) {
                    shutdown(connection.client_fd, SHUT_RDWR);
                }
            }
        }
    }

private:
    std::mutex mutex_;
    std::map<std::uint64_t, ActiveConnection> connections_;
    std::uint64_t next_id_{1};
};

bool write_all_file(int fd, const char* data, std::size_t size) {
    std::size_t offset = 0;
    while (offset < size) {
        const ssize_t count = ::write(fd, data + offset, size - offset);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    return true;
}

class AccessLogger {
public:
    explicit AccessLogger(std::string path) : path_(std::move(path)) {}
    ~AccessLogger() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }
    AccessLogger(const AccessLogger&) = delete;
    AccessLogger& operator=(const AccessLogger&) = delete;

    bool verify(std::string& error) {
        fd_ = ::open(path_.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd_ < 0) {
            error = "cannot open access log: " + path_ + ": " + std::strerror(errno);
            return false;
        }
        struct stat metadata{};
        if (::fstat(fd_, &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
            error = "access log must be a regular file: " + path_;
            ::close(fd_);
            fd_ = -1;
            return false;
        }
        return true;
    }

    void write(const std::string& client_ip, const std::string& request_line,
               int status, std::size_t response_size) {
        std::ostringstream line;
        line << c2s::rfc3339_now() << ' ' << client_ip << " \"" << request_line
             << "\" " << status << ' ' << response_size << '\n';
        const std::string entry = line.str();
        std::lock_guard lock(mutex_);
        if (fd_ < 0 || !write_all_file(fd_, entry.data(), entry.size())) {
            std::cerr << "Cannot append to access log " << path_ << '\n';
        }
    }

private:
    std::string path_;
    int fd_{-1};
    std::mutex mutex_;
};

class RegistryGuard {
public:
    RegistryGuard(ActiveRegistry& registry, std::uint64_t id) : registry_(registry), id_(id) {}
    ~RegistryGuard() { registry_.remove(id_); }
    RegistryGuard(const RegistryGuard&) = delete;
    RegistryGuard& operator=(const RegistryGuard&) = delete;
private:
    ActiveRegistry& registry_;
    std::uint64_t id_;
};

bool parse_arguments(int argc, char** argv, std::string& port, std::string& acl_path,
                     std::string& log_path) {
    if (argc != 7) {
        return false;
    }
    for (int index = 1; index < argc; index += 2) {
        const std::string option = argv[index];
        const char* raw_value = argv[index + 1];
        if (raw_value == nullptr || *raw_value == '\0') {
            return false;
        }
        if (option == "-p") {
            port = raw_value;
        } else if (option == "-a") {
            if (std::strstr(raw_value, "..") != nullptr ||
                std::strchr(raw_value, '/') != nullptr ||
                std::strchr(raw_value, '\\') != nullptr) {
                return false;
            }
            acl_path = raw_value;
        } else if (option == "-l") {
            if (std::strstr(raw_value, "..") != nullptr ||
                std::strchr(raw_value, '/') != nullptr ||
                std::strchr(raw_value, '\\') != nullptr) {
                return false;
            }
            log_path = raw_value;
        } else {
            return false;
        }
    }
    if (port.empty() || acl_path.empty() || log_path.empty()) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const long parsed = std::strtol(port.c_str(), &end, 10);
    return errno == 0 && end != port.c_str() && *end == '\0' && parsed > 0 && parsed <= 65535;
}

int create_listener(const std::string& port, std::string& error) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    addrinfo* results = nullptr;
    const int rc = getaddrinfo(nullptr, port.c_str(), &hints, &results);
    if (rc != 0) {
        error = gai_strerror(rc);
        return -1;
    }
    int listener = -1;
    for (addrinfo* current = results; current != nullptr; current = current->ai_next) {
        listener = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (listener < 0) {
            continue;
        }
        int yes = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(listener, current->ai_addr, current->ai_addrlen) == 0 &&
            listen(listener, kMaximumClients) == 0) {
            break;
        }
        c2s::close_socket(listener);
    }
    freeaddrinfo(results);
    if (listener < 0) {
        error = c2s::socket_error("unable to create listening socket");
    }
    return listener;
}

std::string numeric_client_ip(const sockaddr_storage& address, socklen_t length) {
    char host[NI_MAXHOST]{};
    if (getnameinfo(reinterpret_cast<const sockaddr*>(&address), length,
                    host, sizeof(host), nullptr, 0, NI_NUMERICHOST) != 0) {
        return "unknown";
    }
    return host;
}

enum class ReadHeadStatus { Ok, Closed, Error, TooLarge };

ReadHeadStatus read_client_head(int fd, std::string& buffer, std::string& head) {
    while (true) {
        const auto marker = buffer.find("\r\n\r\n");
        if (marker != std::string::npos) {
            head = buffer.substr(0, marker + 4);
            buffer.erase(0, marker + 4);
            return ReadHeadStatus::Ok;
        }
        if (buffer.size() >= kMaxHeaderBytes) {
            return ReadHeadStatus::TooLarge;
        }
        pollfd descriptor{};
        descriptor.fd = fd;
        descriptor.events = POLLIN;
        const int rc = poll(&descriptor, 1, kIoTimeoutMs);
        if (rc == 0) {
            return ReadHeadStatus::Error;
        }
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return ReadHeadStatus::Error;
        }
        if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 &&
            (descriptor.revents & POLLIN) == 0) {
            return ReadHeadStatus::Closed;
        }
        char chunk[8192];
        const ssize_t count = recv(fd, chunk, sizeof(chunk), 0);
        if (count == 0) {
            return ReadHeadStatus::Closed;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return ReadHeadStatus::Error;
        }
        buffer.append(chunk, static_cast<std::size_t>(count));
    }
}

bool read_tls_head(c2s::TlsClient& tls, std::string& head, std::string& remainder,
                   std::string& error) {
    std::string buffer;
    char chunk[8192];
    while (buffer.size() < kMaxHeaderBytes) {
        const auto marker = buffer.find("\r\n\r\n");
        if (marker != std::string::npos) {
            head = buffer.substr(0, marker + 4);
            remainder = buffer.substr(marker + 4);
            return true;
        }
        const int count = tls.read_some(chunk, sizeof(chunk), error);
        if (count <= 0) {
            if (count == 0 && error.empty()) {
                error = "upstream closed before completing response headers";
            }
            return false;
        }
        buffer.append(chunk, static_cast<std::size_t>(count));
    }
    error = "upstream response headers exceed 64 KiB";
    return false;
}

class TlsBufferedReader {
public:
    TlsBufferedReader(c2s::TlsClient& tls, std::string initial)
        : tls_(tls), buffer_(std::move(initial)) {}

    bool read_exact(std::size_t count, std::string& output, std::string& error) {
        while (buffer_.size() < count) {
            if (!fill(error)) {
                return false;
            }
        }
        output.assign(buffer_.data(), count);
        buffer_.erase(0, count);
        return true;
    }

    bool read_line(std::string& output, std::string& error) {
        while (true) {
            const auto marker = buffer_.find("\r\n");
            if (marker != std::string::npos) {
                output = buffer_.substr(0, marker + 2);
                buffer_.erase(0, marker + 2);
                return true;
            }
            if (buffer_.size() > 8192) {
                error = "chunk line exceeds 8 KiB";
                return false;
            }
            if (!fill(error)) {
                return false;
            }
        }
    }

    std::string take_buffer() {
        std::string output;
        output.swap(buffer_);
        return output;
    }

    int read_some(char* output, std::size_t capacity, std::string& error) {
        if (!buffer_.empty()) {
            const std::size_t count = std::min(capacity, buffer_.size());
            std::memcpy(output, buffer_.data(), count);
            buffer_.erase(0, count);
            return static_cast<int>(count);
        }
        return tls_.read_some(output, capacity, error);
    }

private:
    bool fill(std::string& error) {
        char chunk[8192];
        const int count = tls_.read_some(chunk, sizeof(chunk), error);
        if (count <= 0) {
            if (count == 0 && error.empty()) {
                error = "upstream closed before response body completed";
            }
            return false;
        }
        buffer_.append(chunk, static_cast<std::size_t>(count));
        return true;
    }

    c2s::TlsClient& tls_;
    std::string buffer_;
};

bool send_counted(int client_fd, const std::string& data, std::size_t& total) {
    if (!c2s::send_all(client_fd, data.data(), data.size())) {
        return false;
    }
    total += data.size();
    return true;
}

bool relay_content_length(int client_fd, TlsBufferedReader& reader, std::size_t length,
                          std::size_t& total, std::string& error) {
    std::size_t remaining = length;
    while (remaining > 0) {
        const std::size_t wanted = std::min<std::size_t>(remaining, 16384);
        std::string chunk;
        if (!reader.read_exact(wanted, chunk, error)) {
            return false;
        }
        if (!send_counted(client_fd, chunk, total)) {
            error = "client closed while receiving response";
            return false;
        }
        remaining -= wanted;
    }
    return true;
}

bool relay_chunked(int client_fd, TlsBufferedReader& reader,
                   std::size_t& total, std::string& error) {
    while (true) {
        std::string size_line;
        if (!reader.read_line(size_line, error)) {
            return false;
        }
        if (!send_counted(client_fd, size_line, total)) {
            error = "client closed while receiving chunk header";
            return false;
        }
        const std::string size_text = c2s::trim_copy(size_line.substr(0, size_line.size() - 2));
        const auto semicolon = size_text.find(';');
        const std::string number = size_text.substr(0, semicolon);
        if (number.empty()) {
            error = "empty chunk size";
            return false;
        }
        std::size_t chunk_size = 0;
        std::istringstream parser(number);
        parser >> std::hex >> chunk_size;
        if (!parser || !parser.eof()) {
            error = "invalid chunk size";
            return false;
        }
        if (chunk_size == 0) {
            while (true) {
                std::string trailer;
                if (!reader.read_line(trailer, error)) {
                    return false;
                }
                if (!send_counted(client_fd, trailer, total)) {
                    error = "client closed while receiving trailers";
                    return false;
                }
                if (trailer == "\r\n") {
                    return true;
                }
            }
        }
        std::string chunk;
        if (!reader.read_exact(chunk_size + 2, chunk, error)) {
            return false;
        }
        if (chunk.size() < 2 || chunk.substr(chunk.size() - 2) != "\r\n") {
            error = "chunk payload missing CRLF";
            return false;
        }
        if (!send_counted(client_fd, chunk, total)) {
            error = "client closed while receiving chunk data";
            return false;
        }
    }
}

bool relay_until_close(int client_fd, TlsBufferedReader& reader,
                       std::size_t& total, std::string& error) {
    char chunk[16384];
    while (true) {
        const int count = reader.read_some(chunk, sizeof(chunk), error);
        if (count == 0) {
            return true;
        }
        if (count < 0) {
            return false;
        }
        if (!c2s::send_all(client_fd, chunk, static_cast<std::size_t>(count))) {
            error = "client closed while receiving close-delimited response";
            return false;
        }
        total += static_cast<std::size_t>(count);
    }
}

void send_and_log_error(int client_fd, AccessLogger& logger, const std::string& client_ip,
                        const std::string& request_line, int status,
                        const std::string& reason, const std::string& detail) {
    const std::string response = c2s::make_error_response(status, reason, detail);
    std::size_t sent = 0;
    if (c2s::send_all(client_fd, response.data(), response.size())) {
        sent = response.size();
    }
    logger.write(client_ip, request_line, status, sent);
}

void handle_client(int client_fd, std::string client_ip,
                   c2s::AccessControlList& acl, AccessLogger& logger,
                   ActiveRegistry& registry, std::atomic<int>& client_count) {
    struct CountGuard {
        std::atomic<int>& count;
        ~CountGuard() { --count; }
    } count_guard{client_count};

    timeval timeout{};
    timeout.tv_sec = kIoTimeoutMs / 1000;
    timeout.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    std::string client_buffer;
    while (true) {
        std::string raw_head;
        const ReadHeadStatus read_status = read_client_head(client_fd, client_buffer, raw_head);
        if (read_status == ReadHeadStatus::Closed) {
            break;
        }
        if (read_status == ReadHeadStatus::TooLarge) {
            send_and_log_error(client_fd, logger, client_ip, "-", 400, "Bad Request",
                               "Request headers exceed 64 KiB");
            break;
        }
        if (read_status != ReadHeadStatus::Ok) {
            break;
        }

        const c2s::RequestParseResult parsed = c2s::parse_request_head(raw_head);
        if (!parsed.ok) {
            std::string request_line = raw_head.substr(0, raw_head.find("\r\n"));
            if (request_line.empty()) {
                request_line = "-";
            }
            send_and_log_error(client_fd, logger, client_ip, request_line,
                               parsed.error_status, parsed.error_reason,
                               parsed.error_status == 501
                                   ? "Only GET and HEAD are supported"
                                   : "Malformed or inconsistent HTTP request");
            break;
        }
        const c2s::HttpRequest& request = parsed.request;

        if (acl.blocked(request.host)) {
            send_and_log_error(client_fd, logger, client_ip, request.request_line,
                               403, "Forbidden", "Destination is blocked by the access-control list");
            break;
        }

        std::vector<c2s::ResolvedAddress> addresses;
        std::string error;
        if (!c2s::resolve_host(request.host, request.port, addresses, error)) {
            send_and_log_error(client_fd, logger, client_ip, request.request_line,
                               502, "Bad Gateway", "Unable to resolve destination host");
            break;
        }
        addresses.erase(std::remove_if(addresses.begin(), addresses.end(),
                                       [&](const c2s::ResolvedAddress& address) {
                                           return acl.blocked(address.numeric_ip);
                                       }),
                        addresses.end());
        if (addresses.empty()) {
            send_and_log_error(client_fd, logger, client_ip, request.request_line,
                               403, "Forbidden", "Destination IP is blocked by the access-control list");
            break;
        }

        const std::uint64_t registry_id = registry.add({request.host, "", client_fd, -1});
        c2s::TlsClient tls;
        RegistryGuard registry_guard(registry, registry_id);
        bool connected = false;
        bool tls_failure = false;
        std::string selected_ip;
        for (const auto& address : addresses) {
            if (tls.connect_to(request.host, address, kConnectTimeoutMs, error)) {
                connected = true;
                selected_ip = address.numeric_ip;
                registry.update_upstream(registry_id, tls.fd(), selected_ip);
                break;
            }
            if (error.find("TLS handshake failed") != std::string::npos ||
                error.find("SSL_set1_host") != std::string::npos) {
                tls_failure = true;
            }
        }
        if (!connected) {
            send_and_log_error(client_fd, logger, client_ip, request.request_line,
                               tls_failure ? 502 : 504,
                               tls_failure ? "Bad Gateway" : "Gateway Timeout",
                               tls_failure ? "Destination TLS verification or handshake failed"
                                           : "Unable to connect to destination");
            break;
        }
        if (acl.blocked(request.host) || acl.blocked(selected_ip)) {
            send_and_log_error(client_fd, logger, client_ip, request.request_line,
                               403, "Forbidden", "Destination became blocked during connection setup");
            break;
        }

        const std::string upstream_request = c2s::build_upstream_request(request, client_ip);
        if (!tls.write_all(upstream_request.data(), upstream_request.size(), error)) {
            send_and_log_error(client_fd, logger, client_ip, request.request_line,
                               502, "Bad Gateway", "Failed while sending request to destination");
            break;
        }

        std::string response_head_raw;
        std::string response_remainder;
        if (!read_tls_head(tls, response_head_raw, response_remainder, error)) {
            send_and_log_error(client_fd, logger, client_ip, request.request_line,
                               502, "Bad Gateway", "Destination returned an invalid or incomplete response");
            break;
        }
        c2s::HttpResponseHead response;
        if (!c2s::parse_response_head(response_head_raw, request.method == "HEAD", response, error)) {
            send_and_log_error(client_fd, logger, client_ip, request.request_line,
                               502, "Bad Gateway", "Destination returned malformed HTTP headers");
            break;
        }

        const bool framed = response.no_body || response.content_length.has_value() || response.chunked;
        const bool keep_alive = request.keep_alive && framed;
        const std::string downstream_head = c2s::build_downstream_response_head(response, keep_alive);
        std::size_t response_size = 0;
        bool relay_ok = send_counted(client_fd, downstream_head, response_size);
        TlsBufferedReader reader(tls, std::move(response_remainder));
        if (relay_ok && !response.no_body) {
            if (response.chunked) {
                relay_ok = relay_chunked(client_fd, reader, response_size, error);
            } else if (response.content_length.has_value()) {
                relay_ok = relay_content_length(client_fd, reader, response.content_length.value(),
                                                response_size, error);
            } else {
                relay_ok = relay_until_close(client_fd, reader, response_size, error);
            }
        }
        logger.write(client_ip, request.request_line, response.status, response_size);
        if (!relay_ok || !keep_alive) {
            break;
        }
    }
    c2s::close_socket(client_fd);
}

} // namespace

int main(int argc, char** argv) {
    std::string port;
    std::string acl_path;
    std::string log_path;
    if (!parse_arguments(argc, argv, port, acl_path, log_path)) {
        std::cerr << "Usage: myproxy -p listen_port -a forbidden_sites_filename -l access_log_filename\n"
                  << "ACL and log names must be single files in the current working directory.\n";
        return 2;
    }

    c2s::AccessControlList acl;
    std::string error;
    if (!acl.load(acl_path, error)) {
        std::cerr << error << '\n';
        return 2;
    }
    AccessLogger logger(log_path);
    if (!logger.verify(error)) {
        std::cerr << error << '\n';
        return 2;
    }

    int listener = create_listener(port, error);
    if (listener < 0) {
        std::cerr << error << '\n';
        return 2;
    }

    int signal_pipe[2]{};
    if (pipe(signal_pipe) < 0) {
        std::cerr << c2s::socket_error("pipe") << '\n';
        c2s::close_socket(listener);
        return 2;
    }
    const int read_flags = fcntl(signal_pipe[0], F_GETFL, 0);
    const int write_flags = fcntl(signal_pipe[1], F_GETFL, 0);
    if (read_flags >= 0) {
        fcntl(signal_pipe[0], F_SETFL, read_flags | O_NONBLOCK);
    }
    if (write_flags >= 0) {
        fcntl(signal_pipe[1], F_SETFL, write_flags | O_NONBLOCK);
    }
    signal_write_fd = signal_pipe[1];
    struct sigaction action{};
    action.sa_handler = sigint_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    sigaction(SIGINT, &action, nullptr);
    signal(SIGPIPE, SIG_IGN);

    ActiveRegistry registry;
    std::atomic<int> client_count{0};
    std::cout << "C2S proxy listening on port " << port << " with " << acl.size()
              << " forbidden entries\n";

    while (true) {
        pollfd descriptors[2]{};
        descriptors[0].fd = listener;
        descriptors[0].events = POLLIN;
        descriptors[1].fd = signal_pipe[0];
        descriptors[1].events = POLLIN;
        const int rc = poll(descriptors, 2, -1);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << c2s::socket_error("poll") << '\n';
            break;
        }

        if ((descriptors[1].revents & POLLIN) != 0) {
            unsigned char buffer[64];
            while (read(signal_pipe[0], buffer, sizeof(buffer)) > 0) {
            }
            std::string reload_error;
            if (acl.load(acl_path, reload_error)) {
                registry.close_blocked(acl);
                std::cout << "Reloaded forbidden-sites file: " << acl.size() << " entries\n";
            } else {
                std::cerr << "ACL reload failed; retaining previous entries: " << reload_error << '\n';
            }
        }

        if ((descriptors[0].revents & POLLIN) != 0) {
            sockaddr_storage client_address{};
            socklen_t client_length = sizeof(client_address);
            int client_fd = accept(listener, reinterpret_cast<sockaddr*>(&client_address), &client_length);
            if (client_fd < 0) {
                if (errno != EINTR) {
                    std::cerr << c2s::socket_error("accept") << '\n';
                }
                continue;
            }
            if (client_count.load() >= kMaximumClients) {
                const std::string response = c2s::make_error_response(
                    503, "Service Unavailable", "Maximum concurrent client limit reached");
                c2s::send_all(client_fd, response.data(), response.size());
                c2s::close_socket(client_fd);
                continue;
            }
            ++client_count;
            const std::string client_ip = numeric_client_ip(client_address, client_length);
            std::thread(handle_client, client_fd, client_ip,
                        std::ref(acl), std::ref(logger), std::ref(registry),
                        std::ref(client_count)).detach();
        }
    }

    c2s::close_socket(listener);
    close(signal_pipe[0]);
    close(signal_pipe[1]);
    return 2;
}
