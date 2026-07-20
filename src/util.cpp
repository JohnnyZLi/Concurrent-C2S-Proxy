#include "util.hpp"

#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>

namespace c2s {

std::string rfc3339_now() {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto milliseconds_part = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    const std::time_t seconds = system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&seconds, &tm);
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << '.'
        << std::setw(3) << std::setfill('0') << milliseconds_part.count() << 'Z';
    return out.str();
}

std::string lower_copy(std::string value) {
    for (char& character : value) {
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    }
    return value;
}

std::string trim_copy(const std::string& value) {
    std::size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first])) != 0) {
        ++first;
    }
    std::size_t last = value.size();
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1])) != 0) {
        --last;
    }
    return value.substr(first, last - first);
}

bool send_all(int fd, const void* data, std::size_t size) {
    const auto* bytes = static_cast<const unsigned char*>(data);
    std::size_t sent = 0;
    while (sent < size) {
        const ssize_t result = send(fd, bytes + sent, size - sent, MSG_NOSIGNAL);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (result == 0) {
            return false;
        }
        sent += static_cast<std::size_t>(result);
    }
    return true;
}

std::string socket_error(const std::string& prefix) {
    return prefix + ": " + std::strerror(errno);
}

void close_socket(int& fd) {
    if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);
        close(fd);
        fd = -1;
    }
}

} // namespace c2s
