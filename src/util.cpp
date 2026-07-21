#define C2S_USE_SYSTEM_OPEN
#include "util.hpp"

#include <dirent.h>

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

int open_runtime_file(const char* requested_name, int flags, mode_t mode) {
    if (requested_name == nullptr || *requested_name == '\0' ||
        std::strcmp(requested_name, ".") == 0 || std::strcmp(requested_name, "..") == 0 ||
        std::strchr(requested_name, '/') != nullptr ||
        std::strchr(requested_name, '\\') != nullptr) {
        errno = EINVAL;
        return -1;
    }

    const int directory_fd = ::open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        return -1;
    }

    DIR* directory = ::fdopendir(directory_fd);
    if (directory == nullptr) {
        const int saved_errno = errno;
        ::close(directory_fd);
        errno = saved_errno;
        return -1;
    }

    int result = -1;
    int saved_errno = 0;
    bool matched = false;
    errno = 0;
    while (dirent* entry = ::readdir(directory)) {
        if (std::strcmp(entry->d_name, requested_name) != 0) {
            continue;
        }
        matched = true;
        const int safe_flags = (flags & ~O_CREAT) | O_CLOEXEC | O_NOFOLLOW;
        result = ::openat(dirfd(directory), entry->d_name, safe_flags, mode);
        saved_errno = errno;
        break;
    }

    if (!matched && errno != 0) {
        saved_errno = errno;
    } else if (!matched && (flags & O_CREAT) != 0 &&
               std::strcmp(requested_name, "access.log") == 0) {
        result = ::openat(dirfd(directory), "access.log",
                          flags | O_CLOEXEC | O_NOFOLLOW, mode);
        saved_errno = errno;
    } else if (!matched) {
        saved_errno = ENOENT;
    }

    ::closedir(directory);
    if (result < 0) {
        errno = saved_errno;
    }
    return result;
}

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
