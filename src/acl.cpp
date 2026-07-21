#include "acl.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <mutex>
#include <sstream>

namespace c2s {

bool AccessControlList::load(const std::string& path, std::string& error) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        error = "cannot open forbidden-sites file: " + path + ": " + std::strerror(errno);
        return false;
    }

    struct stat metadata{};
    if (::fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
        error = "forbidden-sites file must be a regular file: " + path;
        ::close(fd);
        return false;
    }

    constexpr std::size_t kMaximumAclBytes = 1024U * 1024U;
    std::string contents;
    if (metadata.st_size > 0) {
        const auto size = static_cast<std::uintmax_t>(metadata.st_size);
        if (size > kMaximumAclBytes) {
            error = "forbidden-sites file exceeds 1 MiB";
            ::close(fd);
            return false;
        }
        contents.reserve(static_cast<std::size_t>(size));
    }

    char buffer[8192];
    while (true) {
        const ssize_t count = ::read(fd, buffer, sizeof(buffer));
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            error = "cannot read forbidden-sites file: " + path + ": " + std::strerror(errno);
            ::close(fd);
            return false;
        }
        const auto amount = static_cast<std::size_t>(count);
        if (contents.size() > kMaximumAclBytes - amount) {
            error = "forbidden-sites file exceeds 1 MiB";
            ::close(fd);
            return false;
        }
        contents.append(buffer, amount);
    }
    ::close(fd);

    std::unordered_set<std::string> replacement;
    std::istringstream input(contents);
    std::string line;
    while (std::getline(input, line)) {
        const auto comment = line.find('#');
        if (comment != std::string::npos) {
            line.erase(comment);
        }
        line = lower_copy(trim_copy(line));
        while (!line.empty() && line.back() == '.') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        if (replacement.size() >= 1000) {
            error = "forbidden-sites file contains more than 1000 entries";
            return false;
        }
        replacement.insert(line);
    }
    {
        std::unique_lock lock(mutex_);
        entries_.swap(replacement);
    }
    return true;
}

bool AccessControlList::blocked(const std::string& host_or_ip) const {
    std::string candidate = lower_copy(trim_copy(host_or_ip));
    while (!candidate.empty() && candidate.back() == '.') {
        candidate.pop_back();
    }
    std::shared_lock lock(mutex_);
    if (entries_.find(candidate) != entries_.end()) {
        return true;
    }
    in_addr ipv4{};
    in6_addr ipv6{};
    if (inet_pton(AF_INET, candidate.c_str(), &ipv4) == 1 ||
        inet_pton(AF_INET6, candidate.c_str(), &ipv6) == 1) {
        return false;
    }
    std::size_t dot = candidate.find('.');
    while (dot != std::string::npos) {
        const std::string suffix = candidate.substr(dot + 1);
        if (entries_.find(suffix) != entries_.end()) {
            return true;
        }
        dot = candidate.find('.', dot + 1);
    }
    return false;
}

std::size_t AccessControlList::size() const {
    std::shared_lock lock(mutex_);
    return entries_.size();
}

} // namespace c2s
