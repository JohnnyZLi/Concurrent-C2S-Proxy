#include "acl.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <fstream>
#include <mutex>

namespace c2s {

bool AccessControlList::load(const std::string& path, std::string& error) {
    std::ifstream input(path);
    if (!input) {
        error = "cannot open forbidden-sites file: " + path;
        return false;
    }
    std::unordered_set<std::string> replacement;
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
