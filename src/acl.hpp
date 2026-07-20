#pragma once

#include <shared_mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace c2s {

class AccessControlList {
public:
    bool load(const std::string& path, std::string& error);
    bool blocked(const std::string& host_or_ip) const;
    std::size_t size() const;

private:
    mutable std::shared_mutex mutex_;
    std::unordered_set<std::string> entries_;
};

} // namespace c2s
