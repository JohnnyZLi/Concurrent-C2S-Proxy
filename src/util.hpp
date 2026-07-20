#pragma once

#include <chrono>
#include <cstddef>
#include <string>

namespace c2s {

std::string rfc3339_now();
std::string lower_copy(std::string value);
std::string trim_copy(const std::string& value);
bool send_all(int fd, const void* data, std::size_t size);
std::string socket_error(const std::string& prefix);
void close_socket(int& fd);

} // namespace c2s
