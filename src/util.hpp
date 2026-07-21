#pragma once

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstddef>
#include <string>

namespace c2s {

std::string rfc3339_now();
int open_runtime_file(const char* requested_name, int flags, mode_t mode = 0);
std::string lower_copy(std::string value);
std::string trim_copy(const std::string& value);
bool send_all(int fd, const void* data, std::size_t size);
std::string socket_error(const std::string& prefix);
void close_socket(int& fd);

} // namespace c2s

#ifndef C2S_USE_SYSTEM_OPEN
#define open(...) c2s::open_runtime_file(__VA_ARGS__)
#endif
