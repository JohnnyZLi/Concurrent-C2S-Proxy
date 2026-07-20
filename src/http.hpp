#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace c2s {

using Headers = std::vector<std::pair<std::string, std::string>>;

struct HttpRequest {
    std::string method;
    std::string target;
    std::string version;
    std::string request_line;
    Headers headers;
    std::string host;
    std::string port{"443"};
    std::string origin_target{"/"};
    bool keep_alive{true};
};

struct RequestParseResult {
    bool ok{false};
    int error_status{400};
    std::string error_reason{"Bad Request"};
    HttpRequest request;
};

struct HttpResponseHead {
    std::string version;
    int status{0};
    std::string reason;
    std::string status_line;
    Headers headers;
    std::optional<std::size_t> content_length;
    bool chunked{false};
    bool no_body{false};
};

RequestParseResult parse_request_head(const std::string& raw);
bool parse_response_head(const std::string& raw, bool head_request,
                         HttpResponseHead& response, std::string& error);
std::string build_upstream_request(const HttpRequest& request, const std::string& client_ip);
std::string build_downstream_response_head(const HttpResponseHead& response, bool keep_alive);
std::string make_error_response(int status, const std::string& reason, const std::string& detail);
std::optional<std::string> header_value(const Headers& headers, const std::string& name);

} // namespace c2s
