#include "http.hpp"
#include "util.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include <sstream>
#include <string_view>

namespace c2s {
namespace {

bool split_head_lines(const std::string& raw, std::vector<std::string>& lines) {
    if (raw.size() < 4 || raw.substr(raw.size() - 4) != "\r\n\r\n") {
        return false;
    }
    std::size_t start = 0;
    while (start + 2 <= raw.size()) {
        const auto end = raw.find("\r\n", start);
        if (end == std::string::npos) {
            return false;
        }
        if (end == start) {
            break;
        }
        lines.push_back(raw.substr(start, end - start));
        start = end + 2;
    }
    return !lines.empty();
}

bool parse_headers(const std::vector<std::string>& lines, Headers& headers) {
    for (std::size_t index = 1; index < lines.size(); ++index) {
        const std::string& line = lines[index];
        if (line.empty() || line.front() == ' ' || line.front() == '\t') {
            return false;
        }
        const auto colon = line.find(':');
        if (colon == std::string::npos || colon == 0) {
            return false;
        }
        const std::string name = trim_copy(line.substr(0, colon));
        const std::string value = trim_copy(line.substr(colon + 1));
        if (name.empty()) {
            return false;
        }
        headers.emplace_back(name, value);
    }
    return true;
}

bool parse_authority(const std::string& authority, std::string& host, std::string& port) {
    if (authority.empty()) {
        return false;
    }
    if (authority.front() == '[') {
        const auto closing = authority.find(']');
        if (closing == std::string::npos) {
            return false;
        }
        host = authority.substr(1, closing - 1);
        if (closing + 1 < authority.size()) {
            if (authority[closing + 1] != ':' || closing + 2 >= authority.size()) {
                return false;
            }
            port = authority.substr(closing + 2);
        }
        return !host.empty();
    }
    const auto first_colon = authority.find(':');
    const auto last_colon = authority.rfind(':');
    if (first_colon != std::string::npos && first_colon == last_colon) {
        host = authority.substr(0, first_colon);
        port = authority.substr(first_colon + 1);
        return !host.empty() && !port.empty();
    }
    host = authority;
    return !host.empty();
}

bool valid_port(const std::string& port) {
    if (port.empty()) {
        return false;
    }
    unsigned long value = 0;
    for (char character : port) {
        if (!std::isdigit(static_cast<unsigned char>(character))) {
            return false;
        }
        value = value * 10UL + static_cast<unsigned long>(character - '0');
        if (value > 65535UL) {
            return false;
        }
    }
    return value > 0;
}

bool parse_request_target(HttpRequest& request) {
    const std::string lower_target = lower_copy(request.target);
    if (lower_target.rfind("http://", 0) == 0 || lower_target.rfind("https://", 0) == 0) {
        const std::size_t scheme_length = lower_target.rfind("http://", 0) == 0 ? 7U : 8U;
        const auto delimiter = request.target.find_first_of("/?#", scheme_length);
        const std::string authority = delimiter == std::string::npos
            ? request.target.substr(scheme_length)
            : request.target.substr(scheme_length, delimiter - scheme_length);
        if (authority.find('@') != std::string::npos) {
            return false;
        }
        if (delimiter == std::string::npos) {
            request.origin_target = "/";
        } else if (request.target[delimiter] == '/') {
            request.origin_target = request.target.substr(delimiter);
        } else {
            request.origin_target = "/" + request.target.substr(delimiter);
        }
        if (!parse_authority(authority, request.host, request.port)) {
            return false;
        }
    } else if (!request.target.empty() && request.target.front() == '/') {
        request.origin_target = request.target;
        const auto host_header = header_value(request.headers, "host");
        if (!host_header.has_value() || !parse_authority(host_header.value(), request.host, request.port)) {
            return false;
        }
    } else {
        return false;
    }
    request.host = lower_copy(request.host);
    return valid_port(request.port);
}

bool parse_content_length_value(const std::string& text, std::size_t& value) {
    const std::string trimmed = trim_copy(text);
    if (trimmed.empty()) {
        return false;
    }
    unsigned long long parsed = 0;
    const auto result = std::from_chars(trimmed.data(), trimmed.data() + trimmed.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != trimmed.data() + trimmed.size() ||
        parsed > std::numeric_limits<std::size_t>::max()) {
        return false;
    }
    value = static_cast<std::size_t>(parsed);
    return true;
}

std::string canonical_host_header(const HttpRequest& request) {
    const bool ipv6 = request.host.find(':') != std::string::npos;
    const std::string host = ipv6 ? "[" + request.host + "]" : request.host;
    return request.port == "443" ? host : host + ":" + request.port;
}

} // namespace

std::optional<std::string> header_value(const Headers& headers, const std::string& name) {
    const std::string wanted = lower_copy(name);
    for (const auto& [header_name, value] : headers) {
        if (lower_copy(header_name) == wanted) {
            return value;
        }
    }
    return std::nullopt;
}

RequestParseResult parse_request_head(const std::string& raw) {
    RequestParseResult result;
    std::vector<std::string> lines;
    if (!split_head_lines(raw, lines)) {
        return result;
    }

    std::istringstream request_line(lines.front());
    if (!(request_line >> result.request.method >> result.request.target >> result.request.version)) {
        return result;
    }
    std::string extra;
    if (request_line >> extra) {
        return result;
    }
    result.request.request_line = lines.front();
    if (result.request.version != "HTTP/1.1" && result.request.version != "HTTP/1.0") {
        return result;
    }
    if (!parse_headers(lines, result.request.headers)) {
        return result;
    }
    std::vector<std::string> host_values;
    for (const auto& [name, value] : result.request.headers) {
        if (lower_copy(name) == "host") {
            host_values.push_back(trim_copy(value));
        }
    }
    if (host_values.size() != 1 || host_values.front().empty()) {
        return result;
    }

    if (result.request.method != "GET" && result.request.method != "HEAD") {
        result.error_status = 501;
        result.error_reason = "Not Implemented";
        return result;
    }
    if (!parse_request_target(result.request)) {
        return result;
    }
    std::string host_header_host;
    std::string host_header_port = "443";
    if (!parse_authority(host_values.front(), host_header_host, host_header_port) ||
        lower_copy(host_header_host) != result.request.host || host_header_port != result.request.port) {
        return result;
    }

    std::optional<std::size_t> content_length;
    for (const auto& [name, value] : result.request.headers) {
        if (lower_copy(name) == "content-length") {
            std::size_t parsed = 0;
            if (!parse_content_length_value(value, parsed)) {
                return result;
            }
            if (content_length.has_value() && content_length.value() != parsed) {
                return result;
            }
            content_length = parsed;
        }
    }
    if (content_length.value_or(0) != 0) {
        return result;
    }

    const auto connection = header_value(result.request.headers, "connection");
    const auto proxy_connection = header_value(result.request.headers, "proxy-connection");
    const std::string connection_value = lower_copy(connection.value_or(proxy_connection.value_or("")));
    result.request.keep_alive = result.request.version == "HTTP/1.1";
    if (connection_value.find("close") != std::string::npos) {
        result.request.keep_alive = false;
    } else if (connection_value.find("keep-alive") != std::string::npos) {
        result.request.keep_alive = true;
    }

    result.ok = true;
    return result;
}

bool parse_response_head(const std::string& raw, bool head_request,
                         HttpResponseHead& response, std::string& error) {
    std::vector<std::string> lines;
    if (!split_head_lines(raw, lines)) {
        error = "malformed upstream response head";
        return false;
    }
    std::istringstream status_line(lines.front());
    if (!(status_line >> response.version >> response.status)) {
        error = "malformed upstream status line";
        return false;
    }
    std::getline(status_line, response.reason);
    response.reason = trim_copy(response.reason);
    response.status_line = lines.front();
    if (response.version.rfind("HTTP/", 0) != 0 || response.status < 100 || response.status > 599) {
        error = "invalid upstream status line";
        return false;
    }
    if (!parse_headers(lines, response.headers)) {
        error = "malformed upstream response headers";
        return false;
    }

    for (const auto& [name, value] : response.headers) {
        const std::string lower_name = lower_copy(name);
        if (lower_name == "content-length") {
            std::size_t parsed = 0;
            if (!parse_content_length_value(value, parsed)) {
                error = "invalid upstream Content-Length";
                return false;
            }
            if (response.content_length.has_value() && response.content_length.value() != parsed) {
                error = "conflicting upstream Content-Length headers";
                return false;
            }
            response.content_length = parsed;
        } else if (lower_name == "transfer-encoding" &&
                   lower_copy(value).find("chunked") != std::string::npos) {
            response.chunked = true;
        }
    }
    if (response.chunked) {
        response.content_length.reset();
    }
    response.no_body = head_request || (response.status >= 100 && response.status < 200) ||
                       response.status == 204 || response.status == 304;
    return true;
}

std::string build_upstream_request(const HttpRequest& request, const std::string& client_ip) {
    std::ostringstream out;
    out << request.method << ' ' << request.origin_target << ' ' << request.version << "\r\n";
    bool had_xff = false;
    for (const auto& [name, value] : request.headers) {
        const std::string lower_name = lower_copy(name);
        if (lower_name == "host" || lower_name == "connection" ||
            lower_name == "proxy-connection" || lower_name == "proxy-authorization") {
            continue;
        }
        if (lower_name == "x-forwarded-for") {
            out << "X-Forwarded-For: " << value << ", " << client_ip << "\r\n";
            had_xff = true;
            continue;
        }
        out << name << ": " << value << "\r\n";
    }
    out << "Host: " << canonical_host_header(request) << "\r\n";
    if (!had_xff) {
        out << "X-Forwarded-For: " << client_ip << "\r\n";
    }
    out << "Connection: close\r\n\r\n";
    return out.str();
}

std::string build_downstream_response_head(const HttpResponseHead& response, bool keep_alive) {
    std::ostringstream out;
    out << response.status_line << "\r\n";
    for (const auto& [name, value] : response.headers) {
        const std::string lower_name = lower_copy(name);
        if (lower_name == "connection" || lower_name == "proxy-connection" ||
            lower_name == "keep-alive") {
            continue;
        }
        out << name << ": " << value << "\r\n";
    }
    out << "Connection: " << (keep_alive ? "keep-alive" : "close") << "\r\n\r\n";
    return out.str();
}

std::string make_error_response(int status, const std::string& reason, const std::string& detail) {
    const std::string body = std::to_string(status) + " " + reason + "\n" + detail + "\n";
    std::ostringstream out;
    out << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
        << "Content-Type: text/plain; charset=utf-8\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    return out.str();
}

} // namespace c2s
