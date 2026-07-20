# Test cases

1. **GET through TLS origin** - verifies clear-to-secure forwarding, response body, status, and byte count.
2. **HEAD request** - verifies header-only relay without consuming a response body.
3. **Unsupported CONNECT/POST** - verifies 501 and connection closure.
4. **Forbidden hostname** - verifies 403 and access-log entry.
5. **Unresolvable hostname** - verifies 502 Bad Gateway.
6. **Resolved but unreachable destination** - verifies 504 Gateway Timeout.
7. **Concurrent clients** - sends 24 requests through a 12-worker test pool and verifies all responses.
8. **ACL reload** - changes the forbidden file, sends SIGINT, and verifies the new rule without process termination.
9. **Malformed header/request line** - verifies 400 Bad Request.
10. **X-Forwarded-For** - verifies creation of the header and preservation of an existing chain.
