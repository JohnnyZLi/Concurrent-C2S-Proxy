# Concurrent Clear-to-Secure Proxy

A concurrent HTTP forward proxy that accepts clear-text client requests, establishes verified TLS connections to destination servers, applies a reloadable hostname/IP blocklist, adds `X-Forwarded-For`, relays HTTP/1.1 responses, and writes structured access logs.

This project was originally completed for **CSE 156/L: Network Programming** at UC Santa Cruz in Winter 2025. The original university-hosted source was lost when the campus Unix service was retired; this repository is a reconstructed and expanded implementation based on the surviving project specification.

## Highlights

- Concurrent support for up to 50 clients using isolated worker threads
- GET and HEAD forwarding from clear-text HTTP to HTTPS
- OpenSSL TLS 1.2+ with certificate and hostname verification by default
- Absolute-form proxy requests and origin-form requests with `Host`
- Hostname and resolved-IP access-control checks
- `SIGINT` reload of the forbidden-sites file without terminating the proxy
- Active connection shutdown when a reloaded rule blocks the destination
- `X-Forwarded-For` creation and chain preservation
- HTTP error mapping: 400, 403, 501, 502, 503, and 504
- Content-Length, chunked, HEAD, and close-delimited response relay
- Downstream keep-alive when message framing permits it
- RFC 3339 access logs with client, request line, status, and byte count
- ACL and log files confined to the working directory, with traversal and symlink rejection
- Regular-file enforcement, a 1 MiB ACL limit, and owner-only access-log permissions

## Dependencies

- C++17 compiler
- OpenSSL development headers and libraries
- POSIX sockets and threads

On Debian/Ubuntu:

```sh
sudo apt-get install build-essential libssl-dev
```

## Build

```sh
make
```

## Usage

```sh
./bin/myproxy -p LISTEN_PORT -a FORBIDDEN_SITES_FILENAME -l ACCESS_LOG_FILENAME
```

The ACL and log arguments must each be a single filename in the process working directory. Absolute paths, directory separators, parent-directory references, symbolic links, and non-regular files are rejected. To store runtime files elsewhere, change into that directory before launching the binary by its absolute path.

Example:

```sh
mkdir -p runtime
printf 'example.org\n203.0.113.9\n' > runtime/forbidden.txt
cd runtime
/path/to/Concurrent-C2S-Proxy/bin/myproxy -p 9090 -a forbidden.txt -l access.log
curl -x http://127.0.0.1:9090 http://example.com/
```

The client sends clear-text HTTP to the proxy. The proxy connects to the requested host using HTTPS, defaulting to port 443 unless the request URL supplies another port.

Send `Control-C` (`SIGINT`) to reload the forbidden-sites file. The process remains running.

## Test

```sh
make test
```

The integration suite creates a local TLS origin and verifies GET, HEAD, `X-Forwarded-For`, unsupported methods, concurrency, ACL reload, forbidden responses, access logging, path traversal rejection, symlink rejection, and restrictive log permissions.

For local development against a self-signed origin only, set `C2S_INSECURE=1`. Certificate verification remains enabled by default.

See [`doc/design.md`](doc/design.md) for connection management and cleanup details.
