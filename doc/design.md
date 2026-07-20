# Design and connection management

## Request path

1. The accept loop admits at most 50 concurrent clients.
2. A worker reads one complete HTTP header block, capped at 64 KiB.
3. The parser validates the request line, HTTP version, headers, method, authority, port, and body-related fields.
4. The access-control list is checked against the normalized hostname.
5. DNS resolves the destination. Resolved addresses present in the ACL are removed.
6. The proxy opens a bounded-time TCP connection and performs a TLS handshake with Server Name Indication and hostname verification.
7. The request target is converted to origin form, hop-by-hop proxy headers are removed, and `X-Forwarded-For` is added or extended.
8. The response head is parsed and rebuilt for the client. The body is streamed according to Content-Length, chunked framing, HEAD/no-body semantics, or connection close.
9. The access log records the status and exact number of bytes forwarded to the client.

## Concurrency

The listener remains in a poll loop while each accepted client is handled by a detached worker thread. Shared state is limited to:

- the access-control set, protected by a shared mutex
- the access log, protected by a mutex
- the active connection registry, protected by a mutex
- an atomic client count

## Persistent connections

The proxy opens a fresh upstream TLS connection for each request and asks the origin to close it after the response. The downstream client connection remains persistent when the response has unambiguous framing: Content-Length, chunked transfer encoding, or no response body. Close-delimited responses force the downstream connection to close because their end cannot otherwise be represented without buffering the entire body.

## SIGINT reload

The signal handler performs only the async-signal-safe action of writing one byte to a self-pipe. The main poll loop receives that byte, reloads the ACL, and scans active connections. Any client/upstream pair whose hostname or selected IP is newly forbidden is shut down on both sides.

A failed reload leaves the previous ACL active.

## Cleanup

Each worker owns its client socket and TLS object. Scope guards unregister active connections, decrement the client count, shut down sockets, and free OpenSSL objects on every return path. Closing either side interrupts pending I/O and prevents dangling connections.

## Security choices

- TLS certificate and hostname verification are enabled by default.
- TLS versions older than 1.2 are disabled.
- Proxy authentication headers are not forwarded.
- Request and response headers are size-limited.
- Only GET and HEAD are accepted.
- ACL entries match exact names/IPs and subdomains of a blocked domain.
