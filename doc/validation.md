# Validation

Validated on a Linux x86-64 environment with GCC 14.2.0 and OpenSSL 3.5.5.

- Warning-clean build with `-Wall -Wextra -Wpedantic -Wconversion -Wshadow`
- Local certificate and hostname verification exercised with a generated trusted certificate
- GET, HEAD, chunked response, downstream keep-alive, malformed request, 501, 502, concurrency, ACL reload, 403, `X-Forwarded-For`, and access-log tests passed
- AddressSanitizer and UndefinedBehaviorSanitizer integration run passed

Run the standard checks with:

```sh
make clean
make
make test
```
