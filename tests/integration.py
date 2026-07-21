#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
PROXY = ROOT / "bin" / "myproxy"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        body = f"secure origin {self.path}\nxff={self.headers.get('X-Forwarded-For', '')}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        if self.path == "/chunked":
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (body[:7], body[7:]):
                self.wfile.write(f"{len(part):X}\r\n".encode() + part + b"\r\n")
            self.wfile.write(b"0\r\nX-Test: done\r\n\r\n")
            self.wfile.flush()
        else:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "123")
        self.end_headers()

    def log_message(self, *_: object) -> None:
        pass


def request(proxy_port: int, target: str, method: str = "GET") -> bytes:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
        authority = target.split("://", 1)[1].split("/", 1)[0]
        raw = (
            f"{method} {target} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(raw)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)


def read_one_response(sock: socket.socket) -> bytes:
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        buffer += sock.recv(4096)
    head, body = buffer.split(b"\r\n\r\n", 1)
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        name, value = line.split(b":", 1)
        headers[name.lower()] = value.strip()
    length = int(headers.get(b"content-length", b"0"))
    while len(body) < length:
        body += sock.recv(4096)
    return head + b"\r\n\r\n" + body[:length]


def persistent_pair(proxy_port: int, target: str) -> tuple[bytes, bytes]:
    authority = target.split("://", 1)[1].split("/", 1)[0]
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
        first = (
            f"GET {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n"
        ).encode()
        sock.sendall(first)
        response_one = read_one_response(sock)
        second_target = target.rsplit("/", 1)[0] + "/second"
        second = (
            f"GET {second_target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        ).encode()
        sock.sendall(second)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return response_one, b"".join(chunks)


def status(response: bytes) -> int:
    return int(response.split(b"\r\n", 1)[0].split()[1])


def assert_startup_rejected(work: Path, *arguments: str) -> None:
    completed = subprocess.run(
        [str(PROXY), *arguments],
        cwd=work,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=3,
        check=False,
    )
    assert completed.returncode == 2, completed


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="c2s-proxy-") as temporary:
        work = Path(temporary)
        cert = work / "cert.pem"
        key = work / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        origin_port = free_port()
        server = ThreadingHTTPServer(("127.0.0.1", origin_port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        proxy_port = free_port()
        acl = work / "forbidden.txt"
        acl.write_text("# initially empty\n", encoding="utf-8")
        access_log = work / "access.log"

        assert_startup_rejected(
            work, "-p", str(proxy_port), "-a", "../forbidden.txt", "-l", access_log.name
        )
        assert_startup_rejected(
            work, "-p", str(proxy_port), "-a", acl.name, "-l", "nested/access.log"
        )
        acl_link = work / "forbidden-link.txt"
        acl_link.symlink_to(acl.name)
        assert_startup_rejected(
            work, "-p", str(proxy_port), "-a", acl_link.name, "-l", access_log.name
        )
        log_link = work / "access-link.log"
        log_link.symlink_to(cert.name)
        assert_startup_rejected(
            work, "-p", str(proxy_port), "-a", acl.name, "-l", log_link.name
        )

        env = os.environ.copy()
        env["SSL_CERT_FILE"] = str(cert)
        proxy = subprocess.Popen(
            [str(PROXY), "-p", str(proxy_port), "-a", acl.name, "-l", access_log.name],
            cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            time.sleep(0.25)
            target = f"http://localhost:{origin_port}/hello"
            response = request(proxy_port, target)
            assert status(response) == 200, response
            assert b"secure origin /hello" in response
            assert b"xff=127.0.0.1" in response

            response = request(proxy_port, target, "HEAD")
            assert status(response) == 200, response
            assert response.endswith(b"\r\n\r\n"), response

            chunked = request(proxy_port, f"http://localhost:{origin_port}/chunked")
            assert status(chunked) == 200, chunked
            assert b"Transfer-Encoding: chunked" in chunked
            assert b"X-Test: done" in chunked

            first, second = persistent_pair(proxy_port, target)
            assert status(first) == 200 and b"Connection: keep-alive" in first
            assert status(second) == 200 and b"secure origin /second" in second

            response = request(proxy_port, target, "CONNECT")
            assert status(response) == 501, response

            with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: one\r\nHost: two\r\nConnection: close\r\n\r\n")
                malformed = sock.recv(4096)
            assert status(malformed) == 400, malformed

            unresolved = request(proxy_port, "http://does-not-exist.invalid/")
            assert status(unresolved) == 502, unresolved

            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                responses = list(executor.map(lambda _: request(proxy_port, target), range(24)))
            assert all(status(item) == 200 for item in responses)

            acl.write_text("localhost\n", encoding="utf-8")
            proxy.send_signal(signal.SIGINT)
            time.sleep(0.25)
            response = request(proxy_port, target)
            assert status(response) == 403, response

            log_text = access_log.read_text(encoding="utf-8")
            assert '"GET http://localhost:' in log_text
            assert " 200 " in log_text
            assert " 403 " in log_text
            assert " 501 " in log_text
            assert access_log.stat().st_mode & 0o777 == 0o600
            print("integration tests passed")
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proxy.kill()
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
