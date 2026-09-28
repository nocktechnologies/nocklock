#!/usr/bin/env python3
import argparse
import select
import socket
import sys
import threading
from pathlib import Path


def pipe(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 30)
            if not readable:
                return
            for src in readable:
                data = src.recv(65536)
                if not data:
                    return
                dst = right if src is left else left
                dst.sendall(data)
    finally:
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()


def handle(conn: socket.socket, allow: set[str]) -> None:
    with conn:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        first = data.split(b"\r\n", 1)[0].decode("ascii", "replace")
        print(f"proxy: request_line={first}", flush=True)
        parts = first.split()
        if len(parts) < 3 or parts[0].upper() != "CONNECT":
            conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n")
            return
        host_port = parts[1]
        if ":" not in host_port:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
            return
        host, raw_port = host_port.rsplit(":", 1)
        if host not in allow:
            print(f"proxy: denied_host={host}", flush=True)
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
            return
        try:
            port = int(raw_port)
            upstream = socket.create_connection((host, port), timeout=20)
        except Exception as exc:
            print(f"proxy: upstream_error={type(exc).__name__}:{exc}", flush=True)
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n")
            return
        print(f"proxy: connected_upstream={host}:{port}", flush=True)
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        pipe(conn, upstream)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--ready", required=True)
    parser.add_argument("--allow", action="append", default=[])
    args = parser.parse_args()

    path = Path(args.socket)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(16)
    Path(args.ready).write_text("ready\n")
    print(f"proxy: ready socket={path}", flush=True)
    allow = set(args.allow)
    try:
        while True:
            conn, _ = server.accept()
            threading.Thread(target=handle, args=(conn, allow), daemon=True).start()
    except KeyboardInterrupt:
        return 0
    finally:
        server.close()
        try:
            path.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    sys.exit(main())
