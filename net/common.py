"""Length-prefixed message framing over TCP + application-layer byte counters."""
from __future__ import annotations

import socket
import struct

MAX_FRAME = 1 << 20  # 1 MiB: reject oversized frames (prevents arbitrary allocation by the peer)
LEN = struct.Struct(">I")


class FramedSocket:
    """Wraps a socket: each message = 4-byte big-endian length + payload.

    Counts APPLICATION-layer bytes (including the 4-byte length prefix), NOT TCP/IP headers.
    Compare with Wireshark to see the difference.
    """

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.msgs_sent = 0
        self.msgs_recv = 0

    def send_msg(self, data: bytes) -> None:
        if len(data) > MAX_FRAME:
            raise ValueError("frame too large")
        self.sock.sendall(LEN.pack(len(data)) + data)
        self.bytes_sent += LEN.size + len(data)
        self.msgs_sent += 1

    def _recv_exact(self, n: int) -> bytes:
        chunks, remaining = [], n
        while remaining:
            chunk = self.sock.recv(remaining)
            if not chunk:
                raise ConnectionError("connection closed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def recv_msg(self) -> bytes:
        (n,) = LEN.unpack(self._recv_exact(LEN.size))
        if n > MAX_FRAME:
            raise ValueError(f"frame of {n} bytes exceeds limit {MAX_FRAME}")
        data = self._recv_exact(n)
        self.bytes_recv += LEN.size + n
        self.msgs_recv += 1
        return data

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
