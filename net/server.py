"""Demo server. Run:  python -m net.server --mode hybrid --param ML-KEM-768"""
from __future__ import annotations

import argparse
import socket

from cryptography.exceptions import InvalidTag

from core.kem import DEFAULT_PARAM, PARAMS
from net.common import FramedSocket
from net.handshake import MODES, HandshakeError, server_handshake


def handle(conn: FramedSocket, args) -> None:
    res = server_handshake(conn, args.mode, args.param, args.backend)
    print(f"[server] handshake OK mode={res.mode} param={res.param} backend={res.backend} "
          f"{res.elapsed_s * 1000:.2f} ms, sent={res.bytes_sent}B received={res.bytes_recv}B (application layer)")
    while True:
        try:
            plain = res.channel.open(conn.recv_msg())
        except InvalidTag:
            print("[server] AES-GCM AUTHENTICATION FAILED -> closing connection "
                  "(keys do not match or data was modified)")
            return
        print(f"[server] received: {plain.decode(errors='replace')!r}")
        conn.send_msg(res.channel.seal(b"ACK: " + plain))
        if plain == b"bye":
            return


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1", help="default: localhost only (safe)")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--mode", choices=list(MODES), default="mlkem")
    p.add_argument("--param", choices=PARAMS, default=DEFAULT_PARAM)
    p.add_argument("--backend", choices=["kyber-py", "oqs"], default="kyber-py")
    p.add_argument("--once", action="store_true", help="serve one connection, then exit")
    p.add_argument("--timeout", type=float, default=30.0)
    args = p.parse_args()

    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))
        srv.listen(1)
        print(f"[server] listening on {args.host}:{args.port} ({args.mode}, {args.param}, {args.backend})")
        while True:
            sock, addr = srv.accept()
            sock.settimeout(args.timeout)
            print(f"[server] connection from {addr}")
            with FramedSocket(sock) as conn:
                try:
                    handle(conn, args)
                except (HandshakeError, ConnectionError, TimeoutError, ValueError) as e:
                    print(f"[server] error: {e!r}")
            if args.once:
                break


if __name__ == "__main__":
    main()
