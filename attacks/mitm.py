"""Scenario 2: man-in-the-middle (MITM) - shows that a KEM alone does not authenticate.

RUN ON LOCALHOST ONLY, against your own demo programs.

Mallory runs server_handshake toward the real client and client_handshake toward the
real server, so she holds two separate session keys and can read/modify every message.

How to run (3 terminals):
  1) python -m net.server --mode hybrid --port 5000
  2) python -m attacks.mitm --mode hybrid --listen-port 5001 --server-port 5000
  3) python -m net.client --mode hybrid --port 5001 --message "the password is 1234"
"""
from __future__ import annotations

import argparse
import socket

from cryptography.exceptions import InvalidTag

from core.kem import DEFAULT_PARAM, PARAMS
from net.common import FramedSocket
from net.handshake import MODES, client_handshake, server_handshake


def relay_once(down: FramedSocket, up: FramedSocket, down_ch, up_ch, tamper: bool) -> bool:
    """Forward one client->server request and one server->client reply. True if finished."""
    plain = down_ch.open(down.recv_msg())
    print(f"[mallory] READ client message: {plain.decode(errors='replace')!r}")
    out = plain
    if tamper and plain != b"bye":
        out = plain + b" [MODIFIED BY MALLORY]"
        print(f"[mallory] modified to: {out.decode()!r}")
    up.send_msg(up_ch.seal(out))

    reply = up_ch.open(up.recv_msg())
    print(f"[mallory] READ server reply: {reply.decode(errors='replace')!r}")
    down.send_msg(down_ch.seal(reply))
    return plain == b"bye"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--listen-port", type=int, default=5001)
    p.add_argument("--server-port", type=int, default=5000)
    p.add_argument("--mode", choices=list(MODES), default="mlkem")
    p.add_argument("--param", choices=PARAMS, default=DEFAULT_PARAM)
    p.add_argument("--backend", choices=["kyber-py", "oqs"], default="kyber-py")
    p.add_argument("--tamper", action="store_true", help="modify messages in transit")
    args = p.parse_args()

    with socket.socket() as lst:
        lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lst.bind((args.host, args.listen_port))
        lst.listen(1)
        print(f"[mallory] waiting for client on {args.host}:{args.listen_port}, forwarding to server :{args.server_port}")
        csock, _ = lst.accept()
        csock.settimeout(60)
        usock = socket.create_connection((args.host, args.server_port), timeout=60)
        with FramedSocket(csock) as down, FramedSocket(usock) as up:
            # Act as the client toward the real server, and as the server toward the real client
            up_res = client_handshake(up, args.mode, args.param, args.backend)
            down_res = server_handshake(down, args.mode, args.param, args.backend)
            print("[mallory] established TWO separate session keys -> neither endpoint detects anything")
            try:
                while not relay_once(down, up, down_res.channel, up_res.channel, args.tamper):
                    pass
            except (InvalidTag, ConnectionError) as e:
                print("[mallory] finished:", repr(e))
    print("Conclusion: authentication (digital signatures / certificates) is required to bind "
          "the public key to the server's identity.")


if __name__ == "__main__":
    main()
