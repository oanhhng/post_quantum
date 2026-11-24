"""Demo client. Run:  python -m net.client --mode hybrid --message "hello" """
from __future__ import annotations

import argparse
import json
import socket

from core.kem import DEFAULT_PARAM, PARAMS
from net.common import FramedSocket
from net.handshake import MODES, client_handshake


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--mode", choices=list(MODES), default="mlkem")
    p.add_argument("--param", choices=PARAMS, default=DEFAULT_PARAM)
    p.add_argument("--backend", choices=["kyber-py", "oqs"], default="kyber-py")
    p.add_argument("--message", action="append", default=None, help="may be repeated")
    p.add_argument("--json", action="store_true", help="print statistics as JSON (for automation)")
    p.add_argument("--timeout", type=float, default=30.0)
    args = p.parse_args()
    messages = args.message or ["Hello from the client", "Second message"]

    sock = socket.create_connection((args.host, args.port), timeout=args.timeout)
    with FramedSocket(sock) as conn:
        res = client_handshake(conn, args.mode, args.param, args.backend)
        hs = {
            "mode": res.mode, "param": res.param, "backend": res.backend,
            "handshake_ms": round(res.elapsed_s * 1000, 3),
            "app_bytes_sent": res.bytes_sent, "app_bytes_recv": res.bytes_recv,
        }
        replies = []
        for m in messages + ["bye"]:
            conn.send_msg(res.channel.seal(m.encode()))
            replies.append(res.channel.open(conn.recv_msg()).decode(errors="replace"))
        hs["total_app_bytes_sent"] = conn.bytes_sent
        hs["total_app_bytes_recv"] = conn.bytes_recv

    if args.json:
        print(json.dumps(hs))
    else:
        print("[client] handshake:", json.dumps(hs, indent=2))
        for m, r in zip(messages + ["bye"], replies):
            print(f"[client] sent {m!r} -> received {r!r}")


if __name__ == "__main__":
    main()
