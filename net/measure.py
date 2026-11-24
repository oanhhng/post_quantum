"""Measure ACTUAL application-layer bytes and handshake time over real localhost TCP.

Run:  python -m net.measure --iters 50 --backend kyber-py
To count packets/segments: start Wireshark/tshark on --port BEFORE running (see net/pcap_stats.py).

Configurations: x25519 (baseline with the same framing), mlkem, hybrid x 3 parameter sets.
'total' time = from connect() until the client finishes the handshake (includes waiting for server keygen).
"""
from __future__ import annotations

import argparse
import csv
import json
import socket
import statistics as st
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from bench.stats import percentile
from core.kem import PARAMS, SIZES
from net.common import FramedSocket
from net.handshake import client_handshake, server_handshake

RESULTS = Path(__file__).parent.parent / "bench" / "results"
FRAME = 4  # length-prefix bytes per message
HDR = 2


def _x25519_server(conn: FramedSocket):
    priv = X25519PrivateKey.generate()
    conn.send_msg(priv.public_key().public_bytes_raw())
    priv.exchange(X25519PublicKey.from_public_bytes(conn.recv_msg()))


def _x25519_client(conn: FramedSocket):
    peer = conn.recv_msg()
    priv = X25519PrivateKey.generate()
    conn.send_msg(priv.public_key().public_bytes_raw())
    priv.exchange(X25519PublicKey.from_public_bytes(peer))


def expected_bytes(mode: str, param: str) -> tuple[int, int]:
    """(client_sent, client_received) expected at the application layer, including 4-byte length prefixes."""
    if mode == "x25519":
        return FRAME + 32, FRAME + 32
    extra = 32 if mode == "hybrid" else 0
    return FRAME + HDR + SIZES[param]["ct"] + extra, FRAME + HDR + SIZES[param]["ek"] + extra


def run_config(mode: str, param: str, backend: str, host: str, port: int, n_total: int) -> list[dict]:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(8)
    err: list[Exception] = []

    def serve():
        try:
            for _ in range(n_total):
                s, _ = srv.accept()
                s.settimeout(60)
                with FramedSocket(s) as conn:
                    if mode == "x25519":
                        _x25519_server(conn)
                    else:
                        server_handshake(conn, mode, param, backend)
        except Exception as e:  # noqa: BLE001
            err.append(e)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    rows = []
    for _ in range(n_total):
        t0 = time.perf_counter()
        sock = socket.create_connection((host, port), timeout=60)
        t_conn = time.perf_counter()
        with FramedSocket(sock) as conn:
            if mode == "x25519":
                _x25519_client(conn)
            else:
                client_handshake(conn, mode, param, backend)
            t1 = time.perf_counter()
            rows.append({"connect_ms": (t_conn - t0) * 1e3, "total_ms": (t1 - t0) * 1e3,
                         "sent_B": conn.bytes_sent, "recv_B": conn.bytes_recv,
                         "msgs": conn.msgs_sent + conn.msgs_recv})
    t.join(timeout=30)
    srv.close()
    if err:
        raise err[0]
    return rows


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5300)
    p.add_argument("--iters", type=int, default=50)
    p.add_argument("--warmup", type=int, default=3)
    p.add_argument("--backend", choices=["kyber-py", "oqs"], default="kyber-py")
    p.add_argument("--params", nargs="+", default=list(PARAMS), choices=PARAMS)
    args = p.parse_args()

    configs = [("x25519", "-")] + [(m, pr) for pr in args.params for m in ("mlkem", "hybrid")]
    out_rows, order, stream = [], [], 0
    for mode, param in configs:
        n_total = args.warmup + args.iters
        rows = run_config(mode, param, args.backend, args.host, args.port, n_total)
        order.append({"mode": mode, "param": param, "streams": [stream, stream + n_total],
                      "warmup_streams": args.warmup})
        stream += n_total
        rows = rows[args.warmup:]
        tot = sorted(r["total_ms"] for r in rows)
        exp_s, exp_r = expected_bytes(mode, param)
        sent, recv = rows[0]["sent_B"], rows[0]["recv_B"]
        assert all(r["sent_B"] == sent and r["recv_B"] == recv for r in rows), "byte counts are not stable?"
        out_rows.append({
            "mode": mode, "param": param, "impl": args.backend if mode != "x25519" else "cryptography",
            "iters": args.iters, "client_sent_B": sent, "client_recv_B": recv, "total_B": sent + recv,
            "expected_total_B": exp_s + exp_r, "matches_expected": (sent, recv) == (exp_s, exp_r),
            "msgs": rows[0]["msgs"],
            "median_ms": round(st.median(tot), 3), "mean_ms": round(st.fmean(tot), 3),
            "stdev_ms": round(st.stdev(tot), 3) if len(tot) > 1 else 0.0,
            "p95_ms": round(percentile(tot, 95), 3),
            "connect_median_ms": round(st.median(r["connect_ms"] for r in rows), 3),
        })
        r = out_rows[-1]
        print(f"{mode:7s} {param:12s} bytes={r['total_B']:5d} (expect {r['expected_total_B']}) "
              f"median={r['median_ms']:.2f}ms p95={r['p95_ms']:.2f}ms")

    RESULTS.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = RESULTS / f"net_handshake_{args.backend}_{ts}.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
        w.writeheader()
        w.writerows(out_rows)
    (RESULTS / f"net_handshake_order_{ts}.json").write_text(
        json.dumps({"port": args.port, "configs": order}, indent=2), encoding="utf-8")
    print("->", path)


if __name__ == "__main__":
    main()
