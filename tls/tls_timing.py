"""Measure TLS 1.3 handshake time between `openssl s_server` and `openssl s_client`.

Run (from the project root):
  python -m tls.tls_timing --n 50 --groups X25519 X25519MLKEM768
  python -m tls.tls_timing --openssl /opt/openssl35/bin/openssl --groups X25519 X25519MLKEM768

METHOD AND LIMITATIONS (state these in the report):
  * Each sample = one run of the `openssl s_client` process, so it includes process start-up cost
    (roughly constant across configurations). Use it only for RELATIVE comparison between key
    exchange groups, not as pure handshake time.
  * The script VERIFIES that the requested group was really negotiated (matched against s_client
    output). If OpenSSL does not support the group (e.g. < 3.5 for ML-KEM) it reports a clear
    message and skips - it never records fake measurements.
  * Loopback has no network latency: differences mostly reflect computation + message size.
"""
from __future__ import annotations

import argparse
import csv
import re
import statistics as st
import subprocess
import tempfile
import time
from pathlib import Path

from bench.stats import percentile

RESULTS = Path(__file__).parent.parent / "bench" / "results"
NEG_RE = re.compile(r"(Negotiated TLS1\.3 group|Server Temp Key|Peer Temp Key)\s*:\s*([^\r\n,]+)", re.I)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def make_cert(openssl: str, d: Path) -> tuple[Path, Path]:
    cert, key = d / "cert.pem", d / "key.pem"
    r = run([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=localhost"])
    if r.returncode:
        raise SystemExit(f"Could not create the certificate: {r.stderr}")
    return cert, key


def client_once(openssl: str, port: int, group: str) -> tuple[float, str, int]:
    t0 = time.perf_counter()
    r = run([openssl, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-groups", group],
            input="Q\n", timeout=30)
    dt = (time.perf_counter() - t0) * 1e3
    out = r.stdout + r.stderr
    m = NEG_RE.findall(out)
    negotiated = m[0][1].strip() if m else ""
    return dt, negotiated, r.returncode


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--openssl", default="openssl")
    p.add_argument("--port", type=int, default=4433)
    p.add_argument("--groups", nargs="+", default=["X25519", "X25519MLKEM768"])
    p.add_argument("--n", type=int, default=50)
    p.add_argument("--warmup", type=int, default=5)
    args = p.parse_args()

    ver = run([args.openssl, "version"]).stdout.strip()
    print("OpenSSL:", ver)
    rows = []
    with tempfile.TemporaryDirectory() as td:
        cert, key = make_cert(args.openssl, Path(td))
        for group in args.groups:
            srv = subprocess.Popen(
                [args.openssl, "s_server", "-accept", str(args.port), "-cert", str(cert), "-key", str(key),
                 "-tls1_3", "-groups", group, "-www"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                time.sleep(1.0)
                _, neg, rc = client_once(args.openssl, args.port, group)  # pre-check
                want = "MLKEM" if "MLKEM" in group.upper() else group
                if rc != 0 or want.lower() not in neg.lower():
                    print(f"[SKIPPED] {group}: handshake failed or the group was not negotiated "
                          f"(rc={rc}, negotiated='{neg}'). Does this OpenSSL support the group? "
                          f"Check: {args.openssl} list -tls-groups")
                    continue
                for _ in range(args.warmup):
                    client_once(args.openssl, args.port, group)
                times = sorted(client_once(args.openssl, args.port, group)[0] for _ in range(args.n))
                rows.append({"group": group, "negotiated": neg, "openssl": ver, "n": args.n,
                             "median_ms": round(st.median(times), 2), "mean_ms": round(st.fmean(times), 2),
                             "stdev_ms": round(st.stdev(times), 2), "p95_ms": round(percentile(times, 95), 2)})
                r = rows[-1]
                print(f"{group:16s} negotiated={neg:16s} median={r['median_ms']}ms p95={r['p95_ms']}ms")
            finally:
                srv.terminate()
                srv.wait(timeout=10)
    if not rows:
        raise SystemExit("No valid results.")
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / f"tls_timing_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("->", path)


if __name__ == "__main__":
    main()
