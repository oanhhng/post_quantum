"""Run the whole experiment pipeline in order and generate report/results_summary.md.

  python run_all.py --quick      # fast environment check (numbers are NOT for the report)
  python run_all.py              # full run (takes a few minutes with kyber-py)
  python run_all.py --backend oqs --openssl /path/to/openssl35

A failing step stops the run so you can fix it; the TLS step is skipped (never faked) if OpenSSL lacks ML-KEM.
"""
from __future__ import annotations

import argparse
import subprocess
import sys


def step(title: str, cmd: list[str], required: bool = True) -> None:
    print(f"\n=== {title}\n$ {' '.join(cmd)}", flush=True)
    rc = subprocess.run(cmd).returncode
    if rc and required:
        sys.exit(f"Step '{title}' failed (exit code {rc}). Stopping.")
    if rc:
        print(f"[warning] '{title}' failed (exit code {rc}), continuing.")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--quick", action="store_true")
    p.add_argument("--backend", choices=["kyber-py", "oqs"], default="kyber-py")
    p.add_argument("--openssl", default="openssl")
    a = p.parse_args()
    py = sys.executable
    it, runs, net_it, tls_n = (20, 2, 10, 10) if a.quick else (200, 5, 50, 50)

    step("Environment", [py, "env_info.py"])
    step("Unit tests", [py, "-m", "pytest", "-q"])
    step("Download NIST vectors", [py, "-m", "tests.vectors.fetch_vectors"], required=False)
    step("NIST KAT", [py, "-m", "tests.kat_runner"])
    step("Tamper", [py, "-m", "attacks.tamper", "--trials", "100", "--backend", a.backend])
    step("Experiment A", [py, "-m", "bench.benchmark", "A", "--backend", a.backend, "--iters", str(it), "--runs", str(runs)])
    step("Experiment B", [py, "-m", "bench.benchmark", "B", "--backend", a.backend, "--iters", str(it), "--runs", str(runs), "--rsa"])
    step("Handshake bytes and time over TCP", [py, "-m", "net.measure", "--backend", a.backend, "--iters", str(net_it)])
    step("TLS timing (Experiment C)", [py, "-m", "tls.tls_timing", "--openssl", a.openssl, "--n", str(tls_n)], required=False)
    step("Summary", [py, "-m", "bench.summarize"])
    print("\nDone. See report/results_summary.md. MITM and Wireshark capture must be done manually (see README).")


if __name__ == "__main__":
    main()
