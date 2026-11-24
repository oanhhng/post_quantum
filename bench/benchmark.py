"""Benchmark.

Experiment A: ML-KEM-512/768/1024 (per-operation timing + sizes).
Experiment B: KEY ESTABLISHMENT ML-KEM-768 vs X25519 (optionally vs RSA-OAEP key transport).

Examples:
  python -m bench.benchmark A --backend kyber-py --iters 200 --runs 3
  python -m bench.benchmark B --backend oqs --iters 1000 --runs 5 --rsa

METHODOLOGY NOTES (state these in the report):
  * Every CSV row has an `impl` column: do NOT merge kyber-py (pure Python) with native results.
  * X25519/RSA use `cryptography` (native OpenSSL). Comparing kyber-py ML-KEM with X25519
    compares two IMPLEMENTATIONS, not the mathematical performance of the algorithms.
  * Same machine, same library versions, close heavy background processes while measuring.
"""
from __future__ import annotations

import argparse
import csv
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

import env_info
from bench.stats import measure
from core.kem import PARAMS, SIZES, get_kem

RESULTS = Path(__file__).parent / "results"


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"-> wrote {path}")


def save_env(tag: str, extra: dict) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"env_{tag}.json").write_text(
        json.dumps({**env_info.collect(), **extra}, indent=2, ensure_ascii=False), encoding="utf-8")


def experiment_a(args) -> None:
    rows = []
    for param in PARAMS:
        kem = get_kem(param, args.backend)
        ek, dk = kem.keygen()
        ss, ct = kem.encaps(ek)
        assert kem.decaps(dk, ct) == ss, "decaps mismatch - stop the benchmark!"
        ops = {
            "keygen": kem.keygen,
            "encaps": lambda: kem.encaps(ek),
            "decaps": lambda: kem.decaps(dk, ct),
        }
        for op, fn in ops.items():
            r = measure(fn, args.warmup, args.iters, args.runs)
            rows.append({"experiment": "A", "impl": kem.backend, "algo": param, "op": op,
                         **{k: round(v, 3) for k, v in r.items()},
                         "ek_B": len(ek), "dk_B": len(dk), "ct_B": len(ct), "ss_B": len(ss)})
            print(f"{param:12s} {op:7s} median={r['median_us']:.1f}us p95={r['p95_us']:.1f}us")
    ts = time.strftime("%Y%m%d_%H%M%S")
    write_csv(RESULTS / f"expA_{args.backend}_{ts}.csv", rows)
    save_env(f"expA_{ts}", vars(args))


# ---- Experiment B: full key-establishment flow ----------------------------------
def kex_mlkem(kem):
    def run():
        ek, dk = kem.keygen()          # initiator
        ss_b, ct = kem.encaps(ek)      # responder
        ss_a = kem.decaps(dk, ct)      # initiator finishes
        assert ss_a == ss_b
    return run


def kex_x25519():
    def run():
        a = X25519PrivateKey.generate()
        b = X25519PrivateKey.generate()
        ss_a = a.exchange(b.public_key())
        ss_b = b.exchange(a.public_key())
        assert ss_a == ss_b
    return run


def kex_rsa_oaep(bits: int):
    """RSA-OAEP KEY TRANSPORT (not a KEM): the responder picks a random 32-byte key and encrypts it."""
    import os
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    def run():
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)  # initiator
        key = os.urandom(32)
        ct = priv.public_key().encrypt(key, oaep)  # responder
        assert priv.decrypt(ct, oaep) == key       # initiator
    return run


def experiment_b(args) -> None:
    kem = get_kem("ML-KEM-768", args.backend)
    sz = SIZES["ML-KEM-768"]
    cases = [
        (f"ML-KEM-768 ({kem.backend})", kem.backend, kex_mlkem(kem),
         sz["ek"], sz["ct"], "keygen+encaps+decaps"),
        ("X25519 (cryptography/OpenSSL)", "cryptography", kex_x25519(),
         32, 32, "2x keygen + 2x DH"),
    ]
    if args.rsa:
        cases.append((f"RSA-{args.rsa_bits}-OAEP key transport (cryptography/OpenSSL)", "cryptography",
                      kex_rsa_oaep(args.rsa_bits), args.rsa_bits // 8 + 38, args.rsa_bits // 8,
                      "keygen+encrypt+decrypt (RSA keygen is slow; analyse separately)"))
    rows = []
    for name, impl, fn, pub_b, resp_b, ops in cases:
        r = measure(fn, args.warmup, args.iters, args.runs)
        rows.append({"experiment": "B", "impl": impl, "algo": name, "ops": ops,
                     **{k: round(v, 3) for k, v in r.items()},
                     "initiator_to_responder_B": pub_b, "responder_to_initiator_B": resp_b,
                     "total_exchange_B": pub_b + resp_b})
        print(f"{name:62s} median={r['median_us']:.1f}us p95={r['p95_us']:.1f}us")
    if kem.backend == "kyber-py":
        print("\n[WARNING] ML-KEM runs as pure Python (kyber-py) while X25519/RSA are native: "
              "do NOT conclude which algorithm is faster from this table.")
    ts = time.strftime("%Y%m%d_%H%M%S")
    write_csv(RESULTS / f"expB_{args.backend}_{ts}.csv", rows)
    save_env(f"expB_{ts}", vars(args))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("experiment", choices=["A", "B"])
    p.add_argument("--backend", choices=["kyber-py", "oqs"], default="kyber-py")
    p.add_argument("--warmup", type=int, default=20)
    p.add_argument("--iters", type=int, default=200, help="timed iterations per run")
    p.add_argument("--runs", type=int, default=3, help="number of independent runs")
    p.add_argument("--rsa", action="store_true", help="(Experiment B) also measure RSA-OAEP key transport")
    p.add_argument("--rsa-bits", type=int, default=2048)
    args = p.parse_args()
    {"A": experiment_a, "B": experiment_b}[args.experiment](args)


if __name__ == "__main__":
    main()
