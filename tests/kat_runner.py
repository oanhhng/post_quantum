"""Run the NIST ACVP known-answer tests for ML-KEM (FIPS 203) against kyber-py. Used by pytest and CLI.

CLI:  python -m tests.kat_runner         (prints a result table, writes report/kat_summary.json)

Test groups:
  keyGen                 : (d||z) -> (ek, dk)           byte-for-byte match
  encapsulation          : (ek, m) -> (c, k)            byte-for-byte match (internal function with fixed m)
  decapsulation          : (dk, c) -> k                 byte-for-byte match (includes implicit-rejection cases)
  encapsulationKeyCheck  : type + modulus check of ek      -> testPassed
  decapsulationKeyCheck  : type + internal hash check of dk -> testPassed
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path

VEC = Path(__file__).parent / "vectors"
IMPLS = {}


def _impls():
    if not IMPLS:
        from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

        IMPLS.update({"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024})
    return IMPLS


def vectors_available() -> bool:
    return all((VEC / d / f).exists() for d in ("keygen", "encapdecap")
               for f in ("prompt.json", "expectedResults.json"))


def _load(folder: str):
    prompt = json.loads((VEC / folder / "prompt.json").read_text())
    expected = json.loads((VEC / folder / "expectedResults.json").read_text())
    exp = {(g["tgId"], t["tcId"]): t for g in expected["testGroups"] for t in g["tests"]}
    return prompt, exp


def _h(s: str) -> bytes:
    return bytes.fromhex(s)


def ek_check(kem, ek: bytes) -> bool:
    """Encapsulation-key check: correct length + Encode(Decode(ek)) == ek (via kyber-py internals)."""
    try:
        kem._encaps_internal(ek, bytes(32))
        return True
    except ValueError:
        return False


def dk_check(kem, dk: bytes) -> bool:
    """Decapsulation-key check: correct length + H(ek_pke) == hash stored in dk (FIPS 203)."""
    if len(dk) != kem._dk_size():
        return False
    k = kem.k
    ek_pke = dk[384 * k: 768 * k + 32]
    h = dk[768 * k + 32: 768 * k + 64]
    return hashlib.sha3_256(ek_pke).digest() == h


def run_all() -> dict:
    """Return {group_name: {'pass': n, 'total': m, 'failed': [tcId...]}}."""
    impls = _impls()
    res = defaultdict(lambda: {"pass": 0, "total": 0, "failed": []})

    def record(name, tc, ok):
        r = res[name]
        r["total"] += 1
        if ok:
            r["pass"] += 1
        else:
            r["failed"].append(tc)

    prompt, exp = _load("keygen")
    for g in prompt["testGroups"]:
        kem = impls[g["parameterSet"]]
        for t in g["tests"]:
            e = exp[(g["tgId"], t["tcId"])]
            ek, dk = kem.key_derive(_h(t["d"]) + _h(t["z"]))
            record(f"keyGen {g['parameterSet']}", t["tcId"], ek == _h(e["ek"]) and dk == _h(e["dk"]))

    prompt, exp = _load("encapdecap")
    for g in prompt["testGroups"]:
        kem = impls[g["parameterSet"]]
        fn = g["function"]
        for t in g["tests"]:
            e = exp[(g["tgId"], t["tcId"])]
            if fn == "encapsulation":
                k, c = kem._encaps_internal(_h(t["ek"]), _h(t["m"]))
                ok = c == _h(e["c"]) and k == _h(e["k"])
            elif fn == "decapsulation":
                ok = kem._decaps_internal(_h(t["dk"]), _h(t["c"])) == _h(e["k"])
            elif fn == "encapsulationKeyCheck":
                ok = ek_check(kem, _h(t["ek"])) == e["testPassed"]
            elif fn == "decapsulationKeyCheck":
                ok = dk_check(kem, _h(t["dk"])) == e["testPassed"]
            else:
                continue
            record(f"{fn} {g['parameterSet']}", t["tcId"], ok)
    return dict(res)


def main() -> None:
    if not vectors_available():
        raise SystemExit("Vectors not found. Run: python -m tests.vectors.fetch_vectors")
    res = run_all()
    tp = sum(r["pass"] for r in res.values())
    tt = sum(r["total"] for r in res.values())
    print(f"{'Test group':44s} {'pass/total':>10s}")
    for name, r in res.items():
        flag = "" if r["pass"] == r["total"] else f"  FAILED tcId={r['failed'][:10]}"
        print(f"{name:44s} {r['pass']:>4d}/{r['total']:<5d}{flag}")
    print(f"{'TOTAL':44s} {tp:>4d}/{tt}")
    out = Path(__file__).parent.parent / "report" / "kat_summary.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"groups": res, "pass": tp, "total": tt}, indent=2), encoding="utf-8")
    print("->", out)
    raise SystemExit(0 if tp == tt else 1)


if __name__ == "__main__":
    main()
