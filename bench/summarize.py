"""Merge the latest results into report/results_summary.md (KAT, Exp. A, Exp. B, network bytes, TLS).

Run:  python -m bench.summarize
Every table names its source CSV for traceability. kyber-py and native results are never merged.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).parent.parent
RES = ROOT / "bench" / "results"


def latest(pattern: str) -> Path | None:
    files = sorted(RES.glob(pattern), key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


def md_table(df: pd.DataFrame) -> str:
    cols = list(df.columns)
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for _, r in df.iterrows():
        lines.append("| " + " | ".join(str(r[c]) for c in cols) + " |")
    return "\n".join(lines)


def section_kat() -> str:
    p = ROOT / "report" / "kat_summary.json"
    if not p.exists():
        return ("## NIST Known-Answer Tests\n_Not run yet: "
                "`python -m tests.vectors.fetch_vectors && python -m tests.kat_runner`_\n")
    d = json.loads(p.read_text())
    df = pd.DataFrame([{"test group": k, "pass": f"{v['pass']}/{v['total']}"} for k, v in d["groups"].items()])
    return f"## NIST Known-Answer Tests (ACVP, FIPS 203): {d['pass']}/{d['total']} passed\n\n{md_table(df)}\n"


def section_a() -> str:
    p = latest("expA_*.csv")
    if not p:
        return "## Experiment A\n_Not run yet._\n"
    df = pd.read_csv(p)
    piv = df.pivot_table(index="algo", columns="op", values="median_us").round(1)
    p95 = df.pivot_table(index="algo", columns="op", values="p95_us").round(1)
    sizes = df.groupby("algo")[["ek_B", "dk_B", "ct_B", "ss_B"]].first()
    out = pd.DataFrame({
        "KeyGen median / p95 (us)": [f"{piv.loc[a,'keygen']} / {p95.loc[a,'keygen']}" for a in piv.index],
        "Encaps median / p95 (us)": [f"{piv.loc[a,'encaps']} / {p95.loc[a,'encaps']}" for a in piv.index],
        "Decaps median / p95 (us)": [f"{piv.loc[a,'decaps']} / {p95.loc[a,'decaps']}" for a in piv.index],
    }, index=piv.index).join(sizes).reset_index()
    out = out.rename(columns={"algo": "Parameter set", "ek_B": "ek (B)", "dk_B": "dk (B)",
                              "ct_B": "ct (B)", "ss_B": "ss (B)"})
    return (f"## Experiment A - ML-KEM by parameter set (impl: {df['impl'].iloc[0]}, n={df['n'].iloc[0]})\n"
            f"_Source: {p.name}_\n\n{md_table(out)}\n")


def section_b() -> str:
    p = latest("expB_*.csv")
    if not p:
        return "## Experiment B\n_Not run yet._\n"
    df = pd.read_csv(p)[["algo", "impl", "ops", "median_us", "p95_us", "stdev_us", "total_exchange_B"]].round(1)
    df = df.rename(columns={"algo": "Algorithm", "impl": "Implementation", "ops": "Operations",
                            "median_us": "Median (us)", "p95_us": "p95 (us)", "stdev_us": "Std. dev. (us)",
                            "total_exchange_B": "Raw bytes exchanged (no framing)"})
    note = ""
    if (df["Implementation"] == "kyber-py").any():
        note = ("\n> **Methodology note:** ML-KEM runs as pure Python (kyber-py) while X25519/RSA run natively "
                "(OpenSSL). This compares two IMPLEMENTATIONS and does not show which algorithm is faster.\n")
    return f"## Experiment B - key establishment\n_Source: {p.name}_\n\n{md_table(df)}\n{note}"


def section_net() -> str:
    p = next(iter(sorted(RES.glob("net_handshake_*.csv"), key=lambda x: x.stat().st_mtime)[::-1]), None)
    if not p:
        return "## Handshake bytes and time over TCP\n_Not run yet: `python -m net.measure`._\n"
    df = pd.read_csv(p)[["mode", "param", "impl", "client_sent_B", "client_recv_B", "total_B",
                         "expected_total_B", "matches_expected", "msgs", "median_ms", "p95_ms"]]
    df = df.rename(columns={"mode": "Mode", "param": "Parameter set", "impl": "Implementation",
                            "client_sent_B": "Client sent (B)", "client_recv_B": "Client received (B)",
                            "total_B": "Total (B)", "expected_total_B": "Expected (B)",
                            "matches_expected": "Matches", "msgs": "Messages",
                            "median_ms": "Median (ms)", "p95_ms": "p95 (ms)"})
    return (f"## Handshake bytes (application layer) and time over localhost TCP\n_Source: {p.name}_\n\n{md_table(df)}\n\n"
            "> On-the-wire bytes (TCP/IP headers) and segment counts come from the pcap via "
            "`python -m net.pcap_stats`.\n")


def section_tls() -> str:
    p = latest("tls_timing_*.csv")
    if not p:
        return "## TLS 1.3 handshake\n_Not run yet: `python -m tls.tls_timing`._\n"
    df = pd.read_csv(p)[["group", "negotiated", "n", "median_ms", "p95_ms", "stdev_ms", "openssl"]]
    df = df.rename(columns={"group": "Requested group", "negotiated": "Negotiated", "n": "Samples",
                            "median_ms": "Median (ms)", "p95_ms": "p95 (ms)", "stdev_ms": "Std. dev. (ms)",
                            "openssl": "OpenSSL"})
    return (f"## TLS 1.3 handshake (openssl s_client / s_server)\n_Source: {p.name}_\n\n{md_table(df)}\n\n"
            "> Each sample includes `openssl` process start-up time: use for relative comparison only.\n")


def main() -> None:
    parts = ["# ML-KEM simulation - results summary\n", section_kat(), section_a(), section_b(),
             section_net(), section_tls()]
    out = ROOT / "report" / "results_summary.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(parts), encoding="utf-8")
    print("->", out)


if __name__ == "__main__":
    main()
