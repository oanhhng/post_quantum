"""Extract TLS handshake figures from pcap files using tshark.

Usage: python summarize_pcap.py a.pcapng b.pcapng
Note: loopback MTU is very large so no fragmentation is visible; run between two machines/VMs
(MTU 1500) to observe the real number of segments.
"""
from __future__ import annotations

import subprocess
import sys


def tshark(args: list[str]) -> str:
    return subprocess.run(["tshark", *args], capture_output=True, text=True, check=True).stdout


def summarize(path: str) -> None:
    print(f"\n=== {path}")
    hs = tshark(["-r", path, "-Y", "tls.handshake.type == 1 || tls.handshake.type == 2",
                 "-T", "fields", "-e", "frame.number", "-e", "frame.len",
                 "-e", "tls.handshake.type", "-e", "tls.handshake.length"])
    names = {"1": "ClientHello", "2": "ServerHello"}
    for line in hs.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 4:
            frame, flen, htype, hlen = parts[:4]
            print(f"  frame {frame:>4}: {names.get(htype.split(',')[0], htype):12s} "
                  f"handshake_len={hlen}B  frame_len={flen}B")
    total = tshark(["-r", path, "-q", "-z", "io,stat,0"])
    print("  --- io statistics (total packets/bytes) ---")
    print("  " + "\n  ".join(total.strip().splitlines()[-6:]))
    conv = tshark(["-r", path, "-q", "-z", "conv,tcp"])
    print("  --- TCP conversations ---")
    print("  " + "\n  ".join(conv.strip().splitlines()))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for p in sys.argv[1:]:
        summarize(p)
