"""Per-connection TCP statistics from a pcap (requires tshark): packets, data segments, bytes.

Procedure:
  1) Terminal A:  tshark -i lo -f "tcp port 5300" -w report/net_measure.pcapng
                  (Windows: pick the loopback adapter listed by `tshark -D`)
  2) Terminal B:  python -m net.measure --port 5300      (writes net_handshake_order_*.json)
  3) Stop tshark (Ctrl+C), then:
        python -m net.pcap_stats report/net_measure.pcapng bench/results/net_handshake_order_<ts>.json

NOT yet verified on the team's machine: the tshark field names (tcp.stream, tcp.len, ...) are valid
for tshark 3.x/4.x; if it fails, run `tshark -G fields | grep tcp.len` to cross-check.
Note: loopback MTU is large (~65536), so a ~1.2 KB ek message is still a single segment.
"""
from __future__ import annotations

import csv
import json
import statistics as st
import subprocess
import sys
from collections import defaultdict


def read_streams(pcap: str) -> dict[int, dict]:
    out = subprocess.run(
        ["tshark", "-r", pcap, "-T", "fields", "-E", "separator=,",
         "-e", "tcp.stream", "-e", "frame.len", "-e", "tcp.len"],
        capture_output=True, text=True, check=True).stdout
    streams: dict[int, dict] = defaultdict(lambda: {"packets": 0, "wire_B": 0, "payload_B": 0, "data_segments": 0})
    for line in out.splitlines():
        parts = line.split(",")
        if len(parts) < 3 or not parts[0]:
            continue
        s = streams[int(parts[0])]
        s["packets"] += 1
        s["wire_B"] += int(parts[1])
        plen = int(parts[2] or 0)
        s["payload_B"] += plen
        s["data_segments"] += plen > 0
    return dict(streams)


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    pcap, order_path = sys.argv[1], sys.argv[2]
    streams = read_streams(pcap)
    order = json.load(open(order_path, encoding="utf-8"))["configs"]
    rows = []
    for c in order:
        lo, hi = c["streams"]
        ids = [i for i in range(lo + c["warmup_streams"], hi) if i in streams]
        if not ids:
            print(f"[warning] no stream found for {c['mode']} {c['param']} - did the capture start BEFORE the run?")
            continue
        def med(key):
            return st.median(streams[i][key] for i in ids)
        rows.append({"mode": c["mode"], "param": c["param"], "streams_used": len(ids),
                     "packets_median": med("packets"), "data_segments_median": med("data_segments"),
                     "payload_B_median": med("payload_B"), "wire_B_median": med("wire_B")})
    if not rows:
        sys.exit("no data")
    w = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
    print("\n# payload_B: TCP payload bytes (compare with 'total_B' from net.measure); wire_B: includes Ethernet/IP/TCP headers",
          file=sys.stderr)


if __name__ == "__main__":
    main()
