#!/usr/bin/env bash
# Experiment C: TLS 1.3 X25519 vs X25519MLKEM768 + packet capture.
# REQUIRES: OpenSSL >= 3.5 (ML-KEM support), tshark. Run on Linux/WSL (not PowerShell).
# Check first:  openssl version ; openssl list -tls-groups
set -euo pipefail

OPENSSL="${OPENSSL:-openssl}"
PORT="${PORT:-4433}"
IFACE="${IFACE:-lo}"
OUT="${OUT:-../report}"
mkdir -p "$OUT"

echo "== OpenSSL: $($OPENSSL version)"
$OPENSSL list -tls-groups 2>/dev/null | grep -qi "MLKEM768" || {
  echo "ERROR: this OpenSSL has no ML-KEM key-exchange group. Use OpenSSL >= 3.5 (WSL/Docker) or set OPENSSL=/path/to/openssl"; exit 1; }

# Self-signed certificate for the demo only (never commit .pem files)
[ -f cert.pem ] || $OPENSSL req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -keyout key.pem -out cert.pem -days 7 -subj "/CN=localhost"

run_case () {
  local GROUP="$1" TAG="$2"
  echo "== Case $TAG (groups=$GROUP)"
  $OPENSSL s_server -accept "$PORT" -cert cert.pem -key key.pem -tls1_3 -groups "$GROUP" -www >/dev/null 2>&1 &
  local SRV=$!
  sleep 1
  tshark -i "$IFACE" -f "tcp port $PORT" -w "$OUT/tls_${TAG}.pcapng" >/dev/null 2>&1 &
  local CAP=$!
  sleep 1
  # Complete the handshake, then quit ('Q' ends s_client)
  echo Q | $OPENSSL s_client -connect "localhost:$PORT" -tls1_3 -groups "$GROUP" 2>&1 | grep -E "Negotiated|Server Temp Key|Peer Temp Key|Protocol" || true
  sleep 1
  kill "$CAP" "$SRV" 2>/dev/null || true
  wait 2>/dev/null || true
}

run_case "X25519" "x25519"
run_case "X25519MLKEM768" "x25519mlkem768"

echo "== Handshake timing (python -m tls.tls_timing --openssl $OPENSSL, run from the project root)"
(cd .. && python -m tls.tls_timing --openssl "$OPENSSL" --port "$((PORT+1))") || true

echo "== Packet summary (python summarize_pcap.py)"
python summarize_pcap.py "$OUT/tls_x25519.pcapng" "$OUT/tls_x25519mlkem768.pcapng"
