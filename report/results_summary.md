# ML-KEM simulation - results summary

## NIST Known-Answer Tests (ACVP, FIPS 203): 240/240 passed

| test group | pass |
|---|---|
| keyGen ML-KEM-512 | 25/25 |
| keyGen ML-KEM-768 | 25/25 |
| keyGen ML-KEM-1024 | 25/25 |
| encapsulation ML-KEM-512 | 25/25 |
| encapsulation ML-KEM-768 | 25/25 |
| encapsulation ML-KEM-1024 | 25/25 |
| decapsulation ML-KEM-512 | 10/10 |
| decapsulation ML-KEM-768 | 10/10 |
| decapsulation ML-KEM-1024 | 10/10 |
| decapsulationKeyCheck ML-KEM-512 | 10/10 |
| encapsulationKeyCheck ML-KEM-512 | 10/10 |
| decapsulationKeyCheck ML-KEM-768 | 10/10 |
| encapsulationKeyCheck ML-KEM-768 | 10/10 |
| decapsulationKeyCheck ML-KEM-1024 | 10/10 |
| encapsulationKeyCheck ML-KEM-1024 | 10/10 |

## Experiment A - ML-KEM by parameter set (impl: kyber-py, n=1000)
_Source: expA_kyber-py_20261123_152012.csv_

| Parameter set | KeyGen median / p95 (us) | Encaps median / p95 (us) | Decaps median / p95 (us) | ek (B) | dk (B) | ct (B) | ss (B) |
|---|---|---|---|---|---|---|---|
| ML-KEM-1024 | 5197.2 / 9434.8 | 6644.8 / 12124.1 | 8994.9 / 17098.9 | 1568 | 3168 | 1568 | 32 |
| ML-KEM-512 | 1960.6 / 3686.9 | 2897.2 / 5715.8 | 4481.4 / 8925.1 | 800 | 1632 | 768 | 32 |
| ML-KEM-768 | 4498.9 / 7481.5 | 4555.8 / 7975.5 | 6054.0 / 13914.8 | 1184 | 2400 | 1088 | 32 |

## Experiment B - key establishment
_Source: expB_kyber-py_20261123_152143.csv_

| Algorithm | Implementation | Operations | Median (us) | p95 (us) | Std. dev. (us) | Raw bytes exchanged (no framing) |
|---|---|---|---|---|---|---|
| ML-KEM-768 (kyber-py) | kyber-py | keygen+encaps+decaps | 14346.1 | 25353.4 | 4253.1 | 2272 |
| X25519 (cryptography/OpenSSL) | cryptography | 2x keygen + 2x DH | 139.6 | 316.0 | 54.6 | 64 |
| RSA-2048-OAEP key transport (cryptography/OpenSSL) | cryptography | keygen+encrypt+decrypt (RSA keygen is slow; analyse separately) | 54412.2 | 149478.1 | 43536.0 | 550 |

> **Methodology note:** ML-KEM runs as pure Python (kyber-py) while X25519/RSA run natively (OpenSSL). This compares two IMPLEMENTATIONS and does not show which algorithm is faster.

## Handshake bytes (application layer) and time over localhost TCP
_Source: net_handshake_kyber-py_20261123_152153.csv_

| Mode | Parameter set | Implementation | Client sent (B) | Client received (B) | Total (B) | Expected (B) | Matches | Messages | Median (ms) | p95 (ms) |
|---|---|---|---|---|---|---|---|---|---|---|
| x25519 | - | cryptography | 36 | 36 | 72 | 72 | True | 2 | 14.977 | 17.021 |
| mlkem | ML-KEM-512 | kyber-py | 774 | 806 | 1580 | 1580 | True | 2 | 13.043 | 33.551 |
| hybrid | ML-KEM-512 | kyber-py | 806 | 838 | 1644 | 1644 | True | 2 | 17.942 | 31.455 |
| mlkem | ML-KEM-768 | kyber-py | 1094 | 1190 | 2284 | 2284 | True | 2 | 26.372 | 35.931 |
| hybrid | ML-KEM-768 | kyber-py | 1126 | 1222 | 2348 | 2348 | True | 2 | 25.017 | 33.527 |
| mlkem | ML-KEM-1024 | kyber-py | 1574 | 1574 | 3148 | 3148 | True | 2 | 42.123 | 53.183 |
| hybrid | ML-KEM-1024 | kyber-py | 1606 | 1606 | 3212 | 3212 | True | 2 | 33.834 | 49.964 |

> On-the-wire bytes (TCP/IP headers) and segment counts come from the pcap via `python -m net.pcap_stats`.

## TLS 1.3 handshake (openssl s_client / s_server)
_Source: tls_timing_20261123_151526.csv_

| Requested group | Negotiated | Samples | Median (ms) | p95 (ms) | Std. dev. (ms) | OpenSSL |
|---|---|---|---|---|---|---|
| X25519 | X25519 | 50 | 1049.99 | 1063.53 | 9.88 | OpenSSL 4.1.0 23 Oct 2026 (Library: OpenSSL 4.1.0 23 Oct 2026) |
| X25519MLKEM768 | X25519MLKEM768 | 50 | 1049.14 | 1065.75 | 10.32 | OpenSSL 4.1.0 23 Oct 2026 (Library: OpenSSL 4.1.0 23 Oct 2026) |

> Each sample includes `openssl` process start-up time: use for relative comparison only.
