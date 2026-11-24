# ML-KEM (FIPS 203) simulation - Network Security final project

> For LEARNING purposes only. `kyber-py` (pure Python) has no side-channel protection; the protocol in `net/`
> is our own design, is not compatible with TLS, and does not authenticate the server. Do not use it with real data.

## Setup

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements.txt
```
**Linux / macOS:**
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```
Then:
```
python env_info.py          # record the output in the lab notebook
python -m pytest -q         # everything must pass
```
Run every `python -m ...` command from the PROJECT ROOT (the folder that contains `core/`, `net/`, `bench/`).

## Layout
| Folder | Contents |
|---|---|
| `core/` | `kem.py` (ML-KEM wrapper, kyber-py / oqs backends), `kdf.py` (HKDF), `aead.py` (AES-GCM, counter nonces) |
| `net/` | `common.py`, `handshake.py` (mlkem / hybrid), `server.py`, `client.py`, `measure.py` (real byte/time measurement), `pcap_stats.py` |
| `attacks/` | `tamper.py` (ciphertext modification), `mitm.py` (man-in-the-middle) |
| `bench/` | `benchmark.py` (Exp. A, B), `stats.py`, `plot.py`, `summarize.py` (summary tables), `results/` |
| `tls/` | `run_tls_experiment.sh`, `tls_timing.py` (timing), `summarize_pcap.py` (Exp. C; needs OpenSSL >= 3.5 and tshark) |
| `tests/` | `test_kem.py`, `test_measure.py`, `test_kat.py` + `kat_runner.py`, `vectors/fetch_vectors.py` (NIST KAT) |
| `report/` | `lab_notebook.md` (template), place for pcap files and screenshots |

## Run everything with one command
```
python run_all.py --quick     # fast environment check (numbers are NOT for the report)
python run_all.py             # full run, produces report/results_summary.md
```
MITM and Wireshark/tshark capture must be done manually.

## Scenarios, step by step
1. **Scenario 1 - key establishment and encrypted chat**
   ```
   python -m net.server --mode mlkem --once                  # terminal 1
   python -m net.client --mode mlkem --message "hello"       # terminal 2
   ```
   Use `--mode hybrid` for X25519 + ML-KEM and `--param ML-KEM-512|768|1024`.
   Server and client MUST use the same mode and parameter set.
2. **Scenario 2 - performance**
   ```
   python -m bench.benchmark A --iters 200 --runs 5
   python -m bench.benchmark B --iters 200 --runs 5 --rsa
   python -m net.measure --iters 50                          # real bytes + time over TCP
   python -m bench.plot bench/results/exp*.csv
   python -m bench.summarize                                 # report/results_summary.md
   ```
   Native backend: `--backend oqs` (requires `liboqs` + `liboqs-python`; algorithm names must be `ML-KEM-xxx`).
   **Never merge** kyber-py tables with native tables.
3. **Scenario 3 - hybrid TLS 1.3** (Linux/WSL, OpenSSL >= 3.5, tshark)
   ```
   cd tls && ./run_tls_experiment.sh
   python -m tls.tls_timing --openssl /path/to/openssl      # from the project root
   ```
4. **Scenario 4 - security tests**
   ```
   python -m attacks.tamper --trials 100                     # ciphertext tampering
   python -m tests.vectors.fetch_vectors                     # download NIST vectors + MANIFEST.json
   python -m tests.kat_runner                                # pass/total per group, writes report/kat_summary.json
   ```
   MITM (3 terminals) is described at the top of `attacks/mitm.py` (add `--tamper` to modify messages).

### About the NIST KAT
The KAT validates the `kyber-py` LIBRARY (internal functions `_encaps_internal`, `_decaps_internal`, `key_derive`);
`core/kem.py` only wraps it. `ek_check` / `dk_check` are our own implementations of the FIPS 203 checks.

### Packet / segment counts (requires tshark)
Start a capture on the loopback adapter (`tshark -D` lists adapters; on Windows use the Npcap loopback adapter), then run
`python -m net.measure --port 5300` and `python -m net.pcap_stats <pcap> <order.json>`. See the top of `net/pcap_stats.py`.

## What to record in the lab notebook every run
Environment (`env_info.py` + RAM + physical/VM), parameters (warmup/iters/runs/backend), commit, RAW CSV/pcap files,
anomalies and fixes. Benchmark runs automatically save an `env_*.json` next to the results.

## Manual checks still required
- Cross-check the sizes in `core/kem.py` against FIPS 203.
- Verify the TLS group name (`X25519MLKEM768`) and OpenSSL commands with `openssl list -tls-groups`.
- Verify the tshark-based scripts on your machine (they were not tested in the original development environment).
