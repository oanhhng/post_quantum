"""Scenario 1: ciphertext tampering -> demonstrates implicit rejection of the FO transform.

Run: python -m attacks.tamper --trials 100 --param ML-KEM-768
"""
from __future__ import annotations

import argparse
import secrets

from cryptography.exceptions import InvalidTag

from core.aead import SecureChannel
from core.kdf import derive_session_keys
from core.kem import DEFAULT_PARAM, PARAMS, get_kem


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--trials", type=int, default=100)
    p.add_argument("--param", choices=PARAMS, default=DEFAULT_PARAM)
    p.add_argument("--backend", choices=["kyber-py", "oqs"], default="kyber-py")
    args = p.parse_args()

    kem = get_kem(args.param, args.backend)
    ek, dk = kem.keygen()
    ss, ct = kem.encaps(ek)

    no_error = same_key = aead_fail = 0
    for _ in range(args.trials):
        bad = bytearray(ct)
        bad[secrets.randbelow(len(bad))] ^= 1 << secrets.randbelow(8)  # flip one random bit
        try:
            ss_bad = kem.decaps(dk, bytes(bad))
        except Exception as e:  # not expected
            print("Decaps raised an exception (unexpected):", repr(e))
            continue
        no_error += 1
        same_key += ss_bad == ss

        # Channel level: sender uses the true key, receiver uses the key from the tampered ct
        k_send = derive_session_keys(ss, ct, b"tamper-demo").client_to_server
        k_recv = derive_session_keys(ss_bad, ct, b"tamper-demo").client_to_server
        sender = SecureChannel(k_send, k_send)
        receiver = SecureChannel(k_recv, k_recv)
        try:
            receiver.open(sender.seal(b"hello"))
        except InvalidTag:
            aead_fail += 1

    n = args.trials
    print(f"Parameter set: {args.param} | backend: {kem.backend} | trials: {n}")
    print(f"- Decaps raised NO error             : {no_error}/{n}  (implicit rejection)")
    print(f"- Shared key equals the original key : {same_key}/{n}  (expected 0)")
    print(f"- AES-GCM authentication failed      : {aead_fail}/{n}  (expected {n})")
    print("Conclusion: the failure is NOT visible at the KEM layer; it surfaces at the AEAD layer.")


if __name__ == "__main__":
    main()
