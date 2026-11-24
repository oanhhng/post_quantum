"""AES-256-GCM secure channel with counter nonces and one key per direction."""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_MESSAGES = 2**32  # safe limit for a 96-bit counter nonce in this demo


class SecureChannel:
    """Assumes an in-order, loss-free transport (TCP), so the nonce is an implicit counter.

    Replayed, reordered or modified messages fail decryption (InvalidTag).
    """

    def __init__(self, send_key: bytes, recv_key: bytes):
        self._send = AESGCM(send_key)
        self._recv = AESGCM(recv_key)
        self._send_ctr = 0
        self._recv_ctr = 0

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")

    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        if self._send_ctr >= MAX_MESSAGES:
            raise RuntimeError("nonce space exhausted; a new key exchange is required")
        out = self._send.encrypt(self._nonce(self._send_ctr), plaintext, aad)
        self._send_ctr += 1
        return out

    def open(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Raises cryptography.exceptions.InvalidTag if authentication fails."""
        out = self._recv.decrypt(self._nonce(self._recv_ctr), ciphertext, aad)
        self._recv_ctr += 1  # advance only on successful decryption
        return out
