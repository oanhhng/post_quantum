"""Session key derivation from the shared secret using HKDF-SHA256."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class SessionKeys:
    client_to_server: bytes
    server_to_client: bytes


def derive_session_keys(shared_secret: bytes, transcript: bytes, info: bytes) -> SessionKeys:
    """salt = SHA-256(transcript) binds the keys to the full handshake transcript.

    `info` should contain protocol label + mode + parameter set (domain separation).
    """
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hashlib.sha256(transcript).digest(),
        info=info,
    ).derive(shared_secret)
    return SessionKeys(okm[:32], okm[32:])
