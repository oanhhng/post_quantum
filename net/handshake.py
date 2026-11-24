"""Handshake protocol: plain ML-KEM or hybrid (X25519 + ML-KEM).

  Server -> Client : HDR || ek [|| x25519_pub_server]
  Client -> Server : HDR || ct [|| x25519_pub_client]
  Keys: HKDF(ss, salt=SHA256(msg1||msg2), info=PROTO|mode|param)
        ss = ss_mlkem            (mode mlkem)
        ss = ss_mlkem||ss_x25519 (mode hybrid)

WARNING: this is a LEARNING protocol. A KEM does not authenticate by itself: there is no
server authentication, so it is vulnerable to MITM (see attacks/mitm.py). It is not
compatible with any TLS specification.
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from core.aead import SecureChannel
from core.kdf import derive_session_keys
from core.kem import PARAMS, SIZES, get_kem
from net.common import FramedSocket

PROTO = b"mlkem-demo-v1"
MODES = {"mlkem": 1, "hybrid": 2}
MODE_NAME = {v: k for k, v in MODES.items()}
PARAM_ID = {p: i + 1 for i, p in enumerate(PARAMS)}
ID_PARAM = {v: k for k, v in PARAM_ID.items()}
HDR = struct.Struct(">BB")
X25519_LEN = 32


class HandshakeError(Exception):
    pass


@dataclass
class HandshakeResult:
    channel: SecureChannel
    mode: str
    param: str
    backend: str
    elapsed_s: float
    bytes_sent: int
    bytes_recv: int


def _header(mode: str, param: str) -> bytes:
    return HDR.pack(MODES[mode], PARAM_ID[param])


def _info(mode: str, param: str) -> bytes:
    return b"|".join([PROTO, mode.encode(), param.encode()])


def _split(msg: bytes, mode: str, param: str, kem_field: str) -> tuple[bytes, bytes]:
    """Check header + EXACT length; return (KEM part, X25519 part or b'')."""
    if len(msg) < HDR.size or msg[: HDR.size] != _header(mode, param):
        raise HandshakeError("header (mode/param) does not match the configuration")
    body = msg[HDR.size :]
    kem_len = SIZES[param][kem_field]
    expected = kem_len + (X25519_LEN if mode == "hybrid" else 0)
    if len(body) != expected:
        raise HandshakeError(f"wrong message length: {len(body)} != {expected}")
    return body[:kem_len], body[kem_len:]


def _combine(ss_kem: bytes, ss_x: bytes) -> bytes:
    return ss_kem + ss_x  # ss_x is empty in mlkem mode


def server_handshake(conn: FramedSocket, mode: str = "mlkem", param: str = "ML-KEM-768",
                     backend: str = "kyber-py") -> HandshakeResult:
    t0 = time.perf_counter()
    s0, r0 = conn.bytes_sent, conn.bytes_recv
    kem = get_kem(param, backend)

    ek, dk = kem.keygen()
    x_priv = X25519PrivateKey.generate() if mode == "hybrid" else None
    msg1 = _header(mode, param) + ek
    if x_priv:
        msg1 += x_priv.public_key().public_bytes_raw()
    conn.send_msg(msg1)

    msg2 = conn.recv_msg()
    ct, x_peer = _split(msg2, mode, param, "ct")
    ss_kem = kem.decaps(dk, ct)  # bad ct -> different key (implicit rejection), NO exception
    ss_x = x_priv.exchange(X25519PublicKey.from_public_bytes(x_peer)) if x_priv else b""

    keys = derive_session_keys(_combine(ss_kem, ss_x), msg1 + msg2, _info(mode, param))
    return HandshakeResult(
        SecureChannel(send_key=keys.server_to_client, recv_key=keys.client_to_server),
        mode, param, kem.backend, time.perf_counter() - t0,
        conn.bytes_sent - s0, conn.bytes_recv - r0,
    )


def client_handshake(conn: FramedSocket, mode: str = "mlkem", param: str = "ML-KEM-768",
                     backend: str = "kyber-py") -> HandshakeResult:
    t0 = time.perf_counter()
    s0, r0 = conn.bytes_sent, conn.bytes_recv
    kem = get_kem(param, backend)

    msg1 = conn.recv_msg()
    ek, x_peer = _split(msg1, mode, param, "ek")
    ss_kem, ct = kem.encaps(ek)

    msg2 = _header(mode, param) + ct
    ss_x = b""
    if mode == "hybrid":
        x_priv = X25519PrivateKey.generate()
        msg2 += x_priv.public_key().public_bytes_raw()
        ss_x = x_priv.exchange(X25519PublicKey.from_public_bytes(x_peer))
    conn.send_msg(msg2)

    keys = derive_session_keys(_combine(ss_kem, ss_x), msg1 + msg2, _info(mode, param))
    return HandshakeResult(
        SecureChannel(send_key=keys.client_to_server, recv_key=keys.server_to_client),
        mode, param, kem.backend, time.perf_counter() - t0,
        conn.bytes_sent - s0, conn.bytes_recv - r0,
    )
