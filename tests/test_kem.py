"""Unit + integration tests. Run: pytest -v"""
import socket
import threading

import pytest
from cryptography.exceptions import InvalidTag

from core.aead import SecureChannel
from core.kdf import derive_session_keys
from core.kem import PARAMS, SIZES, get_kem
from net.common import FramedSocket
from net.handshake import HandshakeError, client_handshake, server_handshake


@pytest.mark.parametrize("param", PARAMS)
def test_roundtrip_and_sizes(param):
    kem = get_kem(param)
    ek, dk = kem.keygen()
    ss, ct = kem.encaps(ek)
    assert kem.decaps(dk, ct) == ss
    assert (len(ek), len(dk), len(ct), len(ss)) == tuple(SIZES[param][k] for k in ("ek", "dk", "ct", "ss"))


def test_tampered_ciphertext_gives_different_key_without_error():
    kem = get_kem("ML-KEM-768")
    ek, dk = kem.keygen()
    ss, ct = kem.encaps(ek)
    bad = bytearray(ct)
    bad[0] ^= 1
    assert kem.decaps(dk, bytes(bad)) != ss


def test_wrong_secret_key_gives_different_key():
    kem = get_kem("ML-KEM-768")
    ek, _ = kem.keygen()
    _, dk2 = kem.keygen()
    ss, ct = kem.encaps(ek)
    assert kem.decaps(dk2, ct) != ss


def test_wrong_sizes_rejected():
    kem = get_kem("ML-KEM-768")
    with pytest.raises(ValueError):
        kem.encaps(b"short")


def test_kdf_deterministic_and_context_bound():
    a = derive_session_keys(b"s" * 32, b"t", b"i")
    assert a == derive_session_keys(b"s" * 32, b"t", b"i")
    assert a != derive_session_keys(b"s" * 32, b"t2", b"i")
    assert a != derive_session_keys(b"s" * 32, b"t", b"i2")
    assert a.client_to_server != a.server_to_client


def test_aead_roundtrip_tamper_and_replay():
    k = b"k" * 32
    tx, rx = SecureChannel(k, k), SecureChannel(k, k)
    m1 = tx.seal(b"one")
    assert rx.open(m1) == b"one"
    with pytest.raises(InvalidTag):  # replay -> different expected nonce
        rx.open(m1)
    m2 = bytearray(tx.seal(b"two"))
    m2[0] ^= 1
    with pytest.raises(InvalidTag):
        rx.open(bytes(m2))


def _handshake_pair(mode, param, server_mode=None, server_param=None):
    a, b = socket.socketpair()
    a.settimeout(60); b.settimeout(60)
    out = {}

    def srv():
        try:
            with FramedSocket(a) as c:
                out["srv"] = server_handshake(c, server_mode or mode, server_param or param)
        except Exception as e:  # noqa: BLE001
            out["srv_err"] = e

    t = threading.Thread(target=srv)
    t.start()
    try:
        with FramedSocket(b) as c:
            out["cli"] = client_handshake(c, mode, param)
    except Exception as e:  # noqa: BLE001
        out["cli_err"] = e
    t.join()
    return out


@pytest.mark.parametrize("mode", ["mlkem", "hybrid"])
def test_handshake_and_chat(mode):
    out = _handshake_pair(mode, "ML-KEM-512")
    assert "srv" in out and "cli" in out, out
    msg = out["cli"].channel.seal(b"hello")
    assert out["srv"].channel.open(msg) == b"hello"
    assert out["cli"].channel.open(out["srv"].channel.seal(b"world")) == b"world"


def test_handshake_mismatch_rejected():
    out = _handshake_pair("mlkem", "ML-KEM-512", server_mode="hybrid")
    assert isinstance(out.get("cli_err"), HandshakeError)


def test_hybrid_message_sizes_768():
    out = _handshake_pair("hybrid", "ML-KEM-768")
    # server->client: 4 (len) + 2 (hdr) + 1184 (ek) + 32 (x25519)
    assert out["cli"].bytes_recv == 4 + 2 + 1184 + 32
    # client->server: 4 + 2 + 1088 (ct) + 32
    assert out["cli"].bytes_sent == 4 + 2 + 1088 + 32
