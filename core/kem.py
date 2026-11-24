"""ML-KEM wrapper with pluggable backends.

Unified interface:
    ek, dk = kem.keygen()
    ss, ct = kem.encaps(ek)
    ss     = kem.decaps(dk, ct)

Backends:
  - "kyber-py": pure Python, for learning and testing (slow, no side-channel protection).
  - "oqs"     : liboqs-python (native), for realistic performance benchmarks.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

PARAMS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
DEFAULT_PARAM = "ML-KEM-768"

# Sizes in bytes per FIPS 203. Cross-check against the official document.
SIZES = {
    "ML-KEM-512": {"ek": 800, "dk": 1632, "ct": 768, "ss": 32},
    "ML-KEM-768": {"ek": 1184, "dk": 2400, "ct": 1088, "ss": 32},
    "ML-KEM-1024": {"ek": 1568, "dk": 3168, "ct": 1568, "ss": 32},
}


class KEM(ABC):
    backend: str
    param: str

    @property
    def sizes(self) -> dict:
        return SIZES[self.param]

    @abstractmethod
    def keygen(self) -> tuple[bytes, bytes]: ...

    @abstractmethod
    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        """Return (shared_secret, ciphertext)."""

    @abstractmethod
    def decaps(self, dk: bytes, ct: bytes) -> bytes: ...

    def _check(self, name: str, data: bytes) -> None:
        expected = self.sizes[name]
        if len(data) != expected:
            raise ValueError(f"wrong {name} size: {len(data)} != {expected}")


class KyberPyKEM(KEM):
    backend = "kyber-py"

    def __init__(self, param: str):
        from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

        self.param = param
        self._impl = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}[param]

    def keygen(self):
        return self._impl.keygen()

    def encaps(self, ek):
        self._check("ek", ek)
        ss, ct = self._impl.encaps(ek)
        return ss, ct

    def decaps(self, dk, ct):
        self._check("dk", dk)
        self._check("ct", ct)
        return self._impl.decaps(dk, ct)


class OqsKEM(KEM):
    backend = "oqs"

    def __init__(self, param: str):
        import oqs  # liboqs-python

        self._oqs = oqs
        self.param = param
        enabled = oqs.get_enabled_kem_mechanisms()
        # Newer liboqs: "ML-KEM-768"; older: "Kyber768" (NOT compatible with FIPS 203)
        if param not in enabled:
            raise RuntimeError(
                f"liboqs does not support '{param}'. Available: {[m for m in enabled if 'KEM' in m or 'Kyber' in m]}"
            )

    def keygen(self):
        with self._oqs.KeyEncapsulation(self.param) as k:
            ek = k.generate_keypair()
            return ek, k.export_secret_key()

    def encaps(self, ek):
        self._check("ek", ek)
        with self._oqs.KeyEncapsulation(self.param) as k:
            ct, ss = k.encap_secret(ek)
            return ss, ct

    def decaps(self, dk, ct):
        self._check("dk", dk)
        self._check("ct", ct)
        with self._oqs.KeyEncapsulation(self.param, secret_key=dk) as k:
            return k.decap_secret(ct)


def get_kem(param: str = DEFAULT_PARAM, backend: str = "kyber-py") -> KEM:
    if param not in PARAMS:
        raise ValueError(f"param must be one of {PARAMS}")
    if backend == "kyber-py":
        return KyberPyKEM(param)
    if backend == "oqs":
        return OqsKEM(param)
    raise ValueError("backend must be 'kyber-py' or 'oqs'")
