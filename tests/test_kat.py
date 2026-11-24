"""NIST ACVP known-answer tests (FIPS 203). Skipped if vectors are missing: python -m tests.vectors.fetch_vectors"""
import pytest

from tests import kat_runner

pytestmark = pytest.mark.skipif(not kat_runner.vectors_available(),
                                reason="ACVP vectors not downloaded (python -m tests.vectors.fetch_vectors)")


@pytest.fixture(scope="module")
def results():
    return kat_runner.run_all()


@pytest.mark.parametrize("prefix", ["keyGen", "encapsulation ", "decapsulation ",
                                    "encapsulationKeyCheck", "decapsulationKeyCheck"])
def test_kat_group(results, prefix):
    groups = {k: v for k, v in results.items() if k.startswith(prefix)}
    assert groups, f"no test group {prefix}"
    for name, r in groups.items():
        assert r["pass"] == r["total"], f"{name}: failed tcId={r['failed']}"


def test_key_derive_is_deterministic():
    from kyber_py.ml_kem import ML_KEM_768

    seed = bytes(range(64))
    assert ML_KEM_768.key_derive(seed) == ML_KEM_768.key_derive(seed)
