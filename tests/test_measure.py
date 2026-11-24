"""Tests for the measurement/statistics helpers (no external network needed)."""
import pytest

from bench.stats import measure, percentile
from net.measure import expected_bytes, run_config


def test_percentile_interpolation():
    assert percentile([1, 2, 3, 4], 0) == 1
    assert percentile([1, 2, 3, 4], 100) == 4
    assert percentile([1, 2, 3, 4], 50) == pytest.approx(2.5)


def test_measure_returns_all_stats():
    r = measure(lambda: sum(range(100)), warmup=2, iters=20, runs=2)
    assert r["n"] == 40
    assert r["min_us"] <= r["median_us"] <= r["p95_us"] <= r["p99_us"]
    assert {"mean_us", "stdev_us", "run_median_stdev_us"} <= r.keys()


@pytest.mark.parametrize("mode", ["mlkem", "hybrid"])
def test_measured_bytes_match_formula(mode):
    rows = run_config(mode, "ML-KEM-512", "kyber-py", "127.0.0.1", 0 if False else 5390, 2)
    exp_s, exp_r = expected_bytes(mode, "ML-KEM-512")
    assert all((r["sent_B"], r["recv_B"]) == (exp_s, exp_r) for r in rows)


def test_expected_bytes_values_768():
    assert expected_bytes("mlkem", "ML-KEM-768") == (4 + 2 + 1088, 4 + 2 + 1184)
    assert expected_bytes("hybrid", "ML-KEM-768") == (4 + 2 + 1088 + 32, 4 + 2 + 1184 + 32)
    assert expected_bytes("x25519", "-") == (36, 36)
