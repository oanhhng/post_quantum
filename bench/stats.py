"""Timing with warm-up and statistics (mean/median/stdev/p95/p99)."""
from __future__ import annotations

import gc
import statistics as st
import time
from typing import Callable


def percentile(sorted_vals: list[float], q: float) -> float:
    """Linearly interpolated percentile (q in [0, 100])."""
    if not sorted_vals:
        raise ValueError("empty input")
    k = (len(sorted_vals) - 1) * q / 100
    lo, hi = int(k), min(int(k) + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def measure(fn: Callable[[], object], warmup: int, iters: int, runs: int) -> dict:
    """Take `runs` independent runs of `iters` timed calls, each after `warmup` untimed calls.

    Times are in microseconds. Returns statistics over all samples plus the standard
    deviation of the per-run medians (a stability indicator).
    """
    all_samples: list[float] = []
    run_medians: list[float] = []
    for _ in range(runs):
        for _ in range(warmup):
            fn()
        gc_was_enabled = gc.isenabled()
        gc.disable()  # reduce garbage-collector noise
        try:
            samples = []
            for _ in range(iters):
                t0 = time.perf_counter_ns()
                fn()
                samples.append((time.perf_counter_ns() - t0) / 1e3)
        finally:
            if gc_was_enabled:
                gc.enable()
        run_medians.append(st.median(samples))
        all_samples.extend(samples)

    s = sorted(all_samples)
    return {
        "n": len(s),
        "mean_us": st.fmean(s),
        "median_us": st.median(s),
        "stdev_us": st.stdev(s) if len(s) > 1 else 0.0,
        "p95_us": percentile(s, 95),
        "p99_us": percentile(s, 99),
        "min_us": s[0],
        "run_median_stdev_us": st.stdev(run_medians) if len(run_medians) > 1 else 0.0,
    }
