"""Plot charts from CSV.   python -m bench.plot bench/results/expA_*.csv"""
from __future__ import annotations

import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd


def plot_a(df: pd.DataFrame, out: Path) -> None:
    pivot_m = df.pivot(index="algo", columns="op", values="median_us")
    pivot_e = df.pivot(index="algo", columns="op", values="stdev_us")
    ax = pivot_m.plot.bar(yerr=pivot_e, capsize=3, figsize=(8, 4.5))
    ax.set_ylabel("Median time (µs); error bars = std. dev.")
    ax.set_xlabel("Parameter set")
    ax.set_title(f"Experiment A - ML-KEM operation time by parameter set ({df['impl'].iloc[0]})")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(out, dpi=150)


def plot_b(df: pd.DataFrame, out: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    labels = [a.split(" (")[0] for a in df["algo"]]
    axes[0].bar(labels, df["median_us"], yerr=df["stdev_us"], capsize=3)
    axes[0].set_ylabel("Median time (µs, log scale)")
    axes[0].set_title("Key-establishment time")
    axes[0].set_yscale("log")
    axes[1].bar(labels, df["total_exchange_B"])
    axes[1].set_ylabel("Total bytes exchanged (both directions)")
    axes[1].set_title("Data transferred")
    for ax in axes:
        ax.tick_params(axis="x", rotation=15)
    fig.suptitle("Experiment B (note: different implementations - see the 'impl' column)")
    plt.tight_layout()
    plt.savefig(out, dpi=150)


def main() -> None:
    for name in sys.argv[1:]:
        path = Path(name)
        df = pd.read_csv(path)
        out = path.with_suffix(".png")
        (plot_a if df["experiment"].iloc[0] == "A" else plot_b)(df, out)
        print("->", out)


if __name__ == "__main__":
    main()
