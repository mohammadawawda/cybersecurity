#!/usr/bin/env python3
"""Plot mixnet benchmark results.

Reads the tidy CSV produced by `go run ./bench` and emits the figures:
each metric (preparation time, per-round mix latency,
end-to-end latency) plotted against both the number of clients and the
plaintext size, with the encrypted/mixed system overlaid on an
unencrypted/unmixed baseline. Every plot has a title, axis labels (with units),
and a legend.

Usage:
    python3 scripts/plot.py [--csv bench/results.csv] [--outdir bench/plots]

Depends only on matplotlib (no pandas).
"""
import argparse
import csv
import os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

METRIC_LABEL = {
    "prep": "Message preparation",
    "mix_layer": "Mix decrypt + forward (one round, one hop)",
    "end_to_end": "End-to-end delivery (whole round)",
}
METRIC_ORDER = ["prep", "mix_layer", "end_to_end"]


def load(path):
    """rows[(metric, sweep, encrypted)] -> sorted list of (x, mean_us)."""
    rows = defaultdict(list)
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            key = (r["metric"], r["sweep"], int(r["encrypted"]))
            rows[key].append((int(r["x"]), float(r["mean_us"])))
    for k in rows:
        rows[k].sort()
    return rows


def _series(rows, metric, sweep, enc):
    pts = rows.get((metric, sweep, enc), [])
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    return xs, ys


def sweep_figure(rows, sweep, xlabel, title, outfile):
    """One row of three panels (one per metric); encrypted vs baseline, log-y."""
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6))
    for ax, metric in zip(axes, METRIC_ORDER):
        ex, ey = _series(rows, metric, sweep, 1)
        bx, by = _series(rows, metric, sweep, 0)
        if ex:
            ax.plot(ex, ey, "o-", color="#1f77b4", linewidth=2,
                    markersize=6, label="encrypted + mixed")
        if bx:
            ax.plot(bx, by, "s--", color="#d62728", linewidth=1.6,
                    markersize=5, label="unencrypted baseline")
        ax.set_yscale("log")
        ax.set_title(METRIC_LABEL[metric], fontsize=11)
        ax.set_xlabel(xlabel)
        ax.set_ylabel("mean latency (microseconds, log scale)")
        ax.grid(True, which="both", linestyle=":", alpha=0.5)
        ax.legend(fontsize=9)
        if sweep == "clients":
            ax.set_xticks(ex or bx)
    fig.suptitle(title, fontsize=13, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(outfile, dpi=130)
    plt.close(fig)
    return outfile


def e2e_scaling_figure(rows, outfile):
    """Focused linear plot: end-to-end latency vs clients (encrypted only)."""
    fig, ax = plt.subplots(figsize=(7, 4.6))
    ex, ey = _series(rows, "end_to_end", "clients", 1)
    ax.plot(ex, ey, "o-", color="#2ca02c", linewidth=2.2, markersize=7,
            label="end-to-end (3-hop cascade)")
    # annotate per-message cost
    for x, y in zip(ex, ey):
        ax.annotate(f"{y/1000:.2f} ms", (x, y), textcoords="offset points",
                    xytext=(0, 9), ha="center", fontsize=9)
    ax.set_title("End-to-end latency scales linearly with batch size",
                 fontsize=12, fontweight="bold")
    ax.set_xlabel("number of clients (= messages per round)")
    ax.set_ylabel("mean end-to-end latency (microseconds)")
    ax.set_xticks(ex)
    ax.grid(True, linestyle=":", alpha=0.5)
    ax.legend()
    fig.tight_layout()
    fig.savefig(outfile, dpi=130)
    plt.close(fig)
    return outfile


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="bench/results.csv")
    ap.add_argument("--outdir", default="bench/plots")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    rows = load(args.csv)

    made = []
    made.append(sweep_figure(
        rows, "clients",
        "number of clients (= messages per round)",
        "Latency vs number of clients (plaintext fixed at 256 bytes)",
        os.path.join(args.outdir, "bench_clients.png")))
    made.append(sweep_figure(
        rows, "payload",
        "plaintext size (bytes); on-wire size constant at 1024",
        "Latency vs plaintext size (2 clients) — flat curves confirm "
        "size-independence",
        os.path.join(args.outdir, "bench_payload.png")))
    made.append(e2e_scaling_figure(
        rows, os.path.join(args.outdir, "bench_e2e_scaling.png")))

    for m in made:
        print("wrote", m)


if __name__ == "__main__":
    main()
