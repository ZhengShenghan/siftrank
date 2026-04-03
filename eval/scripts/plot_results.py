#!/usr/bin/env python3
"""Generate paper-ready plots from evaluation results."""

import glob
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
PLOTS_DIR = os.path.join(RESULTS_DIR, "plots")


def load_summaries(results_dir):
    """Load all summary JSON files, keyed by vuln_type."""
    summaries = {}
    for path in sorted(glob.glob(os.path.join(results_dir, "*_summary.json"))):
        with open(path) as f:
            data = json.load(f)
        key = data["config"]["vuln_type"]
        # If multiple runs for same vuln_type, keep latest
        summaries[key] = data
    return summaries


def load_per_function_results(results_dir):
    """Load all JSONL result files, keyed by vuln_type."""
    results = {}
    for path in sorted(glob.glob(os.path.join(results_dir, "*_results.jsonl"))):
        # Infer vuln_type from matching summary
        summary_path = path.replace("_results.jsonl", "_summary.json")
        if os.path.exists(summary_path):
            with open(summary_path) as f:
                meta = json.load(f)
            key = meta["config"]["vuln_type"]
        else:
            continue

        entries = []
        with open(path) as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))
        results[key] = entries
    return results


# --- Plot helpers ---

LABELS = {"any": "Any CWE", "specific": "Correct CWE", "wrong": "Wrong CWE"}
COLORS = {"any": "#4C72B0", "specific": "#55A868", "wrong": "#C44E52"}
ORDER = ["any", "specific", "wrong"]


def _bar_chart(ax, keys, values, title, ylabel, fmt=".3f"):
    x = np.arange(len(keys))
    labels = [LABELS.get(k, k) for k in keys]
    colors = [COLORS.get(k, "#999") for k in keys]
    bars = ax.bar(x, values, color=colors, width=0.5, edgecolor="white", linewidth=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.005,
                f"{val:{fmt}}", ha="center", va="bottom", fontsize=9)


def plot_classification_metrics(summaries, out_dir):
    """Bar chart comparing accuracy, precision, recall, F1, MCC across experiments."""
    keys = [k for k in ORDER if k in summaries]
    metrics = ["accuracy", "balanced_accuracy", "precision", "recall", "f1", "specificity", "mcc"]
    labels_map = {
        "accuracy": "Accuracy", "balanced_accuracy": "Balanced\nAccuracy",
        "precision": "Precision", "recall": "Recall", "f1": "F1",
        "specificity": "Specificity", "mcc": "MCC",
    }

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(metrics))
    width = 0.22
    offsets = np.linspace(-width, width, len(keys))

    for i, k in enumerate(keys):
        s = summaries[k]
        vals = [s.get(m, 0) or 0 for m in metrics]
        bars = ax.bar(x + offsets[i], vals, width, label=LABELS[k], color=COLORS[k],
                       edgecolor="white", linewidth=0.5)

    ax.set_xticks(x)
    ax.set_xticklabels([labels_map[m] for m in metrics])
    ax.set_ylabel("Score")
    ax.set_title("Classification Metrics by Prompt Type (gpt-5-nano)")
    ax.legend()
    ax.axhline(y=0.5, color="gray", linestyle="--", alpha=0.5, label="Random baseline")
    ax.set_ylim(0, 1.05)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "classification_metrics.png"), dpi=200)
    fig.savefig(os.path.join(out_dir, "classification_metrics.pdf"))
    plt.close(fig)
    print("Saved classification_metrics.png/pdf")


def plot_confusion_matrices(summaries, out_dir):
    """Side-by-side confusion matrices."""
    keys = [k for k in ORDER if k in summaries]
    fig, axes = plt.subplots(1, len(keys), figsize=(4 * len(keys), 3.5))
    if len(keys) == 1:
        axes = [axes]

    for ax, k in zip(axes, keys):
        s = summaries[k]
        tp = s.get("true_positives", 0)
        fp = s.get("false_positives", 0)
        tn = s.get("true_negatives", 0)
        fn = s.get("false_negatives", 0)
        cm = np.array([[tp, fn], [fp, tn]])
        total = cm.sum()

        im = ax.imshow(cm, cmap="Blues", vmin=0, vmax=total / 2)
        for i in range(2):
            for j in range(2):
                color = "white" if cm[i, j] > total / 4 else "black"
                ax.text(j, i, f"{cm[i, j]}\n({cm[i, j]/total:.1%})",
                        ha="center", va="center", fontsize=10, color=color)

        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Vuln", "Safe"])
        ax.set_yticklabels(["Vuln", "Safe"])
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        ax.set_title(LABELS[k])

    fig.suptitle("Confusion Matrices (gpt-5-nano)", fontsize=13)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "confusion_matrices.png"), dpi=200)
    fig.savefig(os.path.join(out_dir, "confusion_matrices.pdf"))
    plt.close(fig)
    print("Saved confusion_matrices.png/pdf")


def plot_token_usage(summaries, out_dir):
    """Stacked bar chart of token usage (input, output, reasoning)."""
    keys = [k for k in ORDER if k in summaries]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = np.arange(len(keys))
    width = 0.4

    input_t = [summaries[k]["total_input_tokens"] / 1e6 for k in keys]
    output_t = [summaries[k]["total_output_tokens"] / 1e6 for k in keys]
    reasoning_t = [summaries[k].get("total_reasoning_tokens", 0) / 1e6 for k in keys]

    ax.bar(x, input_t, width, label="Input", color="#4C72B0")
    ax.bar(x, output_t, width, bottom=input_t, label="Output", color="#55A868")
    bottoms = [i + o for i, o in zip(input_t, output_t)]
    if any(r > 0 for r in reasoning_t):
        ax.bar(x, reasoning_t, width, bottom=bottoms, label="Reasoning", color="#C44E52")

    ax.set_xticks(x)
    ax.set_xticklabels([LABELS[k] for k in keys])
    ax.set_ylabel("Tokens (millions)")
    ax.set_title("Token Usage by Prompt Type (gpt-5-nano)")
    ax.legend()
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "token_usage.png"), dpi=200)
    fig.savefig(os.path.join(out_dir, "token_usage.pdf"))
    plt.close(fig)
    print("Saved token_usage.png/pdf")


def plot_latency_distribution(per_func, out_dir):
    """Overlapping histograms of per-call latency."""
    keys = [k for k in ORDER if k in per_func]
    fig, ax = plt.subplots(figsize=(8, 4.5))

    for k in keys:
        latencies = [r["latency_ms"] / 1000 for r in per_func[k] if r["latency_ms"] > 0]
        ax.hist(latencies, bins=50, alpha=0.5, label=LABELS[k], color=COLORS[k], edgecolor="white")

    ax.set_xlabel("Latency (seconds)")
    ax.set_ylabel("Count")
    ax.set_title("Per-Call Latency Distribution (gpt-5-nano)")
    ax.legend()
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "latency_distribution.png"), dpi=200)
    fig.savefig(os.path.join(out_dir, "latency_distribution.pdf"))
    plt.close(fig)
    print("Saved latency_distribution.png/pdf")


def plot_timing_and_throughput(summaries, out_dir):
    """Bar charts for wall clock time and throughput."""
    keys = [k for k in ORDER if k in summaries]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9, 4))

    # Wall clock
    wall = [summaries[k]["wall_clock_sec"] / 60 for k in keys]
    _bar_chart(ax1, keys, wall, "Wall Clock Time", "Minutes", ".1f")

    # Throughput RPM
    rpm = [summaries[k]["throughput_rpm"] for k in keys]
    _bar_chart(ax2, keys, rpm, "Throughput", "Requests / min", ".0f")

    fig.suptitle("Performance (gpt-5-nano)", fontsize=13)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "timing_throughput.png"), dpi=200)
    fig.savefig(os.path.join(out_dir, "timing_throughput.pdf"))
    plt.close(fig)
    print("Saved timing_throughput.png/pdf")


def plot_output_tokens_vs_latency(per_func, out_dir):
    """Scatter plot: output tokens vs latency, colored by experiment."""
    keys = [k for k in ORDER if k in per_func]
    fig, ax = plt.subplots(figsize=(8, 5))

    for k in keys:
        tokens = [r["output_tokens"] for r in per_func[k] if r["output_tokens"] > 0]
        latency = [r["latency_ms"] / 1000 for r in per_func[k] if r["output_tokens"] > 0]
        ax.scatter(tokens, latency, alpha=0.15, s=8, label=LABELS[k], color=COLORS[k])

    ax.set_xlabel("Output Tokens")
    ax.set_ylabel("Latency (seconds)")
    ax.set_title("Output Tokens vs Latency (gpt-5-nano)")
    ax.legend(markerscale=3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "tokens_vs_latency.png"), dpi=200)
    fig.savefig(os.path.join(out_dir, "tokens_vs_latency.pdf"))
    plt.close(fig)
    print("Saved tokens_vs_latency.png/pdf")


def main():
    os.makedirs(PLOTS_DIR, exist_ok=True)

    summaries = load_summaries(RESULTS_DIR)
    per_func = load_per_function_results(RESULTS_DIR)

    print(f"Loaded {len(summaries)} experiments: {list(summaries.keys())}")

    plot_classification_metrics(summaries, PLOTS_DIR)
    plot_confusion_matrices(summaries, PLOTS_DIR)
    plot_token_usage(summaries, PLOTS_DIR)
    plot_latency_distribution(per_func, PLOTS_DIR)
    plot_timing_and_throughput(summaries, PLOTS_DIR)
    plot_output_tokens_vs_latency(per_func, PLOTS_DIR)

    print(f"\nAll plots saved to {PLOTS_DIR}/")


if __name__ == "__main__":
    main()
