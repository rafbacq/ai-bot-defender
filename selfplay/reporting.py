"""Persisted artifacts for the app: the eval report, the emergent-strategy log, and
the cost-to-evade curve PNG (matplotlib is optional — imported lazily, like
``crawler_graph.reporting``)."""

import json

from . import config


def write_eval_report(payload):
    config.ensure_output_dir()
    with open(config.EVAL_REPORT, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return str(config.EVAL_REPORT)


def read_eval_report():
    try:
        with open(config.EVAL_REPORT, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def append_strategy(entry):
    """Append one line to the emergent-strategy autocurriculum log."""
    config.ensure_output_dir()
    with open(config.STRATEGIES_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, default=str) + "\n")


def read_strategies(limit=200):
    out = []
    try:
        with open(config.STRATEGIES_LOG, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        return out[-limit:]
    return out[-limit:]


def render_curve(history, curve, path=None):
    """Render training curves + the cost-to-evade curve. Returns the path or None
    when matplotlib is unavailable."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return None
    path = str(path or config.CURVE_PNG)
    config.ensure_output_dir()
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.2))

    it = [h["iter"] for h in history]
    axes[0].plot(it, [h["mean_D"] for h in history], color="#B91C1C", label="mean detector D")
    axes[0].plot(it, [h["evasion_rate"] for h in history], color="#0F766E", label="evasion rate")
    axes[0].set_title("Attacker learning"); axes[0].set_xlabel("iteration")
    axes[0].legend(fontsize=8); axes[0].grid(alpha=0.3)

    ax2 = axes[1]
    ax2.plot(it, [h["mean_harvest"] for h in history], color="#B45309", label="harvest")
    ax2.set_xlabel("iteration"); ax2.set_ylabel("harvest", color="#B45309")
    ax2b = ax2.twinx()
    ax2b.plot(it, [h["lambda"] for h in history], color="#6D28D9", label="λ (dual)")
    ax2b.set_ylabel("λ", color="#6D28D9")
    ax2.set_title("Harvest vs. detection shadow price"); ax2.grid(alpha=0.3)

    if curve:
        infra = [r["infra_cost"] for r in curve]
        axes[2].plot(infra, [r["evasion_rate"] for r in curve], "o-", color="#0F766E", label="evasion")
        axes[2].plot(infra, [r["mean_D"] for r in curve], "s--", color="#B91C1C", label="mean D")
        for r in curve:
            axes[2].annotate(r["stack"], (r["infra_cost"], r["evasion_rate"]),
                             fontsize=6, rotation=20, ha="left", va="bottom")
        axes[2].set_title("Cost-to-evade curve"); axes[2].set_xlabel("infrastructure cost")
        axes[2].legend(fontsize=8); axes[2].grid(alpha=0.3)

    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)
    return path
