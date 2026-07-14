"""Persist and read LLM query-run results.

Each run is one JSON file under ``querying/runs/`` (git-ignored). The web app's
stats and history views read these files; the pipeline writes them.
"""

import json
import os
from pathlib import Path

from . import config


def _runs_dir():
    config.RUNS_DIR.mkdir(parents=True, exist_ok=True)
    return config.RUNS_DIR


def save_run(run):
    """Write a run dict to ``runs/<run_id>.json`` and return the path.

    The write is **atomic** (temp file in the same dir + ``os.replace``): a
    run is checkpointed while it executes in the background, and a concurrent
    reader (the live run-status poller) must never observe a half-written
    file. ``os.replace`` swaps the file in as a single, atomic operation.
    """
    runs_dir = _runs_dir()
    path = runs_dir / f"{run['run_id']}.json"
    tmp = runs_dir / f".{run['run_id']}.json.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(run, handle, indent=2, default=str)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    return path


def load_run(run_id):
    """Load a single run by id, or ``None`` if it does not exist / is unreadable."""
    path = _runs_dir() / f"{run_id}.json"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError):
        # A transient partial read (or a corrupt file) is treated as "not
        # available yet" rather than crashing the caller.
        return None


def list_runs():
    """Return all runs, newest first (sorted by ``started_at``)."""
    runs = []
    for path in _runs_dir().glob("*.json"):
        try:
            with open(path, encoding="utf-8") as handle:
                runs.append(json.load(handle))
        except (json.JSONDecodeError, OSError):
            continue
    runs.sort(key=lambda r: r.get("started_at", ""), reverse=True)
    return runs


def runs_summary():
    """Aggregate cross-run totals for the landing-page statistics."""
    runs = list_runs()
    queries_completed = 0
    matches_found = 0
    models = set()
    best_score = 0.0
    for run in runs:
        for result in run.get("results", []):
            if "error" in result:
                continue
            queries_completed += 1
            models.add(result.get("model"))
            score = (result.get("best_match") or {}).get("jaccard_score", 0) or 0
            best_score = max(best_score, score)
            if result.get("leaked"):
                matches_found += 1
    return {
        "total_runs": len(runs),
        "queries_completed": queries_completed,
        "matches_found": matches_found,
        "models_used": sorted(m for m in models if m),
        "best_score": round(best_score, 4),
    }
