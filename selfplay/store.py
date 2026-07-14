"""Persist / list self-play run records (mirrors ``querying/store.py``'s contract
so a future unified history view is trivial). One JSON per run under
``selfplay/output/runs/``; the latest also updates ``eval_report.json``."""

import json
import time
import uuid

from . import config


def new_run_id():
    return f"sp-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"


def save_run(record):
    config.ensure_output_dir()
    rid = record.get("run_id") or new_run_id()
    record["run_id"] = rid
    record.setdefault("created_at", time.time())
    path = config.RUNS_DIR / f"{rid}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, default=str)
    return rid


def load_run(rid):
    path = config.RUNS_DIR / f"{rid}.json"
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def list_runs(limit=50):
    if not config.RUNS_DIR.exists():
        return []
    files = sorted(config.RUNS_DIR.glob("sp-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    out = []
    for p in files[:limit]:
        try:
            with open(p, encoding="utf-8") as fh:
                r = json.load(fh)
            out.append({
                "run_id": r.get("run_id"),
                "created_at": r.get("created_at"),
                "kind": r.get("kind", "train"),
                "final_evasion": (r.get("summary") or {}).get("final_evasion_rate"),
                "final_D": (r.get("summary") or {}).get("final_mean_D"),
                "baseline_evasion": (r.get("summary") or {}).get("baseline_evasion_rate"),
            })
        except (OSError, json.JSONDecodeError):
            continue
    return out


def runs_summary():
    runs = list_runs(limit=1000)
    return {"total_runs": len(runs), "last": runs[0] if runs else None}
