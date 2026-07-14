"""Adversarial self-play service for the /selfplay page (Direction 2).

Thin adapter over the repo-root ``selfplay`` package (mirrors ``graph_intel.py``).
The page reads persisted artifacts (``selfplay/output/eval_report.json``, the
cost-to-evade ``curve.png``, the emergent-strategy log); a "Launch training" action
runs ``python -m selfplay {train,coevolve,ingest}`` as a **background subprocess**
(training is minutes-long and must not block the event loop — the same pattern the
Template Generator uses). The robust detector it produces is scored against the live
logdb for the /logs second-opinion panel.

Everything is guarded so the page degrades to an informative empty state when the
package/torch/artifacts are absent — the app never crashes because self-play hasn't
been run yet.
"""

import subprocess
import sys
import threading
import time

from .. import config

try:
    from selfplay import config as sp_config
    from selfplay import reporting as sp_reporting
    from selfplay import store as sp_store
    _IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - surfaced in the UI
    sp_config = sp_reporting = sp_store = None
    _IMPORT_ERROR = str(exc)


class SelfPlayError(RuntimeError):
    pass


# --- background job state ---------------------------------------------------
_JOB = {"status": "idle", "kind": None, "started": None, "ended": None, "returncode": None}
_LOCK = threading.Lock()


def available():
    return _IMPORT_ERROR is None


def torch_available():
    if not available():
        return False
    try:
        from crawler_graph.ml import gnn
        return gnn.torch_available()
    except Exception:
        return False


def _log_path():
    return sp_config.OUTPUT_DIR / "job.log"


def status():
    """Trainer + artifact status for the page header."""
    if not available():
        return {"available": False, "import_error": _IMPORT_ERROR}
    report = load_report()
    robust_exists = sp_config.ROBUST_DETECTOR.exists()
    with _LOCK:
        job = dict(_JOB)
    return {
        "available": True,
        "torch": torch_available(),
        "job": job,
        "has_report": report is not None,
        "robust_detector_trained": robust_exists,
        "last_summary": (report or {}).get("summary"),
        "kind": (report or {}).get("kind"),
    }


def load_report():
    if not available():
        return None
    return sp_reporting.read_eval_report()


def read_strategies(limit=200):
    if not available():
        return []
    return sp_reporting.read_strategies(limit=limit)


def list_runs(limit=25):
    if not available():
        return []
    return sp_store.list_runs(limit=limit)


def curve_path():
    if not available():
        return None
    p = sp_config.CURVE_PNG
    return p if p.exists() else None


def summary():
    """Compact headline metrics for the landing-page stats."""
    report = load_report()
    if not report:
        return None
    s = report.get("summary") or {}
    return {
        "evasion_lift": s.get("evasion_lift"),
        "final_evasion": s.get("final_evasion_rate"),
        "robust_auc": s.get("robust_val_auc"),
        "kind": report.get("kind"),
    }


# --- background launch ------------------------------------------------------
def _run_job(kind, args):
    log = _log_path()
    sp_config.ensure_output_dir()
    try:
        with open(log, "w", encoding="utf-8") as fh:
            proc = subprocess.Popen(
                [sys.executable, "-m", "selfplay", kind, *args],
                cwd=str(config.PROJECT_ROOT), stdout=fh, stderr=subprocess.STDOUT,
                env={**_env()},
            )
            rc = proc.wait()
    except Exception as exc:  # pragma: no cover
        rc = -1
        try:
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(f"\nlauncher error: {exc}\n")
        except OSError:
            pass
    with _LOCK:
        _JOB.update(status="done" if rc == 0 else "error",
                    ended=time.time(), returncode=rc)


def _env():
    import os
    e = dict(os.environ)
    e.setdefault("PROJECT_ROOT", str(config.PROJECT_ROOT))
    return e


def launch_training(kind="train", overrides=None):
    """Start a background self-play job. ``kind`` ∈ {train, coevolve, ingest}."""
    if not available():
        raise SelfPlayError(f"selfplay is not importable: {_IMPORT_ERROR}")
    if kind not in ("train", "coevolve", "ingest"):
        raise SelfPlayError(f"unknown job kind: {kind}")
    if kind in ("train", "coevolve") and not torch_available():
        raise SelfPlayError("torch/torch_geometric unavailable — cannot train in this environment.")
    with _LOCK:
        if _JOB["status"] == "running":
            raise SelfPlayError("a self-play job is already running.")
        _JOB.update(status="running", kind=kind, started=time.time(), ended=None, returncode=None)

    args = []
    for k, v in (overrides or {}).items():
        if v is None or v == "":
            continue
        args += [f"--{k.replace('_', '-')}", str(v)]
    if kind == "train":
        args.append("-v")
    threading.Thread(target=_run_job, args=(kind, args), daemon=True).start()
    return {"status": "running", "kind": kind}


def job_log(tail=8000):
    try:
        with open(_log_path(), encoding="utf-8") as fh:
            return fh.read()[-tail:]
    except OSError:
        return ""


# --- /logs second opinion ---------------------------------------------------
def score_live(threshold=0.5, since_hours=None):
    """Score current logdb endpoints with the robust detector → robust_predictions.json."""
    if not available():
        return {"ok": False, "reason": _IMPORT_ERROR}
    try:
        from selfplay import robust_detector
        return robust_detector.score_live(threshold=threshold, since_hours=since_hours)
    except Exception as exc:
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def load_robust_predictions():
    """Read the persisted second-opinion predictions for the /logs panel."""
    if not available():
        return None
    import json
    try:
        with open(sp_config.ROBUST_PREDS, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None
