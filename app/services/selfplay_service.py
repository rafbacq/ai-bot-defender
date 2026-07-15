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

import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import CancelledError

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


class SelfPlayForbidden(SelfPlayError):
    pass


# --- background job state ---------------------------------------------------
_JOB = {
    "id": None, "status": "idle", "kind": None, "started": None,
    "updated": None, "ended": None, "returncode": None, "owner": None,
}
_LOCK = threading.Lock()
_PROC = None
_CANCEL_EVENT = threading.Event()


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
        job = {key: value for key, value in _JOB.items() if key != "owner"}
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
def _run_job(kind, args, job_id, cancel_event):
    global _PROC
    log = _log_path()
    sp_config.ensure_output_dir()
    try:
        with open(log, "w", encoding="utf-8") as fh:
            proc = subprocess.Popen(
                [sys.executable, "-m", "selfplay", kind, *args],
                cwd=str(config.PROJECT_ROOT), stdout=fh, stderr=subprocess.STDOUT,
                env={**_env()},
                start_new_session=True,
            )
            with _LOCK:
                if _JOB.get("id") == job_id:
                    _PROC = proc
                cancel_now = cancel_event.is_set()
            if cancel_now:
                _terminate_process(proc)
            rc = proc.wait()
    except Exception as exc:  # pragma: no cover
        rc = -1
        try:
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(f"\nlauncher error: {exc}\n")
        except OSError:
            pass
    with _LOCK:
        if _JOB.get("id") == job_id:
            cancelled = cancel_event.is_set()
            _PROC = None
            _JOB.update(
                status="cancelled" if cancelled else "done" if rc == 0 else "error",
                ended=time.time(), updated=time.time(), returncode=rc,
            )


def _run_score_job(job_id, cancel_event):
    """Background wrapper for the page's robust live-scoring action."""
    log = _log_path()
    sp_config.ensure_output_dir()

    def cancel_check():
        if cancel_event.is_set():
            raise CancelledError("Cancelled by user.")

    try:
        with open(log, "w", encoding="utf-8") as fh:
            fh.write("Scoring current traffic with the robust detector…\n")
        result = score_live(cancel_check=cancel_check)
        cancel_check()
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(result, indent=2, default=str) + "\n")
        ok = bool(result.get("ok"))
        error = None if ok else result.get("reason")
    except CancelledError:
        ok, error = False, None
    except Exception as exc:  # pragma: no cover - surfaced in status/log
        ok, error = False, f"{type(exc).__name__}: {exc}"
    with _LOCK:
        if _JOB.get("id") == job_id:
            cancelled = cancel_event.is_set()
            _JOB.update(
                status="cancelled" if cancelled else "done" if ok else "error",
                ended=time.time(), updated=time.time(), returncode=None,
            )
    if error:
        try:
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(f"\nScoring failed: {error}\n")
        except OSError:
            pass


def _env():
    e = dict(os.environ)
    e.setdefault("PROJECT_ROOT", str(config.PROJECT_ROOT))
    return e


def _begin(kind, owner):
    global _CANCEL_EVENT
    with _LOCK:
        if _JOB["status"] in ("running", "cancelling"):
            raise SelfPlayError("a self-play job is already running.")
        _CANCEL_EVENT = threading.Event()
        now = time.time()
        _JOB.update(
            id=uuid.uuid4().hex[:16], status="running", kind=kind,
            started=now, updated=now, ended=None, returncode=None, owner=owner,
        )
        return _JOB["id"], _CANCEL_EVENT


def launch_training(kind="train", overrides=None, owner=None):
    """Start a background self-play job. ``kind`` ∈ {train, coevolve, ingest}."""
    if not available():
        raise SelfPlayError(f"selfplay is not importable: {_IMPORT_ERROR}")
    if kind not in ("train", "coevolve", "ingest"):
        raise SelfPlayError(f"unknown job kind: {kind}")
    if kind in ("train", "coevolve") and not torch_available():
        raise SelfPlayError("torch/torch_geometric unavailable — cannot train in this environment.")
    job_id, cancel_event = _begin(kind, owner)

    args = []
    for k, v in (overrides or {}).items():
        if v is None or v == "":
            continue
        args += [f"--{k.replace('_', '-')}", str(v)]
    if kind == "train":
        args.append("-v")
    threading.Thread(
        target=_run_job, args=(kind, args, job_id, cancel_event), daemon=True,
    ).start()
    return {"id": job_id, "status": "running", "kind": kind}


def launch_score(owner=None):
    """Run robust live scoring in the same single-job lifecycle as training."""
    if not available():
        raise SelfPlayError(f"selfplay is not importable: {_IMPORT_ERROR}")
    if not sp_config.ROBUST_DETECTOR.exists():
        raise SelfPlayError("Train a robust detector before scoring live traffic.")
    job_id, cancel_event = _begin("score-live", owner)
    threading.Thread(
        target=_run_score_job, args=(job_id, cancel_event),
        name="selfplay-score-live", daemon=True,
    ).start()
    return {"id": job_id, "status": "running", "kind": "score-live"}


def _terminate_process(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, OSError):
        try:
            proc.terminate()
        except (ProcessLookupError, OSError):
            pass

    def escalate():
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass

    timer = threading.Timer(4.0, escalate)
    timer.daemon = True
    timer.start()


def cancel_job(*, requester=None, is_admin=False):
    """Cancel the one active self-play/scoring job; idempotent when terminal."""
    with _LOCK:
        owner = _JOB.get("owner")
        if not (is_admin or owner is None or (requester and requester == owner)):
            raise SelfPlayForbidden("This job belongs to a different account.")
        if _JOB["status"] not in ("running", "cancelling"):
            return {key: value for key, value in _JOB.items() if key != "owner"}
        _CANCEL_EVENT.set()
        _JOB["status"] = "cancelling"
        _JOB["updated"] = time.time()
        proc = _PROC
        snapshot = {key: value for key, value in _JOB.items() if key != "owner"}
    _terminate_process(proc)
    return snapshot


def active_job(*, requester=None, is_admin=False):
    """Normalized active state for the app-wide job center."""
    with _LOCK:
        owner = _JOB.get("owner")
        if not (is_admin or owner is None or (requester and requester == owner)):
            return None
        if _JOB.get("status") not in {"running", "cancelling"}:
            return None
        kind = _JOB.get("kind") or "self-play"
        return {
            "id": _JOB.get("id") or "selfplay",
            "kind": kind,
            "status": _JOB.get("status"),
            "label": (
                "Stopping adversarial job…" if _JOB.get("status") == "cancelling"
                else "Scoring current traffic…" if kind == "score-live"
                else f"Adversarial {kind} is running…"
            ),
            "started": _JOB.get("started"),
            "updated": _JOB.get("updated") or _JOB.get("started"),
            "href": "/selfplay",
        }


def job_log(tail=8000):
    try:
        with open(_log_path(), encoding="utf-8") as fh:
            return fh.read()[-tail:]
    except OSError:
        return ""


# --- /logs second opinion ---------------------------------------------------
def score_live(threshold=0.5, since_hours=None, cancel_check=None):
    """Score current logdb endpoints with the robust detector → robust_predictions.json."""
    if not available():
        return {"ok": False, "reason": _IMPORT_ERROR}
    try:
        from selfplay import robust_detector
        return robust_detector.score_live(
            threshold=threshold, since_hours=since_hours,
            cancel_check=cancel_check,
        )
    except CancelledError:
        raise
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
