"""Run detection/manual investigations in the background with live progress.

Why background: querying real search-enabled models takes many seconds per
model, so a synchronous ``POST /query/run`` would hang the request (and time
out behind a proxy). Instead a run is started on a worker thread and the user
is redirected immediately to its run page, which polls a small JSON status
endpoint and reveals the attribution results only when the run completes — the
vision the user asked for (see the prompt, watch responses populate, results at
the end).

Design notes:

- One worker thread per run (runs are infrequent and I/O-bound — waiting on
  provider HTTP — so a thread is the simplest correct choice; no event loop or
  task queue needed). A small bounded pool guards against pathological misuse.
- Live state lives in memory (``_RUNS``); the authoritative record is still the
  ``querying/runs/<id>.json`` file the adapter persists (checkpointed after the
  prompt and again at the end), so a run survives a page reload and history/
  stats keep working unchanged.
- ``status(run_id)`` merges live progress (if the run is in this process) with
  the persisted file, and detects an **interrupted** run — one whose file says
  ``running`` but has no live worker (e.g. the app restarted mid-run) — so the
  page never spins forever.
"""

import threading
import time

from querying.store import load_run

from . import auto_query_adapter

# Live, in-process run state keyed by run_id. Guarded by _LOCK.
_RUNS = {}
_LOCK = threading.Lock()
_MAX_TRACKED = 200  # cap the in-memory registry; oldest finished runs evicted


def _prune_locked():
    if len(_RUNS) <= _MAX_TRACKED:
        return
    finished = sorted(
        (rid for rid, s in _RUNS.items() if s.get("done")),
        key=lambda rid: _RUNS[rid].get("updated", 0),
    )
    for rid in finished[: len(_RUNS) - _MAX_TRACKED]:
        _RUNS.pop(rid, None)


def _init_state(run_id, kind, models):
    state = {
        "run_id": run_id,
        "kind": kind,
        "stage": "queued",
        "stage_label": "Queued…",
        "subject": None,
        "role_prompt": None,
        "prompt": None,
        "models": list(models),
        # Per-model live status: pending -> querying -> done|error.
        "model_status": {m: {"state": "pending"} for m in models},
        "done": False,
        "status": "running",
        "error": None,
        "updated": time.time(),
    }
    with _LOCK:
        _RUNS[run_id] = state
        _prune_locked()
    return state


def _progress(run_id):
    """Return a ``progress(event, data)`` callback bound to ``run_id``."""

    def callback(event, data):
        with _LOCK:
            state = _RUNS.get(run_id)
            if state is None:
                return
            state["updated"] = time.time()
            if event == "stage":
                state["stage"] = data.get("stage", state["stage"])
                state["stage_label"] = data.get("label", state["stage_label"])
            elif event == "prompt":
                state["subject"] = data.get("subject")
                state["role_prompt"] = data.get("role_prompt")
                state["prompt"] = data.get("prompt")
            elif event == "model_start":
                state["model_status"][data["model"]] = {"state": "querying"}
            elif event == "model_done":
                ok = data.get("ok", True)
                state["model_status"][data["model"]] = {
                    "state": "done" if ok else "error",
                    "chars": len(data.get("answer") or ""),
                    "error": data.get("error"),
                    "error_kind": data.get("error_kind"),
                }
            elif event == "finished":
                state["stage"] = "finished"
                state["stage_label"] = "Done"
                state["done"] = True
                state["status"] = data.get("status", "completed")
                state["error"] = data.get("error")

    return callback


def _run_worker(fn, run_id, kwargs):
    try:
        fn(run_id=run_id, progress=_progress(run_id), **kwargs)
    except Exception as exc:  # the adapter already traps its own errors; belt & braces
        with _LOCK:
            state = _RUNS.get(run_id)
            if state is not None:
                state.update(done=True, status="failed",
                             error=f"{type(exc).__name__}: {exc}",
                             stage="finished", stage_label="Failed", updated=time.time())


def _start(fn, kind, models, kwargs):
    run_id = auto_query_adapter._new_run_id()
    _init_state(run_id, kind, models)
    thread = threading.Thread(
        target=_run_worker, args=(fn, run_id, kwargs),
        name=f"aq-run-{run_id}", daemon=True,
    )
    thread.start()
    return run_id


def start_detection(*, site_id=None, url=None, models, csv_path=None):
    """Kick off a detection run in the background; return its run_id at once."""
    return _start(
        auto_query_adapter.run_detection, "detection", models,
        {"site_id": site_id, "url": url, "models": models, "csv_path": csv_path},
    )


def start_manual(*, records, site_id=None, url=None, csv_path=None):
    """Kick off a manual evaluation in the background; return its run_id."""
    models = [r["Model"] for r in records]
    return _start(
        auto_query_adapter.run_manual_evaluation, "manual", models,
        {"records": records, "site_id": site_id, "url": url, "csv_path": csv_path},
    )


def _live_snapshot(run_id):
    with _LOCK:
        state = _RUNS.get(run_id)
        return dict(state, model_status=dict(state["model_status"])) if state else None


def status(run_id):
    """Merged live + persisted status for the run page's poller.

    Shape: ``{run_id, present, done, status, stage, stage_label, subject,
    models[], error, interrupted}``. ``present`` is False when nothing is known
    about the id at all (bad link).
    """
    live = _live_snapshot(run_id)
    record = load_run(run_id)

    if live is None and record is None:
        return {"run_id": run_id, "present": False, "done": True,
                "status": "missing", "stage": "missing",
                "stage_label": "No run found with that id.", "models": [],
                "interrupted": False}

    if live is not None:
        models = [
            {"model": m, **live["model_status"].get(m, {"state": "pending"})}
            for m in live["models"]
        ]
        return {
            "run_id": run_id,
            "present": True,
            "done": live["done"],
            "status": live["status"],
            "stage": live["stage"],
            "stage_label": live["stage_label"],
            "subject": live.get("subject") or (record or {}).get("subject"),
            "kind": live.get("kind"),
            "models": models,
            "error": live.get("error"),
            "interrupted": False,
        }

    # No live worker: read from the persisted record. A record still marked
    # "running" with no worker means the process was restarted mid-run.
    status_val = record.get("status")
    interrupted = status_val == "running"
    done = status_val in ("completed", "failed") or interrupted
    return {
        "run_id": run_id,
        "present": True,
        "done": done,
        "status": "failed" if interrupted else status_val,
        "stage": "finished" if done else status_val,
        "stage_label": ("This run was interrupted (the app restarted before it finished)."
                        if interrupted else "Done"),
        "subject": record.get("subject"),
        "kind": record.get("kind"),
        "models": [{"model": m, "state": "done"} for m in record.get("models", [])],
        "error": record.get("error"),
        "interrupted": interrupted,
    }
