"""Durable registry for cancellable background page operations.

The application already has specialised registries for template generation,
LLM investigations, provenance probes, and self-play.  This registry covers the
remaining button-triggered operations that used to block their HTTP request:
site deployment, campaign analysis, manual-prompt generation, and membership
inference.

Execution is owned by a server worker thread, never by the browser request that
launched it.  Public task metadata and results are also checkpointed under
``configs/history/jobs``.  That gives a returning browser a stable task id and
result even after it navigates away or closes; a web-page poller is only a view
of the work, not the thing driving it.

Cancellation is cooperative for Python work and immediate for a subprocess
registered through :class:`TaskContext`.  A task belongs to the signed-in user
that launched it; only that user (or an administrator) may inspect or cancel it.
If the application process itself restarts, a checkpoint that was still marked
running is made terminal as ``interrupted`` rather than pretending it is alive.
"""

from __future__ import annotations

import json
import os
import signal
import threading
import time
import uuid
from concurrent.futures import CancelledError

from .. import config


class TaskError(RuntimeError):
    """Base error for background-task lifecycle operations."""


class TaskBusy(TaskError):
    """Raised when an exclusive operation is already running."""

    def __init__(self, message, job_id=None):
        super().__init__(message)
        self.job_id = job_id


class TaskForbidden(TaskError):
    """Raised when a different user attempts to control a task."""


_JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()
_MAX_JOBS = 200
_MAX_PERSISTED_JOBS = 500


def _jobs_dir():
    path = config.HISTORY_DIR / "jobs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _job_path(job_id: str):
    # job ids are generated internally, but keeping the path prefix/suffix fixed
    # also makes an arbitrary status URL unable to escape the history directory.
    safe_id = "".join(ch for ch in str(job_id) if ch.isalnum() or ch in "_-")
    if safe_id != str(job_id) or not safe_id:
        return None
    return _jobs_dir() / f"task-{safe_id}.json"


def _record(job: dict) -> dict:
    """JSON-safe task record, including owner/result for internal recovery."""
    return {
        key: value
        for key, value in job.items()
        if not key.startswith("_")
    }


def _write_record(record: dict) -> None:
    path = _job_path(record.get("id", ""))
    if path is None:
        return
    tmp = path.with_name(f".{path.name}.{threading.get_ident()}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, default=str)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except OSError:
        # Persistence must never turn a successfully-started operation into a
        # failed one. The in-process registry remains authoritative while live.
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def _persist_locked(job: dict) -> None:
    _write_record(_record(job))


def _read_record(job_id: str) -> dict | None:
    path = _job_path(job_id)
    if path is None or not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) and value.get("id") == job_id else None


def _persisted_records() -> list[dict]:
    records = []
    try:
        paths = list(_jobs_dir().glob("task-*.json"))
    except OSError:
        return records
    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                value = json.load(handle)
            if isinstance(value, dict) and value.get("id"):
                records.append(value)
        except (OSError, ValueError):
            continue
    return records


def _mark_interrupted(record: dict) -> dict:
    """Terminalize an orphaned checkpoint from a previous app process."""
    if record.get("done") or record.get("status") not in {"running", "cancelling"}:
        return record
    updated = dict(record)
    updated.update(
        status="interrupted",
        done=True,
        ok=False,
        label="Interrupted because the application service restarted.",
        error="The server process restarted before this operation finished. Run it again.",
        ended=time.time(),
        updated=time.time(),
    )
    _write_record(updated)
    return updated


def _prune_persisted() -> None:
    """Bound ignored machine-local history without touching live records."""
    records = _persisted_records()
    if len(records) <= _MAX_PERSISTED_JOBS:
        return
    records.sort(key=lambda item: item.get("updated", 0), reverse=True)
    for record in records[_MAX_PERSISTED_JOBS:]:
        if not record.get("done"):
            continue
        path = _job_path(record.get("id", ""))
        if path is not None:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


def _prune_locked() -> None:
    if len(_JOBS) <= _MAX_JOBS:
        return
    finished = sorted(
        (job_id for job_id, job in _JOBS.items() if job.get("done")),
        key=lambda job_id: _JOBS[job_id].get("updated", 0),
    )
    for job_id in finished[: len(_JOBS) - _MAX_JOBS]:
        _JOBS.pop(job_id, None)


def _same_owner(job: dict, requester: str | None, is_admin: bool) -> bool:
    owner = job.get("owner")
    # ``owner is None`` supports jobs launched by tests/CLI code and jobs that
    # pre-date account ownership. Web-launched jobs always carry an owner.
    return bool(is_admin or owner is None or (requester and requester == owner))


def _snapshot(job: dict) -> dict:
    """Return only JSON-safe, non-sensitive task state."""
    return {
        key: value
        for key, value in job.items()
        if not key.startswith("_") and key not in {"owner", "result"}
    }


def _signal_process_group(proc, sig) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.send_signal(sig)
        except (ProcessLookupError, OSError):
            pass


def _terminate_process(proc, grace_seconds: float = 4.0) -> None:
    """SIGTERM a registered process group, then SIGKILL only if it ignores it."""
    _signal_process_group(proc, signal.SIGTERM)

    def escalate():
        if proc.poll() is None:
            _signal_process_group(proc, signal.SIGKILL)

    timer = threading.Timer(grace_seconds, escalate)
    timer.daemon = True
    timer.start()


class TaskContext:
    """Worker-facing cancellation/progress handle."""

    def __init__(self, job_id: str, cancel_event: threading.Event):
        self.job_id = job_id
        self.cancel_event = cancel_event

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def check_cancelled(self) -> None:
        if self.cancelled:
            raise CancelledError("Cancelled by user.")

    def update(self, **fields) -> None:
        with _LOCK:
            job = _JOBS.get(self.job_id)
            if job is None:
                return
            # Once cancellation has been requested, a late phase update must
            # not change the visible state back to "running".
            if job.get("status") == "cancelling":
                fields.pop("status", None)
            job.update(fields)
            job["updated"] = time.time()
            _persist_locked(job)

    def attach_process(self, proc) -> None:
        """Register a process created with ``start_new_session=True``.

        There is a deliberate cancellation-race check after registration: if
        the user clicked Cancel between ``Popen`` and this method, the newly
        attached process is terminated immediately.
        """
        with _LOCK:
            job = _JOBS.get(self.job_id)
            if job is None:
                terminate_now = True
            else:
                job["_process"] = proc
                terminate_now = job["_cancel_event"].is_set()
        if terminate_now:
            _terminate_process(proc)

    def detach_process(self, proc) -> None:
        with _LOCK:
            job = _JOBS.get(self.job_id)
            if job is not None and job.get("_process") is proc:
                job["_process"] = None


def start(
    kind: str,
    worker,
    *,
    owner: str | None = None,
    label: str = "Starting…",
    exclusive_key: str | None = None,
    redirect: str | None = None,
) -> str:
    """Start ``worker(context)`` on a daemon thread and return an opaque id."""
    cancel_event = threading.Event()
    job_id = uuid.uuid4().hex[:16]
    now = time.time()
    state = {
        "id": job_id,
        "kind": kind,
        "status": "running",
        "done": False,
        "ok": None,
        "label": label,
        "error": None,
        "redirect": redirect,
        "started": now,
        "updated": now,
        "ended": None,
        "owner": owner,
        "result": None,
        "_cancel_event": cancel_event,
        "_process": None,
        "_exclusive_key": exclusive_key,
    }
    with _LOCK:
        existing = next((
            job for job in _JOBS.values()
            if exclusive_key
            and job.get("_exclusive_key") == exclusive_key
            and not job.get("done")
        ), None)
        if existing is not None:
            existing_id = existing["id"] if _same_owner(existing, owner, False) else None
            raise TaskBusy("That operation is already running.", existing_id)
        _JOBS[job_id] = state
        _prune_locked()
        _persist_locked(state)
    _prune_persisted()

    def run():
        context = TaskContext(job_id, cancel_event)
        try:
            context.check_cancelled()
            result = worker(context)
            context.check_cancelled()
            result = result if isinstance(result, dict) else {"result": result}
            ok = bool(result.get("ok", True))
            with _LOCK:
                job = _JOBS.get(job_id)
                if job is not None:
                    job.update(
                        status="completed" if ok else "failed",
                        done=True,
                        ok=ok,
                        label=result.get("label") or ("Done." if ok else "Operation failed."),
                        error=result.get("error"),
                        redirect=result.get("redirect"),
                        result=result,
                        ended=time.time(),
                        updated=time.time(),
                        _process=None,
                    )
                    _persist_locked(job)
        except CancelledError:
            with _LOCK:
                job = _JOBS.get(job_id)
                if job is not None:
                    job.update(
                        status="cancelled", done=True, ok=False,
                        label="Cancelled.", error=None, ended=time.time(),
                        updated=time.time(), _process=None,
                    )
                    _persist_locked(job)
        except Exception as exc:  # every worker must reach a terminal state
            with _LOCK:
                job = _JOBS.get(job_id)
                if job is not None:
                    job.update(
                        status="failed", done=True, ok=False,
                        label="Operation failed.",
                        error=f"{type(exc).__name__}: {exc}",
                        ended=time.time(), updated=time.time(), _process=None,
                    )
                    _persist_locked(job)

    thread = threading.Thread(target=run, name=f"task-{kind}-{job_id}", daemon=True)
    with _LOCK:
        _JOBS[job_id]["_thread"] = thread
    thread.start()
    return job_id


def status(
    job_id: str,
    *,
    requester: str | None = None,
    is_admin: bool = False,
) -> dict | None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is not None:
            if not _same_owner(job, requester, is_admin):
                raise TaskForbidden("This job belongs to a different account.")
            return _snapshot(job)
    record = _read_record(job_id)
    if record is None:
        return None
    record = _mark_interrupted(record)
    if not _same_owner(record, requester, is_admin):
        raise TaskForbidden("This job belongs to a different account.")
    return _snapshot(record)


def result(
    job_id: str,
    *,
    requester: str | None = None,
    is_admin: bool = False,
):
    """Return a task result after the same owner check as :func:`status`."""
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is not None:
            if not _same_owner(job, requester, is_admin):
                raise TaskForbidden("This job belongs to a different account.")
            return job.get("result")
    record = _read_record(job_id)
    if record is None:
        return None
    record = _mark_interrupted(record)
    if not _same_owner(record, requester, is_admin):
        raise TaskForbidden("This job belongs to a different account.")
    return record.get("result")


def list_jobs(
    *,
    requester: str | None = None,
    is_admin: bool = False,
    kinds=None,
    active_only: bool = False,
    max_age: float | None = None,
) -> list[dict]:
    """List visible jobs newest-first, merging live and persisted state."""
    wanted = set(kinds or ())
    with _LOCK:
        live = {job_id: _record(job) for job_id, job in _JOBS.items()}
    merged = {record["id"]: record for record in _persisted_records() if record.get("id")}
    # Close the small scan race: a job may have started while disk records were
    # being read. Refresh live state before classifying any disk row orphaned.
    with _LOCK:
        live.update({job_id: _record(job) for job_id, job in _JOBS.items()})
    merged.update(live)  # live state always wins over its last checkpoint
    now = time.time()
    visible = []
    for job_id, record in merged.items():
        if job_id not in live:
            record = _mark_interrupted(record)
        if not _same_owner(record, requester, is_admin):
            continue
        if wanted and record.get("kind") not in wanted:
            continue
        if active_only and record.get("done"):
            continue
        if max_age is not None and now - float(record.get("updated") or 0) > max_age:
            continue
        item = _snapshot(record)
        item["result"] = record.get("result")
        visible.append(item)
    visible.sort(key=lambda item: item.get("updated", 0), reverse=True)
    return visible


def latest(
    *,
    requester: str | None = None,
    is_admin: bool = False,
    kinds=None,
    active_only: bool = False,
    max_age: float | None = None,
) -> dict | None:
    jobs = list_jobs(
        requester=requester,
        is_admin=is_admin,
        kinds=kinds,
        active_only=active_only,
        max_age=max_age,
    )
    return jobs[0] if jobs else None


def cancel(
    job_id: str,
    *,
    requester: str | None = None,
    is_admin: bool = False,
) -> dict | None:
    """Request cancellation. Safe and idempotent for terminal tasks."""
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            pass
        elif not _same_owner(job, requester, is_admin):
            raise TaskForbidden("This job belongs to a different account.")
        elif job.get("done"):
            return _snapshot(job)
        else:
            job["_cancel_event"].set()
            job.update(status="cancelling", label="Stopping safely…", updated=time.time())
            _persist_locked(job)
            proc = job.get("_process")
            snapshot = _snapshot(job)
    if job is None:
        record = _read_record(job_id)
        if record is None:
            return None
        record = _mark_interrupted(record)
        if not _same_owner(record, requester, is_admin):
            raise TaskForbidden("This job belongs to a different account.")
        return _snapshot(record)
    if proc is not None:
        _terminate_process(proc)
    return snapshot
