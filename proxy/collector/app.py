"""Central visit collector for the AI Bot Defender reverse proxy.

nginx mirrors every request here (body-less, fire-and-forget). We record one row
per request into the shared `all_visits` table, tagged with the originating site
(from the X-Site header nginx sets), then return 204 as fast as possible.

Design rules:
  - Never block or fail the real response. The mirror is best-effort, so any
    error here is swallowed and the cached DB connection is reset.
  - Accept any method/path so the catch-all route mirrors whatever the client
    sent (in practice GET / for the honeypot).
"""

import json
import os
import re
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

import psycopg2
from psycopg2.extras import Json
from fastapi import FastAPI, Request, Response

DB_HOST = os.environ.get("DB_HOST", "logdb")
DB_USER = os.environ.get("DB_USER", "logger")
DB_PASS = os.environ.get("DB_PASS", "logger")
DB_NAME = os.environ.get("DB_NAME", "site_logs")
ACCESS_LOG = Path(os.environ.get("ACCESS_LOG", "/var/log/nginx/dukecodeplus.access.log"))
MAX_LOG_LINE = 64 * 1024
MAX_URI_CHARS = 16 * 1024
PENDING_TTL_SECONDS = 60.0
REPLAY_BATCH_SIZE = 500
REPLAY_MAX_BYTES = 8 * 1024 * 1024
LIVE_BATCH_SIZE = 128
MAX_LIVE_PENDING = 4096
LIVE_FLUSH_SECONDS = 0.25
RETRY_INITIAL_SECONDS = 0.25
RETRY_MAX_SECONDS = 8.0
ERROR_RETRY_SECONDS = 1.0


def _positive_float_env(name, default):
    """Read one positive finite duration without making startup fragile."""
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return float(default)
    return value if 0 < value < float("inf") else float(default)


# docker-compose.proxy.yml gives nginx and this collector the same configurable
# marker-poll duration. The extra quiet interval covers signal/worker reopen
# jitter and is also the old-inode drain window after the replacement appears.
NGINX_LOG_REOPEN_POLL_SECONDS = _positive_float_env(
    "NGINX_LOG_REOPEN_POLL_SECONDS", 5.0
)
ROTATION_DRAIN_SECONDS = 1.0
MISSING_PATH_GRACE_SECONDS = (
    NGINX_LOG_REOPEN_POLL_SECONDS + ROTATION_DRAIN_SECONDS
)
REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
NON_MIRRORED_PATHS = frozenset({"/__fpbeacon", "/__abd_health", "/_mirror"})
NON_MIRRORED_PREFIXES = ("/.well-known/acme-challenge/",)


class CorrelationHealth:
    """Fixed-cardinality operational state for the off-path status tailer."""

    def __init__(self):
        self._lock = threading.Lock()
        self._values = {
            "thread_up": 0,
            "healthy": 0,
            "access_log_present": 0,
            "last_success_unixtime": 0.0,
            "errors_total": 0,
            "records_seen_total": 0,
            "records_ignored_total": 0,
            "records_unusable_total": 0,
            "records_correlated_total": 0,
            "records_missed_total": 0,
            "startup_race_correlated_total": 0,
            "startup_unresolved_total": 0,
            "mirror_rows_inserted_total": 0,
            "mirror_insert_errors_total": 0,
            "pending": 0,
        }

    def snapshot(self):
        with self._lock:
            return dict(self._values)

    def set_thread_up(self, up):
        with self._lock:
            self._values["thread_up"] = int(bool(up))

    def mark_success(self, *, pending):
        with self._lock:
            self._values["healthy"] = 1
            self._values["access_log_present"] = 1
            self._values["last_success_unixtime"] = time.time()
            self._values["pending"] = max(0, int(pending))

    def mark_failure(self, *, access_log_missing=False):
        with self._lock:
            self._values["healthy"] = 0
            if access_log_missing:
                self._values["access_log_present"] = 0
            self._values["errors_total"] += 1

    def note_seen(self, count=1):
        with self._lock:
            self._values["records_seen_total"] += max(0, int(count))

    def note_ignored(self, count=1):
        with self._lock:
            self._values["records_ignored_total"] += max(0, int(count))

    def note_unusable(self, count=1):
        with self._lock:
            self._values["records_unusable_total"] += max(0, int(count))

    def note_correlated(self, count=1):
        with self._lock:
            self._values["records_correlated_total"] += max(0, int(count))

    def note_missed(self, count=1):
        with self._lock:
            self._values["records_missed_total"] += max(0, int(count))

    def note_startup_correlated(self, count=1):
        with self._lock:
            self._values["startup_race_correlated_total"] += max(0, int(count))

    def note_startup_unresolved(self, count=1):
        with self._lock:
            self._values["startup_unresolved_total"] += max(0, int(count))

    def note_mirror_inserted(self, count=1):
        with self._lock:
            self._values["mirror_rows_inserted_total"] += max(0, int(count))

    def note_mirror_insert_error(self, count=1):
        with self._lock:
            self._values["mirror_insert_errors_total"] += max(0, int(count))

    def set_pending(self, count):
        with self._lock:
            self._values["pending"] = max(0, int(count))


CORRELATION_HEALTH = CorrelationHealth()

_METRICS = (
    ("abd_collector_status_sync_thread_up", "gauge", "Status-sync thread is running.", "thread_up"),
    ("abd_collector_status_sync_healthy", "gauge", "Most recent access-log sync poll succeeded.", "healthy"),
    ("abd_collector_access_log_present", "gauge", "Authoritative nginx access log is readable.", "access_log_present"),
    ("abd_collector_status_sync_last_success_unixtime_seconds", "gauge", "Unix time of the last successful sync poll.", "last_success_unixtime"),
    ("abd_collector_status_sync_errors_total", "counter", "Access-log sync poll failures.", "errors_total"),
    ("abd_collector_status_records_seen_total", "counter", "Valid post-startup final-status records read from nginx.", "records_seen_total"),
    ("abd_collector_status_records_ignored_total", "counter", "Expected non-mirrored telemetry status records ignored.", "records_ignored_total"),
    ("abd_collector_status_records_unusable_total", "counter", "Complete matched-site access records unusable for status correlation.", "records_unusable_total"),
    ("abd_collector_status_records_correlated_total", "counter", "Final statuses matched to mirror rows, including the bounded startup race tail.", "records_correlated_total"),
    ("abd_collector_status_records_missed_total", "counter", "Live final statuses dropped after bounded retry/queue expiry.", "records_missed_total"),
    ("abd_collector_status_startup_race_correlated_total", "counter", "Initially unmatched historical startup-race statuses later matched during bounded retry.", "startup_race_correlated_total"),
    ("abd_collector_status_startup_unresolved_total", "counter", "Initially unmatched historical startup-race statuses dropped after bounded retry/queue expiry.", "startup_unresolved_total"),
    ("abd_collector_mirror_rows_inserted_total", "counter", "Mirrored request rows successfully written to all_visits.", "mirror_rows_inserted_total"),
    ("abd_collector_mirror_insert_errors_total", "counter", "Mirrored request rows lost to collector or database errors.", "mirror_insert_errors_total"),
    ("abd_collector_status_pending", "gauge", "Final statuses currently awaiting a mirror row.", "pending"),
)


def correlation_metrics_response(*, head=False):
    """Return a bounded, no-label Prometheus exposition for the tailer."""
    values = CORRELATION_HEALTH.snapshot()
    lines = []
    for metric, kind, help_text, key in _METRICS:
        lines.extend((
            f"# HELP {metric} {help_text}",
            f"# TYPE {metric} {kind}",
            f"{metric} {values[key]}",
        ))
    body = "" if head else "\n".join(lines) + "\n"
    return Response(
        content=body,
        status_code=200,
        media_type="text/plain; version=0.0.4",
    )

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS all_visits (
    id          serial primary key,
    ts          timestamptz default now(),
    site        text,
    client_ip   text,
    client_port int,
    user_agent  text,
    method      text,
    uri         text,
    headers     jsonb,
    request_id  text,
    response_status smallint
)
"""

# Additive migration for databases created before client_port existed. nginx now
# forwards the client's source TCP port (X-Client-Port) so the crawler-graph layer
# can join each request to its passively-captured TLS fingerprint by 4-tuple.
# Safe and idempotent; CREATE TABLE IF NOT EXISTS alone never alters an existing
# table, so this ALTER is required on already-deployed proxy stacks.
MIGRATIONS = (
    "ALTER TABLE all_visits ADD COLUMN IF NOT EXISTS client_port int",
    "ALTER TABLE all_visits ADD COLUMN IF NOT EXISTS request_id text",
    "ALTER TABLE all_visits ADD COLUMN IF NOT EXISTS response_status smallint",
    "CREATE INDEX IF NOT EXISTS all_visits_request_id_idx ON all_visits (request_id)",
)

_conn = None


def get_conn():
    """Return a live autocommit connection, (re)connecting if needed."""
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASS, dbname=DB_NAME
        )
        _conn.autocommit = True
    return _conn


def reset_conn():
    """Drop the cached connection so the next request reconnects cleanly."""
    global _conn
    try:
        if _conn is not None:
            _conn.close()
    finally:
        _conn = None


def init_db():
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(CREATE_TABLE)
        for statement in MIGRATIONS:
            cur.execute(statement)


ACCESS_RECORD_VALID = "valid"
ACCESS_RECORD_IGNORED = "ignored"
ACCESS_RECORD_UNUSABLE = "unusable"


def _record_timestamp(record):
    """Return an aware nginx log timestamp as Unix seconds, else ``None``."""
    raw_time = record.get("time")
    if not isinstance(raw_time, str) or not raw_time:
        return None
    try:
        parsed = datetime.fromisoformat(
            raw_time[:-1] + "+00:00" if raw_time.endswith("Z") else raw_time
        )
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.timestamp()
    except (OverflowError, TypeError, ValueError):
        return None


def classify_access_record_details(line):
    """Return ``(kind, payload, timestamp)`` for one bounded nginx JSON line.

    Access logs are an untrusted-input boundary: request fields can be long and
    malformed lines can appear around rotation. Expected telemetry paths are
    distinguished from unusable matched-site lines so parser/config drift is
    observable without treating intentionally unmirrored probes as failures.
    Timestamp validity is deliberately independent: live records never require
    it, while historical replay promotion uses it to reject stale evidence.
    """
    if not isinstance(line, str) or not line or len(line) > MAX_LOG_LINE:
        return ACCESS_RECORD_UNUSABLE, None, None
    try:
        record = json.loads(line)
    except (TypeError, ValueError, json.JSONDecodeError):
        return ACCESS_RECORD_UNUSABLE, None, None
    if not isinstance(record, dict):
        return ACCESS_RECORD_UNUSABLE, None, None
    request_id = record.get("request_id")
    status = record.get("status")
    uri = record.get("uri")
    if not isinstance(uri, str) or not uri:
        return ACCESS_RECORD_UNUSABLE, None, None
    path = uri.split("?", 1)[0]
    if path in NON_MIRRORED_PATHS or any(
        path.startswith(prefix) for prefix in NON_MIRRORED_PREFIXES
    ):
        return ACCESS_RECORD_IGNORED, None, _record_timestamp(record)
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        return ACCESS_RECORD_UNUSABLE, None, _record_timestamp(record)
    if isinstance(status, bool):
        return ACCESS_RECORD_UNUSABLE, None, _record_timestamp(record)
    try:
        status = int(status)
    except (TypeError, ValueError):
        return ACCESS_RECORD_UNUSABLE, None, _record_timestamp(record)
    if not 100 <= status <= 599:
        return ACCESS_RECORD_UNUSABLE, None, _record_timestamp(record)
    return ACCESS_RECORD_VALID, (request_id, status), _record_timestamp(record)


def classify_access_record(line):
    """Compatibility classifier returning only ``(kind, payload)``."""
    kind, payload, _timestamp = classify_access_record_details(line)
    return kind, payload


def parse_access_record(line):
    """Compatibility wrapper returning only a usable ``(request_id, status)``."""
    kind, payload = classify_access_record(line)
    return payload if kind == ACCESS_RECORD_VALID else None


def replay_record_is_recent(record_timestamp, startup_timestamp):
    """Whether a historical log result can still be a collector-start race."""
    if record_timestamp is None:
        return False
    try:
        delta = abs(float(record_timestamp) - float(startup_timestamp))
    except (TypeError, ValueError):
        return False
    return delta <= PENDING_TTL_SECONDS


def update_response_status(conn, request_id, status):
    """Apply an authoritative nginx result; return whether its mirror row exists."""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE all_visits SET response_status = %s WHERE request_id = %s",
            (status, request_id),
        )
        # psycopg2 cursors expose rowcount. Test doubles and unusual drivers may
        # not, in which case treating the update as successful avoids retries.
        rowcount = getattr(cur, "rowcount", None)
    return rowcount is None or rowcount > 0


def update_response_status_batch(conn, records, *, return_matched=False):
    """Update many request IDs in one query; optionally return matched IDs."""
    items = list(records.items())
    if not items:
        return set()
    request_ids = [item[0] for item in items]
    statuses = [item[1] for item in items]
    returning = " RETURNING a.request_id" if return_matched else ""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE all_visits AS a SET response_status = v.status "
            "FROM unnest(%s::text[], %s::smallint[]) AS v(request_id, status) "
            "WHERE a.request_id = v.request_id" + returning,
            (request_ids, statuses),
        )
        if return_matched:
            return {str(row[0]) for row in cur.fetchall()}
    return set()


class PendingStatus(NamedTuple):
    status: int
    first_seen: float
    next_attempt: float
    delay: float
    miss_on_drop: bool
    startup_candidate: bool


def _account_pending_drop(entry):
    """Account both monotone provenance flags for one unresolved queue drop."""
    if entry.miss_on_drop:
        CORRELATION_HEALTH.note_missed()
    if entry.startup_candidate:
        CORRELATION_HEALTH.note_startup_unresolved()


def flush_replay(conn, records, pending, startup_timestamp, now=None):
    """Apply one historical batch and queue every recent initial miss.

    ``UPDATE ... RETURNING`` proves which rows already existed during their
    one-shot replay. Only timestamp-bounded misses are eligible for startup-race
    retry; the bounded pending queue explicitly accounts for every later match
    or unresolved drop.
    """
    if not records:
        return conn, 0
    if conn is None or conn.closed:
        conn = status_conn()
    statuses = {
        request_id: record[0]
        for request_id, record in records.items()
    }
    matched = update_response_status_batch(conn, statuses, return_matched=True)
    now = time.monotonic() if now is None else now
    queued = 0
    for request_id in matched:
        # A duplicate from an earlier replay batch may already be waiting. This
        # one-shot match resolves it without claiming bounded-retry credit.
        pending.pop(request_id, None)
    for request_id, (status, record_timestamp) in records.items():
        if request_id in matched or not replay_record_is_recent(
            record_timestamp, startup_timestamp
        ):
            continue
        was_pending = request_id in pending
        queue_live(
            pending,
            request_id,
            status,
            now,
            miss_on_drop=False,
            startup_candidate=True,
        )
        queued += int(not was_pending)
    records.clear()
    CORRELATION_HEALTH.set_pending(len(pending))
    return conn, queued


def queue_live(
    pending,
    request_id,
    status,
    now=None,
    *,
    miss_on_drop=True,
    startup_candidate=False,
):
    """Queue one result for bounded, exponentially backed-off retry.

    Only records read after the startup byte cutoff are authoritative evidence
    of a live correlation loss. A recent historical tail record can still race
    an insert across collector restart, so it receives the same retry behavior
    with ``miss_on_drop=False`` but cannot inflate the live-loss counter.
    """
    now = time.monotonic() if now is None else now
    existing = pending.get(request_id)
    if existing:
        pending[request_id] = PendingStatus(
            status,
            existing.first_seen,
            min(existing.next_attempt, now),
            existing.delay,
            bool(existing.miss_on_drop or miss_on_drop),
            bool(existing.startup_candidate or startup_candidate),
        )
        return
    if len(pending) >= MAX_LIVE_PENDING:
        evicted = pending.pop(next(iter(pending)))
        _account_pending_drop(evicted)
    pending[request_id] = PendingStatus(
        status,
        now,
        now,
        RETRY_INITIAL_SECONDS,
        bool(miss_on_drop),
        bool(startup_candidate),
    )
    CORRELATION_HEALTH.set_pending(len(pending))


def flush_live(conn, pending, now=None):
    """Try one bounded live batch and back off only IDs whose mirror row raced."""
    if not pending:
        CORRELATION_HEALTH.set_pending(0)
        return conn
    now = time.monotonic() if now is None else now
    due = {}
    expired_total = 0
    for request_id, entry in list(pending.items()):
        if now - entry.first_seen >= PENDING_TTL_SECONDS:
            pending.pop(request_id, None)
            expired_total += 1
            _account_pending_drop(entry)
            continue
        if entry.next_attempt <= now:
            due[request_id] = entry.status
            if len(due) >= LIVE_BATCH_SIZE:
                break
    # Account for irreversible TTL drops before a DB attempt: if that attempt
    # itself fails, these entries have still left the bounded queue.
    if expired_total:
        CORRELATION_HEALTH.set_pending(len(pending))
    if not due:
        CORRELATION_HEALTH.set_pending(len(pending))
        return conn
    if conn is None or conn.closed:
        conn = status_conn()
    matched = update_response_status_batch(conn, due, return_matched=True)
    CORRELATION_HEALTH.note_correlated(len(matched))
    CORRELATION_HEALTH.note_startup_correlated(sum(
        int(pending[request_id].startup_candidate)
        for request_id in matched
        if request_id in pending
    ))
    for request_id in due:
        current = pending.get(request_id)
        if current is None:
            continue
        if request_id in matched:
            pending.pop(request_id, None)
            continue
        pending[request_id] = PendingStatus(
            current.status,
            current.first_seen,
            now + current.delay,
            min(current.delay * 2, RETRY_MAX_SECONDS),
            current.miss_on_drop,
            current.startup_candidate,
        )
    CORRELATION_HEALTH.set_pending(len(pending))
    return conn


def status_conn():
    """Create the tailer's independent connection (never share request state)."""
    conn = psycopg2.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS, dbname=DB_NAME
    )
    conn.autocommit = True
    return conn


def open_access_log_file(expected_identity=None):
    """Open/fstat the canonical path atomically enough for safe fd handoff."""
    handle = None
    try:
        handle = ACCESS_LOG.open("rb")
        opened_stat = os.fstat(handle.fileno())
        identity = (opened_stat.st_dev, opened_stat.st_ino)
        if expected_identity is not None and identity != expected_identity:
            raise FileNotFoundError("access log changed during verified open")
        return handle, opened_stat, identity
    except Exception:
        if handle is not None:
            handle.close()
        raise


def follow_access_log(stop_event):
    """Tail nginx's final-response log and correlate results to mirrored rows.

    This runs in a daemon thread with its own DB connection. Historical replay
    is one-shot and batched; every recent initial miss and every newly appended
    record receives bounded retry. Rename/reopen and copytruncate both use a
    verified open-before-close handoff. Every I/O/DB error is swallowed so
    observability remains strictly off the request path.
    """
    CORRELATION_HEALTH.set_thread_up(True)
    startup_timestamp = None
    conn = None
    handle = None
    handle_identity = None
    replay_identity = None
    replay_cutoff = None
    position = 0
    replaying = True
    replay_records = {}
    pending = {}
    discarding_oversized = False
    rotation_quiet_since = None
    rotation_target_identity = None
    partial_observed_end = None
    path_missing_since = None
    path_outage_reported = False
    handoff_retry_at = 0.0
    copytruncate_pending = False
    live_since_flush = 0
    last_live_flush = time.monotonic()

    def report_path_outage(reason):
        """Report a path outage once until a canonical handle is verified."""
        nonlocal path_outage_reported
        if path_outage_reported:
            return
        print(f"collector: access log unavailable: {reason}", flush=True)
        CORRELATION_HEALTH.mark_failure(access_log_missing=True)
        path_outage_reported = True

    def clear_path_outage():
        nonlocal path_outage_reported, path_missing_since
        path_outage_reported = False
        path_missing_since = None

    def apply_replay_batch(now):
        """Run one replay UPDATE and immediately try its recent initial misses."""
        nonlocal conn, live_since_flush, last_live_flush
        conn, queued = flush_replay(
            conn,
            replay_records,
            pending,
            startup_timestamp,
            now,
        )
        live_since_flush += queued
        if pending:
            conn = flush_live(conn, pending, now)
            live_since_flush = 0
            last_live_flush = now

    def finish_replay(now):
        nonlocal replaying, replay_identity, replay_cutoff
        if not replaying:
            return
        apply_replay_batch(now)
        replaying = False
        replay_identity = None
        replay_cutoff = None

    while not stop_event.is_set():
        try:
            if handle is None:
                # Binary mode makes tell()/seek() offsets directly comparable
                # with stat().st_size and lets us retain an unterminated line
                # until nginx finishes writing it.
                try:
                    opened_handle, opened_stat, identity = open_access_log_file()
                except OSError as exc:
                    report_path_outage(exc)
                    CORRELATION_HEALTH.set_pending(len(pending))
                    stop_event.wait(ERROR_RETRY_SECONDS)
                    continue
                initial_open = handle_identity is None
                if identity != handle_identity:
                    position = 0
                handle = opened_handle
                handle_identity = identity
                size = opened_stat.st_size
                if initial_open:
                    # Measure the race window against the successful open that
                    # establishes the replay cutoff, not thread creation. nginx
                    # may legitimately create this file after collector starts.
                    startup_timestamp = time.time()
                    replay_identity = identity
                    # This exact byte boundary separates the pre-start replay
                    # from traffic appended while replay is still being read.
                    replay_cutoff = size
                # A collector restart cannot have mirror rows for traffic while
                # it was down. Replay only the recent tail needed for a crash
                # between insert and status update, never the full 100MB log.
                if initial_open and replaying and size > REPLAY_MAX_BYTES:
                    position = size - REPLAY_MAX_BYTES
                    handle.seek(position)
                    fragment = handle.readline(MAX_LOG_LINE + 1)
                    position = handle.tell()
                    # We intentionally started in the middle of a record. If
                    # its newline is beyond this bounded read, discard chunks
                    # through that newline instead of parsing a JSON suffix.
                    discarding_oversized = not fragment.endswith(b"\n")
                if position > size:
                    # A fresh reopen after an unexpected fd error can also
                    # reveal copytruncate. End replay provenance before reading
                    # the new generation from byte zero.
                    finish_replay(time.monotonic())
                    position = 0
                if position:
                    handle.seek(position)
                rotation_quiet_since = None
                rotation_target_identity = None
                partial_observed_end = None
                copytruncate_pending = False
                handoff_retry_at = 0.0
                clear_path_outage()

            # A failed replay batch is retained and retried before consuming
            # another line, so a DB outage cannot grow memory without bound.
            if replaying and len(replay_records) >= REPLAY_BATCH_SIZE:
                apply_replay_batch(time.monotonic())

            try:
                path_stat = ACCESS_LOG.stat()
                path_identity = (path_stat.st_dev, path_stat.st_ino)
            except OSError:
                path_stat = None
                path_identity = None
            if path_stat is None:
                now = time.monotonic()
                if path_missing_since is None:
                    path_missing_since = now
                if (
                    not path_outage_reported
                    and now - path_missing_since >= MISSING_PATH_GRACE_SECONDS
                ):
                    report_path_outage(
                        f"canonical path missing beyond "
                        f"{MISSING_PATH_GRACE_SECONDS:g}s"
                    )
            else:
                path_missing_since = None
            rotation_pending = bool(
                path_identity is not None and path_identity != handle_identity
            )
            if rotation_pending:
                if rotation_target_identity != path_identity:
                    rotation_target_identity = path_identity
                    rotation_quiet_since = None
                    handoff_retry_at = 0.0
            else:
                rotation_target_identity = None
                rotation_quiet_since = None
                if not copytruncate_pending:
                    handoff_retry_at = 0.0

            canonical_verified = bool(
                path_identity is not None
                and path_identity == handle_identity
                and not copytruncate_pending
            )
            if canonical_verified:
                clear_path_outage()

            if (
                path_stat is not None
                and path_identity == handle_identity
                and path_stat.st_size
                < max(position, partial_observed_end or position)
            ):
                copytruncate_pending = True
                canonical_verified = False

            if copytruncate_pending:
                now = time.monotonic()
                if path_identity is not None and now >= handoff_retry_at:
                    try:
                        fresh_handle, _fresh_stat, fresh_identity = (
                            open_access_log_file(path_identity)
                        )
                    except OSError as exc:
                        report_path_outage(exc)
                        handoff_retry_at = now + ERROR_RETRY_SECONDS
                    else:
                        try:
                            finish_replay(now)
                        except Exception:
                            fresh_handle.close()
                            raise
                        old_handle = handle
                        handle = fresh_handle
                        handle_identity = fresh_identity
                        position = 0
                        discarding_oversized = False
                        partial_observed_end = None
                        rotation_quiet_since = None
                        copytruncate_pending = False
                        handoff_retry_at = 0.0
                        old_handle.close()
                        clear_path_outage()
                        CORRELATION_HEALTH.mark_success(pending=len(pending))
                        continue
                # Never seek/re-read a BufferedReader after copytruncate. Keep
                # the old fd only until a fresh canonical open can replace it.
                CORRELATION_HEALTH.set_pending(len(pending))
                wait_for = max(0.0, handoff_retry_at - time.monotonic())
                stop_event.wait(min(LIVE_FLUSH_SECONDS, wait_for or LIVE_FLUSH_SECONDS))
                continue

            line_start = handle.tell()
            raw_line = handle.readline(MAX_LOG_LINE + 1)
            complete_line = bool(raw_line and raw_line.endswith(b"\n"))
            consumed = False
            parsed = None
            record_kind = None
            record_timestamp = None
            if raw_line:
                if complete_line:
                    position = handle.tell()
                    consumed = True
                    rotation_quiet_since = None
                    partial_observed_end = None
                    if discarding_oversized:
                        discarding_oversized = False
                    elif len(raw_line) <= MAX_LOG_LINE:
                        record_kind, parsed, record_timestamp = classify_access_record_details(
                            raw_line.decode("utf-8", errors="replace")
                        )
                    else:
                        record_kind = ACCESS_RECORD_UNUSABLE
                elif discarding_oversized or len(raw_line) > MAX_LOG_LINE:
                    # Consume a bounded chunk of an oversized record, but do
                    # not ever parse a later suffix as a standalone record.
                    position = handle.tell()
                    consumed = True
                    if not discarding_oversized:
                        record_kind = ACCESS_RECORD_UNUSABLE
                    discarding_oversized = True
                    rotation_quiet_since = None
                    partial_observed_end = None
                else:
                    # readline() may return an ordinary partial record at EOF.
                    # Reset handoff quiet only for newly observed growth; the
                    # same rewound prefix must not postpone rotation forever.
                    partial_end = handle.tell()
                    if (
                        partial_observed_end is None
                        or partial_end > partial_observed_end
                    ):
                        partial_observed_end = partial_end
                        rotation_quiet_since = None
                    handle.seek(line_start)
                    position = line_start

            if consumed:
                historical = bool(
                    replaying
                    and handle_identity == replay_identity
                    and replay_cutoff is not None
                    and line_start < replay_cutoff
                    and position <= replay_cutoff
                )
                if not historical and record_kind == ACCESS_RECORD_IGNORED:
                    CORRELATION_HEALTH.note_ignored()
                elif not historical and record_kind == ACCESS_RECORD_UNUSABLE:
                    CORRELATION_HEALTH.note_unusable()
                if record_kind == ACCESS_RECORD_VALID and parsed:
                    request_id, status = parsed
                    if not historical:
                        CORRELATION_HEALTH.note_seen()
                    if historical:
                        replay_records[request_id] = (status, record_timestamp)
                        if len(replay_records) >= REPLAY_BATCH_SIZE:
                            apply_replay_batch(time.monotonic())
                    else:
                        if replaying:
                            finish_replay(time.monotonic())
                        queue_live(pending, request_id, status)
                        live_since_flush += 1

                # Reaching the startup byte boundary ends replay even when the
                # log grows continuously and readline() never observes EOF.
                if (
                    replaying
                    and handle_identity == replay_identity
                    and replay_cutoff is not None
                    and position >= replay_cutoff
                ):
                    finish_replay(time.monotonic())

                now = time.monotonic()
                if not replaying and (
                    live_since_flush >= LIVE_BATCH_SIZE
                    or now - last_live_flush >= LIVE_FLUSH_SECONDS
                ):
                    conn = flush_live(conn, pending, now)
                    live_since_flush = 0
                    last_live_flush = now
            else:
                if replaying:
                    at_cutoff = bool(
                        handle_identity == replay_identity
                        and replay_cutoff is not None
                        and position >= replay_cutoff
                    )
                    if at_cutoff:
                        finish_replay(time.monotonic())
                now = time.monotonic()
                if not replaying:
                    conn = flush_live(conn, pending, now)
                    live_since_flush = 0
                    last_live_flush = now
                if rotation_pending:
                    # A replacement pathname can appear before every nginx
                    # worker has released the old inode. Require a timed quiet
                    # EOF, then open/fstat the replacement before releasing the
                    # old descriptor so a path race cannot discard evidence.
                    if rotation_quiet_since is None:
                        rotation_quiet_since = now
                    elif (
                        now - rotation_quiet_since >= ROTATION_DRAIN_SECONDS
                        and now >= handoff_retry_at
                    ):
                        replacement = None
                        try:
                            replacement, _replacement_stat, replacement_identity = (
                                open_access_log_file(path_identity)
                            )
                        except OSError as exc:
                            report_path_outage(exc)
                            handoff_retry_at = now + ERROR_RETRY_SECONDS
                        else:
                            try:
                                finish_replay(now)
                            except Exception:
                                replacement.close()
                                raise
                            old_handle = handle
                            handle = replacement
                            handle_identity = replacement_identity
                            position = 0
                            discarding_oversized = False
                            partial_observed_end = None
                            rotation_quiet_since = None
                            rotation_target_identity = None
                            handoff_retry_at = 0.0
                            old_handle.close()
                            clear_path_outage()
                            CORRELATION_HEALTH.mark_success(pending=len(pending))
                            continue
                stop_event.wait(LIVE_FLUSH_SECONDS)
            # EOF with no traffic is still a successful poll. Advancing this
            # heartbeat distinguishes a quiet site from a wedged tailer.
            # A readable old fd does not make a missing canonical path healthy.
            if canonical_verified and not path_outage_reported:
                CORRELATION_HEALTH.mark_success(pending=len(pending))
            else:
                CORRELATION_HEALTH.set_pending(len(pending))
        except Exception as exc:  # pragma: no cover - runtime resilience
            if isinstance(exc, OSError):
                report_path_outage(exc)
            else:
                print(f"collector: access-log status sync failed: {exc}", flush=True)
                CORRELATION_HEALTH.mark_failure()
            try:
                if conn is not None:
                    conn.close()
            except Exception:
                pass
            conn = None
            # A transient Postgres failure must not close/replay the log from
            # byte zero. Only an error on the active fd invalidates that fd;
            # expected path/open handoff failures are handled above and retain it.
            if isinstance(exc, OSError) and handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
                handle = None
            stop_event.wait(ERROR_RETRY_SECONDS)

    try:
        if handle is not None:
            handle.close()
        if conn is not None:
            conn.close()
    finally:
        CORRELATION_HEALTH.set_thread_up(False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # logdb is started first (compose healthcheck gates us), but tolerate a
    # brief race on cold start and never crash if it isn't ready yet.
    for attempt in range(30):
        try:
            init_db()
            break
        except Exception as exc:  # pragma: no cover - startup resilience
            print(f"collector: waiting for logdb ({attempt}): {exc}", flush=True)
            reset_conn()
            time.sleep(1)
    stop_event = threading.Event()
    status_thread = threading.Thread(
        target=follow_access_log,
        args=(stop_event,),
        name="nginx-status-sync",
        daemon=True,
    )
    status_thread.start()
    try:
        yield
    finally:
        stop_event.set()
        status_thread.join(timeout=2)
        reset_conn()


app = FastAPI(
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


async def collect(_path: str, request: Request) -> Response:
    try:
        site = request.headers.get("x-site")
        client_ip = request.headers.get("x-real-ip") or request.headers.get(
            "x-forwarded-for"
        )
        # Client source TCP port (set by nginx as X-Client-Port) — the join key,
        # with client_ip, that ties this request to its TLS handshake fingerprint.
        raw_port = request.headers.get("x-client-port")
        try:
            client_port = int(raw_port) if raw_port else None
        except (TypeError, ValueError):
            client_port = None
        user_agent = request.headers.get("user-agent")
        # Preserve the wire-level target. Starlette's ``url.path`` is decoded,
        # which would erase the double-encoding used by real exploit probes and
        # defeat the classifier's bounded decode logic.
        scope = getattr(request, "scope", {}) or {}
        raw_path = scope.get("raw_path")
        raw_query = scope.get("query_string")
        if isinstance(raw_path, bytes):
            uri = raw_path.decode("latin-1")
        elif isinstance(raw_path, str):
            uri = raw_path
        else:
            uri = request.url.path
        if isinstance(raw_query, bytes):
            query = raw_query.decode("latin-1")
        elif isinstance(raw_query, str):
            query = raw_query
        else:
            query = request.url.query
        if query:
            uri = f"{uri}?{query}"
        uri = uri[:MAX_URI_CHARS]
        headers = dict(request.headers)
        request_id = request.headers.get("x-request-id")
        if not request_id or not REQUEST_ID_RE.fullmatch(request_id):
            request_id = None

        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO all_visits "
                "(site, client_ip, client_port, user_agent, method, uri, headers, request_id) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (site, client_ip, client_port, user_agent, request.method, uri,
                 Json(headers), request_id),
            )
        CORRELATION_HEALTH.note_mirror_inserted()
    except Exception as exc:
        # Fire-and-forget: log and move on, never propagate to the client.
        print(f"collector: insert failed: {exc}", flush=True)
        CORRELATION_HEALTH.note_mirror_insert_error()
        reset_conn()

    return Response(status_code=204)


@app.middleware("http")
async def collect_every_http_request(request: Request, _call_next) -> Response:
    """Record before route dispatch so no path or uncommon method can bypass us.

    Scanner verbs such as TRACE, CONNECT, PROPFIND, and MKCOL are valid evidence
    even though FastAPI would normally return 405. The collector is an internal
    mirror sink—not a browsable API—so every HTTP request is terminal here.
    """
    if request.url.path == "/metrics" and request.method in {"GET", "HEAD"}:
        # Prometheus reaches this exact endpoint on a private bridge. It never
        # enters all_visits and cannot affect the mirrored crawler request path.
        return correlation_metrics_response(head=request.method == "HEAD")
    return await collect(request.url.path.lstrip("/"), request)
