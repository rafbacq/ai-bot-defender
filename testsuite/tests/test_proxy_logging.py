"""Reverse-proxy logging path: request mirror + fingerprint beacon + TLS/TCP shipper.

The proxy is the single entry point that records all traffic. These tests drive
the three collector apps directly (DB connection stubbed) and assert the exact
rows they would write:

  * ``proxy/collector`` — one ``all_visits`` row per mirrored request, tagged with
    the canonical site and the (client_ip, client_port) join key.
  * ``proxy/fp-collector`` — one ``browser_fingerprints`` row per fp.js beacon,
    with normalized numeric fields, ignoring oversized / non-JSON bodies.
  * ``proxy/tls-shipper`` — Zeek ssl.log/tcp_syn.log rows mapped to
    ``tls_handshakes`` / ``tcp_fingerprints`` with a p0f-style OS inference + JA4T.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from .conftest import DummyConn, FakeRequest, load_module_from_path


class _StatusCursor:
    def __init__(self, conn):
        self.conn = conn
        self._rows = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        self.conn.calls.append((sql, params))
        if "RETURNING a.request_id" in sql:
            request_ids = params[0]
            matched = self.conn.match(request_ids)
            self._rows = [(request_id,) for request_id in matched]
            if self.conn.on_returning:
                self.conn.on_returning(request_ids)

    def fetchall(self):
        return self._rows


class _StatusConn:
    def __init__(self, *, match=None, on_returning=None):
        self.calls = []
        self.closed = False
        self.match = match or (lambda request_ids: request_ids)
        self.on_returning = on_returning

    def cursor(self):
        return _StatusCursor(self)

    def close(self):
        self.closed = True


def _access_line(request_id, status=200, uri="/", record_time=None):
    record = {
        "request_id": request_id,
        "status": status,
        "uri": uri,
    }
    if record_time is not None:
        record["time"] = record_time
    return (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")


def _updated_ids(conn):
    return {
        request_id
        for sql, params in conn.calls
        if "unnest(" in sql
        for request_id in params[0]
    }


def _retried_ids(conn):
    return {
        request_id
        for sql, params in conn.calls
        if "RETURNING a.request_id" in sql
        for request_id in params[0]
    }


def _returning_batches(conn):
    return [
        list(params[0])
        for sql, params in conn.calls
        if "RETURNING a.request_id" in sql
    ]


def _wait_until(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_request_collector_writes_one_all_visits_row(repo_root, monkeypatch):
    """The mirror collector records site, IP, source port, method, URI+query, and UA."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")

    module = load_module_from_path("proxy_collector_app", repo_root / "proxy" / "collector" / "app.py")
    calls = []
    monkeypatch.setattr(module, "get_conn", lambda: DummyConn(calls))

    response = asyncio.run(module.collect("deep/path", FakeRequest(
        method="PATCH", path="/deep/path", query="x=1",
        headers={"x-site": "site-001", "x-real-ip": "203.0.113.10",
                 "x-client-port": "55001", "x-request-id": "a" * 32,
                 "user-agent": "SyntheticBot/1.0"},
    )))

    assert response.status_code == 204
    insert = [c for c in calls if "INSERT INTO all_visits" in c[0]][0]
    assert insert[1][:6] == ("site-001", "203.0.113.10", 55001, "SyntheticBot/1.0", "PATCH", "/deep/path?x=1")
    assert insert[1][-1] == "a" * 32
    assert module.CORRELATION_HEALTH.snapshot()["mirror_rows_inserted_total"] == 1


def test_request_collector_classifies_authoritative_ignored_and_unusable_records(repo_root):
    """Telemetry exclusions stay distinct from malformed matched-site evidence."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_status_parser", repo_root / "proxy" / "collector" / "app.py"
    )

    request_id = "0123456789abcdef" * 2
    assert module.parse_access_record(json.dumps({
        "request_id": request_id, "status": 502, "uri": "/",
    })) == (request_id, 502)
    unusable = (
        "not-json",
        "null",
        "[]",
        json.dumps({"request_id": "bad", "status": 200, "uri": "/"}),
        json.dumps({"request_id": request_id, "status": 99, "uri": "/"}),
        json.dumps({"status": 200, "uri": "/"}),
        "x" * (module.MAX_LOG_LINE + 1),
    )
    for line in unusable:
        assert module.parse_access_record(line) is None
        assert module.classify_access_record(line) == (
            module.ACCESS_RECORD_UNUSABLE, None,
        )
    for uri in (
        "/__fpbeacon", "/__fpbeacon?phase=load", "/__abd_health",
        "/_mirror", "/.well-known/acme-challenge/token",
    ):
        # Expected non-mirrored paths are ignored even if their request-id/status
        # fields are absent; they must never inflate parser-drift alerts.
        line = json.dumps({"uri": uri})
        assert module.parse_access_record(line) is None
        assert module.classify_access_record(line) == (
            module.ACCESS_RECORD_IGNORED, None,
        )


def test_replay_timestamp_accepts_aware_offsets_but_never_changes_live_parsing(
    repo_root,
):
    """Replay metadata is strict while the established live parser stays compatible."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_replay_timestamp",
        repo_root / "proxy" / "collector" / "app.py",
    )
    request_id = "1" * 32
    instant = datetime(2026, 7, 16, 12, 30, tzinfo=timezone.utc)
    offset_instant = instant.astimezone(timezone(timedelta(hours=5, minutes=30)))

    for raw_time in (
        instant.isoformat().replace("+00:00", "Z"),
        offset_instant.isoformat(),
    ):
        line = _access_line(request_id, 202, record_time=raw_time).decode()
        kind, payload, timestamp = module.classify_access_record_details(line)
        assert (kind, payload) == (
            module.ACCESS_RECORD_VALID,
            (request_id, 202),
        )
        assert timestamp == pytest.approx(instant.timestamp())
        assert module.parse_access_record(line) == (request_id, 202)

    for raw_time in (None, "not-a-time", "2026-07-16T12:30:00"):
        line = _access_line(request_id, 202, record_time=raw_time).decode()
        kind, payload, timestamp = module.classify_access_record_details(line)
        assert (kind, payload, timestamp) == (
            module.ACCESS_RECORD_VALID,
            (request_id, 202),
            None,
        )
        # Missing/bad replay time must not invalidate a genuinely live record.
        assert module.parse_access_record(line) == (request_id, 202)

    startup = instant.timestamp()
    assert module.replay_record_is_recent(startup, startup)
    assert module.replay_record_is_recent(
        startup - module.PENDING_TTL_SECONDS,
        startup,
    )
    assert module.replay_record_is_recent(
        startup + module.PENDING_TTL_SECONDS / 2,
        startup,
    ), "a small aware clock skew around startup is still inside the race window"
    assert not module.replay_record_is_recent(
        startup - module.PENDING_TTL_SECONDS - 0.001,
        startup,
    )
    assert not module.replay_record_is_recent(
        startup + module.PENDING_TTL_SECONDS + 0.001,
        startup,
    )
    assert not module.replay_record_is_recent(None, startup)


def test_response_status_update_is_correlated_by_request_id(repo_root):
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_status_update", repo_root / "proxy" / "collector" / "app.py"
    )
    calls = []

    assert module.update_response_status(DummyConn(calls), "b" * 32, 200) is True
    assert "UPDATE all_visits SET response_status" in calls[0][0]
    assert calls[0][1] == (200, "b" * 32)


def test_response_status_batch_is_one_query_for_large_replay(repo_root):
    """Historical correlation is bounded by query count, not one UPDATE per row."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_status_batch", repo_root / "proxy" / "collector" / "app.py"
    )
    conn = _StatusConn()
    records = {f"{index:032x}": 200 for index in range(501)}

    module.update_response_status_batch(conn, records)

    assert len(conn.calls) == 1
    assert len(conn.calls[0][1][0]) == len(conn.calls[0][1][1]) == 501


def test_replay_batch_queues_every_recent_initial_miss_without_tail_loss(repo_root):
    """All >32 recent misses are retried; first-pass matches are not credited."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_complete_replay_batch",
        repo_root / "proxy" / "collector" / "app.py",
    )
    startup = time.time()
    request_ids = [f"{index:032x}" for index in range(81)]
    first_pass_match = request_ids[0]
    match_calls = 0

    def match(requested):
        nonlocal match_calls
        match_calls += 1
        return [first_pass_match] if match_calls == 1 else requested

    conn = _StatusConn(match=match)
    records = {
        request_id: (200, startup)
        for request_id in request_ids
    }
    pending = {}

    returned_conn, queued = module.flush_replay(
        conn,
        records,
        pending,
        startup,
        now=0.0,
    )

    assert returned_conn is conn
    assert queued == len(request_ids) - 1
    assert len(pending) == 80
    assert first_pass_match not in pending
    assert all(
        entry.startup_candidate and not entry.miss_on_drop
        for entry in pending.values()
    )
    assert len(_returning_batches(conn)) == 1
    assert len(_returning_batches(conn)[0]) == 81

    module.flush_live(conn, pending, now=0.0)
    health = module.CORRELATION_HEALTH.snapshot()
    assert pending == {}
    assert health["records_correlated_total"] == 80
    assert health["startup_race_correlated_total"] == 80
    assert health["startup_unresolved_total"] == 0


def test_startup_replay_runs_returning_for_every_batch(repo_root, tmp_path, monkeypatch):
    """A 501-row startup replay proves both the full and final short batch."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_each_replay_batch",
        repo_root / "proxy" / "collector" / "app.py",
    )
    access_log = tmp_path / "access.log"
    recorded_at = datetime.now(timezone.utc).isoformat()
    access_log.write_bytes(b"".join(
        _access_line(f"{index:032x}", record_time=recorded_at)
        for index in range(module.REPLAY_BATCH_SIZE + 1)
    ))
    conn = _StatusConn()
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.005)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    try:
        assert _wait_until(lambda: len(_returning_batches(conn)) == 2)
        assert [len(batch) for batch in _returning_batches(conn)] == [500, 1]
        health = module.CORRELATION_HEALTH.snapshot()
        assert health["pending"] == 0
        assert health["startup_race_correlated_total"] == 0
        assert health["startup_unresolved_total"] == 0
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_live_status_retry_uses_exponential_backoff_and_ttl(repo_root):
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_status_retry", repo_root / "proxy" / "collector" / "app.py"
    )
    conn = _StatusConn(match=lambda _request_ids: [])
    pending = {}
    request_id = "c" * 32
    module.queue_live(pending, request_id, 204, now=0.0)

    module.flush_live(conn, pending, now=0.0)
    assert len(conn.calls) == 1
    assert (pending[request_id].next_attempt, pending[request_id].delay) == (
        0.25,
        0.5,
    )
    assert pending[request_id].miss_on_drop is True
    assert pending[request_id].startup_candidate is False
    module.flush_live(conn, pending, now=0.1)
    assert len(conn.calls) == 1, "retry must not spin before its deadline"
    module.flush_live(conn, pending, now=0.25)
    assert len(conn.calls) == 2
    assert (pending[request_id].next_attempt, pending[request_id].delay) == (
        0.75,
        1.0,
    )
    assert pending[request_id].miss_on_drop is True
    module.flush_live(conn, pending, now=module.PENDING_TTL_SECONDS)
    assert request_id not in pending
    health = module.CORRELATION_HEALTH.snapshot()
    assert health["records_missed_total"] == 1
    assert health["pending"] == 0


def test_pending_loss_provenance_survives_duplicates_and_queue_eviction(
    repo_root, monkeypatch,
):
    """Only live evidence contributes to misses, even across refresh and eviction."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_pending_provenance",
        repo_root / "proxy" / "collector" / "app.py",
    )
    historical_id, second_historical_id = "2" * 32, "3" * 32
    live_id, replacement_id = "4" * 32, "5" * 32
    pending = {}
    monkeypatch.setattr(module, "MAX_LIVE_PENDING", 1)

    module.queue_live(
        pending,
        historical_id,
        200,
        now=0.0,
        miss_on_drop=False,
        startup_candidate=True,
    )
    # A duplicate live observation upgrades a historical candidate permanently.
    module.queue_live(pending, historical_id, 201, now=0.1)
    assert pending[historical_id].miss_on_drop is True
    assert pending[historical_id].startup_candidate is True
    module.queue_live(
        pending,
        historical_id,
        202,
        now=0.2,
        miss_on_drop=False,
        startup_candidate=True,
    )
    assert pending[historical_id].miss_on_drop is True
    assert pending[historical_id].startup_candidate is True

    # Evicting that now-live entry counts exactly once.
    module.queue_live(
        pending,
        second_historical_id,
        200,
        now=0.3,
        miss_on_drop=False,
        startup_candidate=True,
    )
    health = module.CORRELATION_HEALTH.snapshot()
    assert health["records_missed_total"] == 1
    assert health["startup_unresolved_total"] == 1

    # Evicting a historical-only entry does not count; evicting live still does.
    module.queue_live(pending, live_id, 200, now=0.4)
    health = module.CORRELATION_HEALTH.snapshot()
    assert health["records_missed_total"] == 1
    assert health["startup_unresolved_total"] == 2
    module.queue_live(
        pending,
        replacement_id,
        200,
        now=0.5,
        miss_on_drop=False,
        startup_candidate=True,
    )
    health = module.CORRELATION_HEALTH.snapshot()
    assert health["records_missed_total"] == 2
    assert health["startup_unresolved_total"] == 2
    assert pending[replacement_id].miss_on_drop is False
    assert pending[replacement_id].startup_candidate is True


def test_expired_status_is_counted_even_when_same_batch_db_update_fails(
    repo_root, monkeypatch,
):
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_status_expiry_error",
        repo_root / "proxy" / "collector" / "app.py",
    )
    pending = {
        "a" * 32: module.PendingStatus(200, 0.0, 0.0, 0.25, True, False),
        "c" * 32: module.PendingStatus(202, 0.0, 0.0, 0.25, False, True),
        "b" * 32: module.PendingStatus(201, 99.0, 99.0, 0.25, True, False),
    }
    module.CORRELATION_HEALTH.set_pending(3)

    def db_down(*_args, **_kwargs):
        raise RuntimeError("status DB unavailable")

    monkeypatch.setattr(module, "update_response_status_batch", db_down)
    with pytest.raises(RuntimeError, match="unavailable"):
        module.flush_live(_StatusConn(), pending, now=100.0)

    assert set(pending) == {"b" * 32}
    health = module.CORRELATION_HEALTH.snapshot()
    assert health["records_missed_total"] == 1
    assert health["startup_unresolved_total"] == 1
    assert health["pending"] == 1


def test_status_sync_health_recovers_and_heartbeats_without_traffic(
    repo_root, tmp_path, monkeypatch,
):
    """Each initial/path outage reports once, recovers, and stays stop-responsive."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_status_health", repo_root / "proxy" / "collector" / "app.py"
    )
    access_log = tmp_path / "access.log"
    rotated = tmp_path / "access.log.1"
    outage_logs = []
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "ERROR_RETRY_SECONDS", 0.01)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.01)
    monkeypatch.setattr(module, "MISSING_PATH_GRACE_SECONDS", 0.03)
    monkeypatch.setattr(module, "status_conn", lambda: _StatusConn())
    monkeypatch.setattr(
        module,
        "print",
        lambda *parts, **_kwargs: outage_logs.append(" ".join(map(str, parts))),
        raising=False,
    )
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()

    assert _wait_until(
        lambda: module.CORRELATION_HEALTH.snapshot()["errors_total"] > 0
    )
    failed = module.CORRELATION_HEALTH.snapshot()
    assert failed["healthy"] == 0
    assert failed["access_log_present"] == 0
    assert failed["thread_up"] == 1
    assert failed["last_success_unixtime"] == 0
    time.sleep(module.ERROR_RETRY_SECONDS * 4)
    assert module.CORRELATION_HEALTH.snapshot()["errors_total"] == 1
    assert len(outage_logs) == 1

    access_log.write_bytes(b"")
    assert _wait_until(
        lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
    )
    recovered = module.CORRELATION_HEALTH.snapshot()
    assert recovered["access_log_present"] == 1
    assert recovered["last_success_unixtime"] > 0

    first_heartbeat = recovered["last_success_unixtime"]
    assert _wait_until(
        lambda: module.CORRELATION_HEALTH.snapshot()["last_success_unixtime"]
        > first_heartbeat
    ), "quiet EOF polls must keep advancing the heartbeat"

    os.rename(access_log, rotated)
    assert _wait_until(
        lambda: module.CORRELATION_HEALTH.snapshot()["errors_total"] == 2
        and module.CORRELATION_HEALTH.snapshot()["healthy"] == 0
    )
    second_outage = module.CORRELATION_HEALTH.snapshot()
    time.sleep(module.MISSING_PATH_GRACE_SECONDS * 2)
    assert module.CORRELATION_HEALTH.snapshot()["errors_total"] == 2
    assert module.CORRELATION_HEALTH.snapshot()[
        "last_success_unixtime"
    ] == second_outage["last_success_unixtime"]
    assert len(outage_logs) == 2

    stop.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert module.CORRELATION_HEALTH.snapshot()["thread_up"] == 0


def test_initial_missing_access_log_reports_once_and_stop_interrupts_retry(
    repo_root, tmp_path, monkeypatch,
):
    """An absent first log has one outage transition and an interruptible wait."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_initial_missing_stop",
        repo_root / "proxy" / "collector" / "app.py",
    )
    outage_logs = []
    monkeypatch.setattr(module, "ACCESS_LOG", tmp_path / "never-created.log")
    monkeypatch.setattr(module, "ERROR_RETRY_SECONDS", 10.0)
    monkeypatch.setattr(
        module,
        "print",
        lambda *parts, **_kwargs: outage_logs.append(" ".join(map(str, parts))),
        raising=False,
    )
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    assert _wait_until(
        lambda: module.CORRELATION_HEALTH.snapshot()["errors_total"] == 1
    )
    failed = module.CORRELATION_HEALTH.snapshot()
    assert failed["healthy"] == 0
    assert failed["access_log_present"] == 0
    assert failed["last_success_unixtime"] == 0
    assert len(outage_logs) == 1

    started_stopping = time.monotonic()
    stop.set()
    thread.join(timeout=0.25)
    assert not thread.is_alive()
    assert time.monotonic() - started_stopping < 0.25
    assert module.CORRELATION_HEALTH.snapshot()["errors_total"] == 1
    assert len(outage_logs) == 1


def test_delayed_initial_log_uses_successful_open_as_replay_race_timestamp(
    repo_root, tmp_path, monkeypatch,
):
    """A delayed nginx log can still promote a genuinely recent pre-cutoff row."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_delayed_initial_log",
        repo_root / "proxy" / "collector" / "app.py",
    )
    request_id = "d" * 32
    access_log = tmp_path / "access.log"
    attempts = 0

    def miss_then_match(request_ids):
        nonlocal attempts
        attempts += 1
        return [] if attempts == 1 else request_ids

    conn = _StatusConn(match=miss_then_match)
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "PENDING_TTL_SECONDS", 0.05)
    monkeypatch.setattr(module, "ERROR_RETRY_SECONDS", 0.01)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.01)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    try:
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["errors_total"] > 0
        )
        # Exceed the scaled replay TTL before nginx creates its first log. A
        # thread-start timestamp would now reject the otherwise recent record.
        time.sleep(module.PENDING_TTL_SECONDS * 2)
        access_log.write_bytes(_access_line(
            request_id,
            record_time=datetime.now(timezone.utc).isoformat(),
        ))
        assert _wait_until(lambda: len(_returning_batches(conn)) >= 2)
        health = module.CORRELATION_HEALTH.snapshot()
        assert health["records_correlated_total"] == 1
        assert health["startup_race_correlated_total"] == 1
        assert health["records_missed_total"] == 0
        assert health["healthy"] == 1
        assert health["access_log_present"] == 1
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_status_tailer_counts_live_unusable_records_but_not_replay_or_telemetry(
    repo_root, tmp_path, monkeypatch,
):
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_status_classification",
        repo_root / "proxy" / "collector" / "app.py",
    )
    access_log = tmp_path / "access.log"
    # Historical malformed data must not re-alert on every collector restart.
    access_log.write_text('{"status":200,"uri":"/"}\n', encoding="utf-8")
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.01)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    assert _wait_until(
        lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
    )
    assert module.CORRELATION_HEALTH.snapshot()["records_unusable_total"] == 0

    with access_log.open("ab", buffering=0) as writer:
        writer.write(b'{"uri":"/__abd_health"}\n')
        writer.write(b'{"status":200,"uri":"/"}\n')

    assert _wait_until(
        lambda: module.CORRELATION_HEALTH.snapshot()["records_ignored_total"] == 1
        and module.CORRELATION_HEALTH.snapshot()["records_unusable_total"] == 1
    )
    health = module.CORRELATION_HEALTH.snapshot()
    assert health["records_seen_total"] == 0
    assert health["errors_total"] == 0

    stop.set()
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_recent_historical_status_is_promoted_for_startup_race_correlation(
    repo_root, tmp_path, monkeypatch,
):
    """A timestamped pre-cutoff record gets one replay plus bounded race retry."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_recent_replay",
        repo_root / "proxy" / "collector" / "app.py",
    )
    request_id = "6" * 32
    access_log = tmp_path / "access.log"
    access_log.write_bytes(_access_line(
        request_id,
        203,
        record_time=datetime.now(timezone.utc).isoformat(),
    ))
    attempts = 0

    def miss_then_match(request_ids):
        nonlocal attempts
        attempts += 1
        return [] if attempts == 1 else request_ids

    conn = _StatusConn(match=miss_then_match)
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.01)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    try:
        assert _wait_until(lambda: len(_returning_batches(conn)) >= 2)
        health = module.CORRELATION_HEALTH.snapshot()
        assert health["records_correlated_total"] == 1
        assert health["startup_race_correlated_total"] == 1
        assert health["startup_unresolved_total"] == 0
        assert health["records_missed_total"] == 0
        assert health["pending"] == 0
        assert len(_returning_batches(conn)) == 2
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_stale_or_unusable_historical_times_are_one_shot_and_never_promoted(
    repo_root, tmp_path, monkeypatch,
):
    """Stale, missing, malformed, and naive replay times cannot become pending."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_stale_replay",
        repo_root / "proxy" / "collector" / "app.py",
    )
    request_ids = [f"{value:032x}" for value in range(7, 11)]
    stale = (datetime.now(timezone.utc) - timedelta(hours=1)).astimezone(
        timezone(timedelta(hours=-4))
    ).isoformat()
    access_log = tmp_path / "access.log"
    access_log.write_bytes(b"".join((
        _access_line(request_ids[0], record_time=stale),
        _access_line(request_ids[1]),
        _access_line(request_ids[2], record_time="not-a-time"),
        _access_line(request_ids[3], record_time="2026-07-16T12:30:00"),
    )))
    conn = _StatusConn(match=lambda _request_ids: [])
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.01)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    try:
        assert _wait_until(lambda: set(request_ids) <= _updated_ids(conn))
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
        )
        time.sleep(0.05)
        assert len(_returning_batches(conn)) == 1
        health = module.CORRELATION_HEALTH.snapshot()
        assert health["records_missed_total"] == 0
        assert health["startup_unresolved_total"] == 0
        assert health["pending"] == 0
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_recent_historical_unmatched_expiry_does_not_count_as_live_loss(
    repo_root, tmp_path, monkeypatch,
):
    """A startup-race candidate may retry and expire without raising missed."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_historical_expiry",
        repo_root / "proxy" / "collector" / "app.py",
    )
    request_id = "b" * 32
    access_log = tmp_path / "access.log"
    access_log.write_bytes(_access_line(
        request_id,
        record_time=datetime.now(timezone.utc).isoformat(),
    ))
    conn = _StatusConn(match=lambda _request_ids: [])
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "PENDING_TTL_SECONDS", 0.5)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.01)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    try:
        assert _wait_until(lambda: request_id in _retried_ids(conn))
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["pending"] == 0,
            timeout=2.0,
        )
        health = module.CORRELATION_HEALTH.snapshot()
        assert health["records_correlated_total"] == 0
        assert health["records_missed_total"] == 0
        assert health["startup_unresolved_total"] == 1
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_post_cutoff_unmatched_expiry_counts_as_live_loss_without_timestamp(
    repo_root, tmp_path, monkeypatch,
):
    """A true post-cutoff record stays parseable and increments missed on expiry."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_live_expiry",
        repo_root / "proxy" / "collector" / "app.py",
    )
    request_id = "c" * 32
    access_log = tmp_path / "access.log"
    access_log.write_bytes(b"")
    conn = _StatusConn(match=lambda _request_ids: [])
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "PENDING_TTL_SECONDS", 0.2)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.01)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    try:
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
        )
        with access_log.open("ab", buffering=0) as writer:
            writer.write(_access_line(request_id))
        assert _wait_until(lambda: request_id in _retried_ids(conn))
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["records_missed_total"] == 1
            and module.CORRELATION_HEALTH.snapshot()["pending"] == 0,
            timeout=2.0,
        )
        health = module.CORRELATION_HEALTH.snapshot()
        assert health["records_seen_total"] == 1
        assert health["records_correlated_total"] == 0
        assert health["startup_unresolved_total"] == 0
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_collector_metrics_are_bounded_private_telemetry_not_research_rows(
    repo_root, monkeypatch,
):
    httpx = pytest.importorskip("httpx")
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_metrics", repo_root / "proxy" / "collector" / "app.py"
    )
    db_calls = []
    monkeypatch.setattr(module, "get_conn", lambda: DummyConn(db_calls))
    module.CORRELATION_HEALTH.set_thread_up(True)
    module.CORRELATION_HEALTH.mark_success(pending=3)

    async def exercise():
        transport = httpx.ASGITransport(app=module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://collector") as client:
            return await client.get("/metrics"), await client.head("/metrics")

    response, head = asyncio.run(exercise())
    assert response.status_code == head.status_code == 200
    assert "abd_collector_status_sync_healthy 1" in response.text
    assert "abd_collector_status_pending 3" in response.text
    assert "abd_collector_status_records_unusable_total 0" in response.text
    assert "abd_collector_status_startup_race_correlated_total 0" in response.text
    assert "abd_collector_status_startup_unresolved_total 0" in response.text
    assert "abd_collector_mirror_rows_inserted_total 0" in response.text
    assert len(response.text.splitlines()) == len(module._METRICS) * 3
    assert head.content == b""
    assert db_calls == [], "/metrics must never create an all_visits row"


def test_access_log_tailer_waits_for_partial_line(repo_root, tmp_path, monkeypatch):
    """An access record split across writes must be correlated exactly once."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_partial_tail", repo_root / "proxy" / "collector" / "app.py"
    )
    access_log = tmp_path / "access.log"
    access_log.write_bytes(b"")
    conn = _StatusConn()
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    assert _wait_until(lambda: thread.is_alive())
    time.sleep(module.LIVE_FLUSH_SECONDS * 1.2)

    request_id = "d" * 32
    line = _access_line(request_id, 404)
    with access_log.open("ab", buffering=0) as writer:
        writer.write(line[:-1])
        time.sleep(module.LIVE_FLUSH_SECONDS * 1.2)
        assert request_id not in _updated_ids(conn)
        writer.write(line[-1:])
    assert _wait_until(lambda: request_id in _updated_ids(conn))

    stop.set()
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_partial_record_crossing_startup_cutoff_is_live_and_can_miss(
    repo_root, tmp_path, monkeypatch,
):
    """A pre-open prefix completed post-open is not historical replay evidence."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_partial_cutoff",
        repo_root / "proxy" / "collector" / "app.py",
    )
    request_id = "9" * 32
    line = _access_line(request_id, 418)
    access_log = tmp_path / "access.log"
    access_log.write_bytes(line[:-1])
    conn = _StatusConn(match=lambda _request_ids: [])
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "PENDING_TTL_SECONDS", 0.12)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.01)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    try:
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
        )
        with access_log.open("ab", buffering=0) as writer:
            writer.write(line[-1:])
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["records_seen_total"] == 1
        )
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["records_missed_total"] == 1
            and module.CORRELATION_HEALTH.snapshot()["pending"] == 0
        )
        health = module.CORRELATION_HEALTH.snapshot()
        assert health["startup_race_correlated_total"] == 0
        assert health["startup_unresolved_total"] == 0
        assert len(_returning_batches(conn)) >= 1
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_replacement_open_failure_retains_old_fd_and_stays_unhealthy(
    repo_root, tmp_path, monkeypatch,
):
    """A stat-visible but unreadable replacement cannot mask handoff failure."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_replacement_open_failure",
        repo_root / "proxy" / "collector" / "app.py",
    )
    real_path = tmp_path / "access.log"
    rotated = tmp_path / "access.log.1"
    real_path.write_bytes(b"")
    original = real_path.stat()
    original_identity = (original.st_dev, original.st_ino)

    class FlakyReplacementPath:
        fail_replacement = True
        open_count = 0

        def open(self, mode):
            self.open_count += 1
            opened = real_path.open(mode)
            opened_stat = os.fstat(opened.fileno())
            identity = (opened_stat.st_dev, opened_stat.st_ino)
            if self.fail_replacement and identity != original_identity:
                opened.close()
                raise PermissionError("replacement temporarily unreadable")
            return opened

        def stat(self):
            return real_path.stat()

    flaky_path = FlakyReplacementPath()
    outage_logs = []
    conn = _StatusConn()
    monkeypatch.setattr(module, "ACCESS_LOG", flaky_path)
    monkeypatch.setattr(module, "ROTATION_DRAIN_SECONDS", 0.02)
    monkeypatch.setattr(module, "ERROR_RETRY_SECONDS", 0.04)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.005)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    monkeypatch.setattr(
        module,
        "print",
        lambda *parts, **_kwargs: outage_logs.append(" ".join(map(str, parts))),
        raising=False,
    )
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    try:
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
        )
        old_id, new_id = "a" * 32, "b" * 32
        with real_path.open("ab", buffering=0) as old_writer:
            os.rename(real_path, rotated)
            real_path.write_bytes(_access_line(new_id, 201))
            assert _wait_until(
                lambda: module.CORRELATION_HEALTH.snapshot()["errors_total"] == 1
                and module.CORRELATION_HEALTH.snapshot()["healthy"] == 0
                and module.CORRELATION_HEALTH.snapshot()["access_log_present"] == 0
            )
            failed = module.CORRELATION_HEALTH.snapshot()
            old_writer.write(_access_line(old_id, 202))
            assert _wait_until(lambda: old_id in _updated_ids(conn))
            time.sleep(module.ERROR_RETRY_SECONDS * 2)
            still_failed = module.CORRELATION_HEALTH.snapshot()
            assert still_failed["errors_total"] == 1
            assert still_failed["healthy"] == 0
            assert still_failed["last_success_unixtime"] == failed[
                "last_success_unixtime"
            ]
            assert len(outage_logs) == 1
            assert flaky_path.open_count <= 4, "handoff retries must be time-bounded"

            flaky_path.fail_replacement = False
        assert _wait_until(
            lambda: new_id in _updated_ids(conn)
            and module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
        )
        assert module.CORRELATION_HEALTH.snapshot()["access_log_present"] == 1
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_open_access_log_file_opens_once_and_closes_failed_fstat(
    repo_root, tmp_path, monkeypatch,
):
    """Verified handoff neither double-opens nor leaks an fd on fstat failure."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_verified_open",
        repo_root / "proxy" / "collector" / "app.py",
    )
    real_path = tmp_path / "access.log"
    real_path.write_bytes(b"")

    class CountingPath:
        def __init__(self):
            self.opens = []

        def open(self, mode):
            opened = real_path.open(mode)
            self.opens.append(opened)
            return opened

    counting_path = CountingPath()
    monkeypatch.setattr(module, "ACCESS_LOG", counting_path)
    handle, _opened_stat, identity = module.open_access_log_file()
    try:
        assert len(counting_path.opens) == 1
        assert identity == (real_path.stat().st_dev, real_path.stat().st_ino)
        assert not handle.closed
    finally:
        handle.close()

    def fail_fstat(_fd):
        raise OSError("fstat failed")

    monkeypatch.setattr(module.os, "fstat", fail_fstat)
    with pytest.raises(OSError, match="fstat failed"):
        module.open_access_log_file()
    assert len(counting_path.opens) == 2
    assert counting_path.opens[-1].closed


def test_copytruncate_reopens_fresh_without_duplicate_status_storm(
    repo_root, tmp_path, monkeypatch,
):
    """Same-inode truncation swaps readers and reads each generation once."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_copytruncate_fresh_reader",
        repo_root / "proxy" / "collector" / "app.py",
    )
    access_log = tmp_path / "access.log"
    access_log.write_bytes(b"")
    conn = _StatusConn()
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.005)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    old_ids = [f"{index:032x}" for index in range(160)]
    new_id = "f" * 32
    try:
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
        )
        with access_log.open("ab", buffering=0) as writer:
            writer.write(b"".join(_access_line(request_id) for request_id in old_ids))
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["records_seen_total"] == 160
        )
        inode_before = access_log.stat().st_ino
        access_log.write_bytes(_access_line(new_id, 206))
        assert access_log.stat().st_ino == inode_before
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["records_seen_total"] == 161
            and new_id in _updated_ids(conn)
        )
        time.sleep(module.LIVE_FLUSH_SECONDS * 6)
        assert module.CORRELATION_HEALTH.snapshot()["records_seen_total"] == 161
        appearances = [
            request_id
            for batch in _returning_batches(conn)
            for request_id in batch
        ]
        assert len(appearances) == len(set(appearances)) == 161
        assert module.CORRELATION_HEALTH.snapshot()["errors_total"] == 0
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_copytruncate_reopen_failure_is_quiet_and_never_reads_stale_buffer(
    repo_root, tmp_path, monkeypatch,
):
    """Failed fresh-open retains unhealthy state until a verified retry succeeds."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_copytruncate_open_failure",
        repo_root / "proxy" / "collector" / "app.py",
    )
    real_path = tmp_path / "access.log"
    real_path.write_bytes(b"")

    class FlakyPath:
        def __init__(self):
            self.open_count = 0
            self.fail_reopen = False

        def open(self, mode):
            self.open_count += 1
            if self.fail_reopen and self.open_count > 1:
                raise PermissionError("copytruncate generation unreadable")
            return real_path.open(mode)

        def stat(self):
            return real_path.stat()

    flaky_path = FlakyPath()
    outage_logs = []
    conn = _StatusConn()
    monkeypatch.setattr(module, "ACCESS_LOG", flaky_path)
    monkeypatch.setattr(module, "ERROR_RETRY_SECONDS", 0.04)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.005)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    monkeypatch.setattr(
        module,
        "print",
        lambda *parts, **_kwargs: outage_logs.append(" ".join(map(str, parts))),
        raising=False,
    )
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    old_ids = [f"{index:032x}" for index in range(64)]
    new_id = "e" * 32
    try:
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
        )
        with real_path.open("ab", buffering=0) as writer:
            writer.write(b"".join(_access_line(request_id) for request_id in old_ids))
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["records_seen_total"] == 64
        )
        flaky_path.fail_reopen = True
        real_path.write_bytes(_access_line(new_id, 206))
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["errors_total"] == 1
            and module.CORRELATION_HEALTH.snapshot()["healthy"] == 0
            and module.CORRELATION_HEALTH.snapshot()["access_log_present"] == 0
        )
        failed = module.CORRELATION_HEALTH.snapshot()
        time.sleep(module.ERROR_RETRY_SECONDS * 2)
        still_failed = module.CORRELATION_HEALTH.snapshot()
        assert still_failed["errors_total"] == 1
        assert still_failed["records_seen_total"] == 64
        assert still_failed["last_success_unixtime"] == failed[
            "last_success_unixtime"
        ]
        assert new_id not in _updated_ids(conn)
        assert len(outage_logs) == 1
        assert flaky_path.open_count <= 4, "fresh-open retries must not busy-spin"

        flaky_path.fail_reopen = False
        assert _wait_until(
            lambda: new_id in _updated_ids(conn)
            and module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
        )
        assert module.CORRELATION_HEALTH.snapshot()["records_seen_total"] == 65
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_access_log_tailer_retains_missing_old_inode_then_follows_replacement(
    repo_root, tmp_path, monkeypatch,
):
    """A late old-inode write survives the full marker/reopen pathname gap."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_rotation_tail", repo_root / "proxy" / "collector" / "app.py"
    )
    access_log = tmp_path / "access.log"
    rotated = tmp_path / "access.log.1"
    access_log.write_bytes(b"")
    conn = _StatusConn()
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "MISSING_PATH_GRACE_SECONDS", 0.05)
    monkeypatch.setattr(module, "ROTATION_DRAIN_SECONDS", 0.03)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.01)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    try:
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
        )
        old_id, new_id = "e" * 32, "f" * 32
        with access_log.open("ab", buffering=0) as old_writer:
            os.rename(access_log, rotated)
            # Wait beyond the scaled missing-path threshold (the production
            # analogue is >6s, and specifically beyond the old ~1s cutoff).
            assert _wait_until(
                lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 0
                and module.CORRELATION_HEALTH.snapshot()["access_log_present"] == 0
            )
            missing_heartbeat = module.CORRELATION_HEALTH.snapshot()[
                "last_success_unixtime"
            ]
            old_writer.write(_access_line(old_id, 202))
            assert _wait_until(lambda: old_id in _retried_ids(conn))
            still_missing = module.CORRELATION_HEALTH.snapshot()
            assert still_missing["healthy"] == 0
            assert still_missing["access_log_present"] == 0
            assert still_missing["last_success_unixtime"] == missing_heartbeat

            # nginx's USR1 reopen creates a new canonical inode. The collector
            # drains the old fd, then atomically hands off and reads this row.
            access_log.write_bytes(_access_line(new_id, 201))
        assert _wait_until(
            lambda: {old_id, new_id} <= _retried_ids(conn), timeout=4.0
        )
        recovered = module.CORRELATION_HEALTH.snapshot()
        assert recovered["healthy"] == 1
        assert recovered["access_log_present"] == 1
        assert recovered["errors_total"] == 1
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_access_log_tailer_drains_old_inode_after_replacement_appears(
    repo_root, tmp_path, monkeypatch,
):
    """Old-worker activity resets the quiet handoff window after USR1 reopen."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_replacement_drain",
        repo_root / "proxy" / "collector" / "app.py",
    )
    access_log = tmp_path / "access.log"
    rotated = tmp_path / "access.log.1"
    access_log.write_bytes(b"")
    conn = _StatusConn()
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "ROTATION_DRAIN_SECONDS", 0.08)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.01)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    try:
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
        )
        old_id, new_id = "7" * 32, "8" * 32
        with access_log.open("ab", buffering=0) as old_writer:
            os.rename(access_log, rotated)
            access_log.write_bytes(_access_line(new_id, 201))
            time.sleep(module.ROTATION_DRAIN_SECONDS / 2)
            old_writer.write(_access_line(old_id, 202))
        assert _wait_until(
            lambda: {old_id, new_id} <= _retried_ids(conn), timeout=3.0
        )
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_rotation_partial_growth_resets_quiet_window_and_suffix_is_preserved(
    repo_root, tmp_path, monkeypatch,
):
    """Each new partial byte postpones handoff; a completed old line survives."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_partial_rotation_growth",
        repo_root / "proxy" / "collector" / "app.py",
    )
    access_log = tmp_path / "access.log"
    rotated = tmp_path / "access.log.1"
    access_log.write_bytes(b"")
    conn = _StatusConn()
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "ROTATION_DRAIN_SECONDS", 0.2)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.005)
    monkeypatch.setattr(module, "status_conn", lambda: conn)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    old_id, new_id = "c" * 32, "d" * 32
    old_line = _access_line(old_id, 207)
    try:
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
        )
        with access_log.open("ab", buffering=0) as old_writer:
            os.rename(access_log, rotated)
            access_log.write_bytes(_access_line(new_id, 208))
            old_writer.write(old_line[:12])
            time.sleep(0.12)
            old_writer.write(old_line[12:-1])
            # Total quiet since the first prefix will exceed the drain window,
            # but the newly observed growth must start a fresh window.
            time.sleep(0.12)
            assert new_id not in _updated_ids(conn)
            old_writer.write(old_line[-1:])
            assert _wait_until(lambda: old_id in _updated_ids(conn), timeout=0.15)
            assert new_id not in _updated_ids(conn)
        assert _wait_until(lambda: new_id in _updated_ids(conn), timeout=2.0)
        appearances = [
            request_id
            for batch in _returning_batches(conn)
            for request_id in batch
        ]
        assert appearances.count(old_id) == appearances.count(new_id) == 1
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_permanently_missing_rotated_path_stays_unhealthy_until_recovery(
    repo_root, tmp_path, monkeypatch,
):
    """Old-fd EOF cannot mask a missing canonical path or spin error metrics."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_permanent_rotation_gap",
        repo_root / "proxy" / "collector" / "app.py",
    )
    access_log = tmp_path / "access.log"
    rotated = tmp_path / "access.log.1"
    access_log.write_bytes(b"")
    monkeypatch.setattr(module, "ACCESS_LOG", access_log)
    monkeypatch.setattr(module, "MISSING_PATH_GRACE_SECONDS", 0.04)
    monkeypatch.setattr(module, "ROTATION_DRAIN_SECONDS", 0.02)
    monkeypatch.setattr(module, "LIVE_FLUSH_SECONDS", 0.01)
    stop = threading.Event()
    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    try:
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
        )
        os.rename(access_log, rotated)
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 0
            and module.CORRELATION_HEALTH.snapshot()["access_log_present"] == 0
        )
        missing = module.CORRELATION_HEALTH.snapshot()
        time.sleep(module.MISSING_PATH_GRACE_SECONDS * 2)
        still_missing = module.CORRELATION_HEALTH.snapshot()
        assert still_missing["healthy"] == 0
        assert still_missing["access_log_present"] == 0
        assert still_missing["last_success_unixtime"] == missing[
            "last_success_unixtime"
        ]
        assert still_missing["errors_total"] == missing["errors_total"] == 1

        access_log.write_bytes(b"")
        assert _wait_until(
            lambda: module.CORRELATION_HEALTH.snapshot()["healthy"] == 1
            and module.CORRELATION_HEALTH.snapshot()["access_log_present"] == 1
        )
        assert module.CORRELATION_HEALTH.snapshot()[
            "last_success_unixtime"
        ] > missing["last_success_unixtime"]
    finally:
        stop.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


def test_access_log_tailer_flushes_during_sustained_stream(repo_root, monkeypatch):
    """A stream that never reaches EOF still flushes before the pending cap."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_sustained_tail", repo_root / "proxy" / "collector" / "app.py"
    )
    stop = threading.Event()

    class EndlessHandle:
        def __init__(self):
            self.position = 0
            self.index = 0

        def fileno(self):
            return 123

        def tell(self):
            return self.position

        def seek(self, position):
            self.position = position

        def readline(self, _limit):
            if self.index < 200:
                line = _access_line(f"{self.index:032x}")
            else:
                line = b"{}\n"  # keep the stream non-empty forever
            self.index += 1
            self.position += len(line)
            return line

        def close(self):
            pass

    class EndlessPath:
        def __init__(self):
            self.handle = EndlessHandle()

        def open(self, _mode):
            return self.handle

        def stat(self):
            return type("Stat", (), {"st_dev": 1, "st_ino": 2, "st_size": 10**9})()

    path = EndlessPath()
    conn = _StatusConn(on_returning=lambda _ids: stop.set())
    monkeypatch.setattr(module, "ACCESS_LOG", path)
    monkeypatch.setattr(
        module.os, "fstat",
        lambda _fd: type("Stat", (), {"st_dev": 1, "st_ino": 2, "st_size": 0})(),
    )
    monkeypatch.setattr(module, "status_conn", lambda: conn)

    thread = threading.Thread(target=module.follow_access_log, args=(stop,), daemon=True)
    thread.start()
    thread.join(timeout=2)
    if thread.is_alive():
        stop.set()
        thread.join(timeout=2)

    returning = [call for call in conn.calls if "RETURNING a.request_id" in call[0]]
    assert not thread.is_alive()
    assert returning and len(returning[0][1][0]) == module.LIVE_BATCH_SIZE


def test_request_collector_never_propagates_db_errors(repo_root, monkeypatch):
    """A DB failure is swallowed (fire-and-forget) and still returns 204."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")

    module = load_module_from_path("proxy_collector_app_err", repo_root / "proxy" / "collector" / "app.py")

    def boom():
        raise RuntimeError("logdb down")

    monkeypatch.setattr(module, "get_conn", boom)
    monkeypatch.setattr(module, "reset_conn", lambda: None)
    response = asyncio.run(module.collect("/", FakeRequest(headers={"x-site": "s"})))
    assert response.status_code == 204  # never blocks/fails the real client
    health = module.CORRELATION_HEALTH.snapshot()
    assert health["mirror_rows_inserted_total"] == 0
    assert health["mirror_insert_errors_total"] == 1


def test_request_collector_middleware_catches_docs_and_arbitrary_methods(
    repo_root, monkeypatch,
):
    """Framework routes and uncommon scanner verbs must each create one row."""
    httpx = pytest.importorskip("httpx")
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_all_methods", repo_root / "proxy" / "collector" / "app.py"
    )
    calls = []
    monkeypatch.setattr(module, "get_conn", lambda: DummyConn(calls))

    async def exercise():
        transport = httpx.ASGITransport(app=module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://collector") as client:
            return [
                await client.get("/docs"),
                await client.request("TRACE", "/"),
                await client.request("PROPFIND", "/dav"),
            ]

    responses = asyncio.run(exercise())
    assert [response.status_code for response in responses] == [204, 204, 204]
    inserts = [call for call in calls if "INSERT INTO all_visits" in call[0]]
    assert len(inserts) == 3
    assert [(call[1][4], call[1][5]) for call in inserts] == [
        ("GET", "/docs"), ("TRACE", "/"), ("PROPFIND", "/dav"),
    ]
    assert module.app.docs_url is None and module.app.openapi_url is None


def test_request_collector_preserves_encoded_wire_target(repo_root, monkeypatch):
    httpx = pytest.importorskip("httpx")
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")
    module = load_module_from_path(
        "proxy_collector_raw_target", repo_root / "proxy" / "collector" / "app.py"
    )
    calls = []
    monkeypatch.setattr(module, "get_conn", lambda: DummyConn(calls))

    async def exercise():
        transport = httpx.ASGITransport(app=module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://collector") as client:
            return await client.get("/%252e%252e/%2565tc/passwd?x=%252f")

    assert asyncio.run(exercise()).status_code == 204
    insert = [call for call in calls if "INSERT INTO all_visits" in call[0]][0]
    assert insert[1][5] == "/%252e%252e/%2565tc/passwd?x=%252f"


def test_fingerprint_collector_normalizes_and_rejects_bad_payloads(repo_root, monkeypatch):
    """fp-collector stores normalized fields for a valid beacon and ignores junk/oversize."""
    pytest.importorskip("fastapi")
    pytest.importorskip("psycopg2")

    module = load_module_from_path("proxy_fp_collector_app", repo_root / "proxy" / "fp-collector" / "app.py")
    calls = []
    monkeypatch.setattr(module, "get_conn", lambda: DummyConn(calls))
    monkeypatch.setattr(module, "MAX_BODY", 2000)

    payload = {
        "phase": "load", "fp_id": "fp-123", "canvas_hash": "canvas", "canvas_winding": True,
        "webgl_hash": "webgl", "webgl_vendor": "Google", "webgl_renderer": "Google SwiftShader",
        "webgl_shader_ms": "12.5", "audio_hash": "audio", "audio_sample": "0.2",
        "font_hash": "font", "fonts": ["Arial"], "screen": {"w": 1440},
        "navigator": {"platform": "Win32"}, "automation": {"score": 2, "webdriver": True},
        "behavior": {"synthetic": True}, "webgpu": {"vendor": "none"},
    }
    ok = asyncio.run(module.collect("__fpbeacon", FakeRequest(
        method="POST", path="/__fpbeacon",
        headers={"x-site": "site-001", "x-real-ip": "203.0.113.10", "x-client-port": "55002",
                 "user-agent": "Chrome", "content-type": "application/json"},
        body=json.dumps(payload).encode("utf-8"),
    )))
    oversize = asyncio.run(module.collect("__fpbeacon", FakeRequest(method="POST", body=b"x" * 2001)))
    nonjson = asyncio.run(module.collect("__fpbeacon", FakeRequest(method="POST", body=b"not json")))

    assert ok.status_code == oversize.status_code == nonjson.status_code == 204
    inserts = [c for c in calls if "INSERT INTO browser_fingerprints" in c[0]]
    assert len(inserts) == 1, "only the valid beacon should be inserted"
    params = inserts[0][1]
    assert params[:7] == ("site-001", "203.0.113.10", 55002, "Chrome", "load", "fp-123", "canvas")
    assert params[11] == 12.5   # webgl_shader_ms coerced to float
    assert params[13] == 0.2    # audio_sample coerced to float


def test_tls_shipper_maps_handshakes_and_infers_tcp_os(repo_root):
    """The shipper maps Zeek rows and infers TCP/IP OS families + a JA4T signature."""
    pytest.importorskip("psycopg2")
    module = load_module_from_path("proxy_tls_shipper_app", repo_root / "proxy" / "tls-shipper" / "app.py")

    # Port coercion ("443/tcp" -> 443).
    assert module._port("443/tcp") == 443 and module._port(8443) == 8443 and module._port("bad") is None

    # p0f-style OS inference from the SYN (TTL bucket + window/scale).
    assert module.infer_os(127, 64240, 8, 1460) == "Windows"   # TTL ~128
    assert module.infer_os(64, 65535, 6, 1460) == "Apple"      # 64 + win 65535 + scale 6
    assert module.infer_os(63, 29200, 7, 1460) == "Linux"      # 64 + scale 7

    # Option-order OS disambiguation (the real detection gain): a TTL-64 window the
    # legacy heuristic does NOT list still classifies from the SYN option order,
    # while an unrecognized order stays conservatively "unknown". TTL wins over order.
    assert module.infer_os(64, 62727, 7, 1460, [2, 4, 8, 1, 3]) == "Linux"
    assert module.infer_os(64, 65535, 6, 1432, [2, 1, 3, 1, 1, 8, 4]) == "Apple"
    assert module.infer_os(64, 65535, 7, 1460, [2, 1, 3, 4, 8]) == "unknown"
    assert module.infer_os(64, 62727, 7, 1460, None) == "unknown"  # pre-upgrade line
    assert module.infer_os(128, 8192, 8, 1460, [2, 4, 8, 1, 3]) == "Windows"

    # Legacy JA4T (no option kinds) vs canonical FoxIO JA4T (with them).
    assert module.build_ja4t(64240, 1460, 8, True, True) == "64240_1460_8_11"
    assert module.build_ja4t(64240, 1460, 10, True, True, [2, 4, 8, 1, 3]) == "64240_2-4-8-1-3_1460_10"
    assert module.build_ja4t(65535, None, None, False, False, []) == "65535__0_0"  # bare scanner SYN
    assert module.build_ja4t(64240, 1460, 8, True, True, ["x"]) == "64240_1460_8_11"  # junk -> fallback
    # Zeek's -1 "no option" sentinel (MSS-only / no window-scale SYN) must render as
    # 0 to match FoxIO's canonical output, not "-1".
    assert module.build_ja4t(65535, 1460, -1, False, False, [2]) == "65535_2_1460_0"
    assert module.build_ja4t(65535, 0, -1, False, False, []) == "65535__0_0"

    tls = module.tls_row_from({
        "ts": 1.5, "uid": "C1", "id.orig_h": "203.0.113.10", "id.orig_p": 55001,
        "id.resp_h": "198.51.100.1", "id.resp_p": 443, "version": "TLSv13",
        "cipher": "TLS_AES_128_GCM_SHA256", "server_name": "site.example",
        "ja3": "ja3", "ja3s": "ja3s", "ja4": "ja4", "ja4s": "ja4s",
    })
    assert tls[2:5] == ("203.0.113.10", 55001, "198.51.100.1")
    assert tls[-2:] == ("ja4", "ja4s")
    assert module.tls_row_from({"id.orig_h": None}) is None  # no source -> skipped

    # A pre-upgrade Zeek line (no opt_kinds key): legacy JA4T + NULL opt_kinds column,
    # OS from the window/scale fallback. The row now carries one extra trailing cell.
    tcp = module.tcp_row_from({
        "ts": 2.0, "uid": "C2", "orig_h": "203.0.113.10", "orig_p": "55001/tcp",
        "resp_h": "198.51.100.1", "resp_p": "443/tcp", "ttl": 64, "win_size": 65535,
        "win_scale": 6, "mss": 1460, "sack_ok": True, "df": True,
    })
    assert tcp[2:6] == ("203.0.113.10", 55001, "198.51.100.1", 443)
    assert tcp[-3:] == ("Apple", "65535_1460_6_11", None)

    # An upgraded line WITH the captured option kinds: canonical JA4T, the stored
    # dash-joined kinds, and the OS inferred from the option order.
    tcp2 = module.tcp_row_from({
        "ts": 3.0, "uid": "C3", "orig_h": "203.0.113.11", "orig_p": "55002/tcp",
        "resp_h": "198.51.100.1", "resp_p": "443/tcp", "ttl": 64, "win_size": 62727,
        "win_scale": 7, "mss": 1460, "sack_ok": True, "df": True,
        "opt_kinds": [2, 4, 8, 1, 3],
    })
    assert tcp2[-3:] == ("Linux", "62727_2-4-8-1-3_1460_7", "2-4-8-1-3")
