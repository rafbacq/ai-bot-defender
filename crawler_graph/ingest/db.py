"""Read visits and TLS handshakes from the proxy stack's ``logdb``.

Mirrors ``app/services/request_log.py``: by default it shells
``docker compose exec logdb psql`` and parses a single ``json_agg`` result. When
``LOGDB_HOST`` is set it uses a direct psycopg2 connection instead (the path used
when this runs inside the app container, which is attached to ``proxy_net``).

Both reads are resilient to the schema being mid-migration: ``all_visits`` may
not yet have the ``client_port`` column (added by the collector migration), and
``tls_handshakes`` may not exist yet (created by the Zeek shipper) — in those
cases we degrade gracefully instead of erroring.
"""

import json
import subprocess

from .. import config


class IntelDBError(RuntimeError):
    """Raised when logdb cannot be queried at all."""


def _docker_exec_json(sql):
    command = [
        "docker", "compose", "-f", str(config.PROXY_COMPOSE), "exec", "-T",
        config.LOGDB_SERVICE,
        "psql", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1",
        "-U", config.LOGDB_USER, "-d", config.LOGDB_NAME, "-c", sql,
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    except FileNotFoundError as exc:
        raise IntelDBError("Docker CLI is not available.") from exc
    except subprocess.TimeoutExpired as exc:
        raise IntelDBError("The logdb query timed out.") from exc
    if result.returncode != 0:
        raise IntelDBError((result.stderr or result.stdout).strip() or "logdb query failed.")
    out = result.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise IntelDBError("logdb returned an invalid response.") from exc


def _direct_json(sql):
    try:
        import psycopg2
    except ImportError as exc:  # pragma: no cover
        raise IntelDBError("psycopg2 is not installed for the direct DB path.") from exc
    try:
        conn = psycopg2.connect(
            host=config.LOGDB_HOST, port=config.LOGDB_PORT, user=config.LOGDB_USER,
            password=config.LOGDB_PASS, dbname=config.LOGDB_NAME, connect_timeout=10,
        )
    except Exception as exc:  # pragma: no cover
        raise IntelDBError(f"Could not connect to logdb at {config.LOGDB_HOST}: {exc}") from exc
    try:
        with conn, conn.cursor() as cur:
            cur.execute(sql)
            row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def _query(sql):
    """Run ``sql`` (must select a single json value) and return the parsed JSON."""
    if config.LOGDB_HOST:
        return _direct_json(sql)
    return _docker_exec_json(sql)


def _visits_sql(columns, since_hours, limit):
    where = ""
    if since_hours and since_hours > 0:
        where = f"WHERE ts >= NOW() - INTERVAL '{int(since_hours)} hours'"
    limit_clause = f"LIMIT {int(limit)}" if limit else ""
    return (
        "SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM ("
        f"SELECT {columns} FROM all_visits {where} "
        f"ORDER BY ts DESC {limit_clause}) t;"
    )


def fetch_visits(limit=None, since_hours=None):
    """Return recent ``all_visits`` rows (newest first) as a list of dicts.

    Tries to include ``client_port`` (needed to join TLS handshakes by 4-tuple);
    if that column does not exist yet, falls back to a query without it so the
    cheap-feature graph still works on an un-migrated database.
    """
    limit = config.MAX_VISITS if limit is None else limit
    since_hours = config.SINCE_HOURS if since_hours is None else since_hours
    # ``headers`` (jsonb) is needed for the JA4H HTTP-header fingerprint; it has
    # always existed on all_visits, so only ``client_port`` needs the fallback.
    with_port = "id, ts, site, client_ip, client_port, user_agent, method, uri, headers"
    without_port = "id, ts, site, client_ip, user_agent, method, uri, headers"
    try:
        rows = _query(_visits_sql(with_port, since_hours, limit))
    except IntelDBError as exc:
        if "client_port" in str(exc) and "does not exist" in str(exc):
            rows = _query(_visits_sql(without_port, since_hours, limit))
        else:
            raise
    rows = rows or []
    for row in rows:
        row.setdefault("client_port", None)
    return rows


def fetch_handshakes(since_hours=None):
    """Return ``tls_handshakes`` rows, or ``[]`` if the table doesn't exist yet."""
    since_hours = config.SINCE_HOURS if since_hours is None else since_hours
    where = ""
    if since_hours and since_hours > 0:
        where = f"WHERE ts >= NOW() - INTERVAL '{int(since_hours)} hours'"
    sql = (
        "SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM ("
        "SELECT ts, src_ip, src_port, ja3, ja3s, ja4, ja4s, sni, version, "
        f"server_name FROM tls_handshakes {where} ORDER BY ts DESC) t;"
    )
    try:
        return _query(sql) or []
    except IntelDBError as exc:
        if "tls_handshakes" in str(exc) and "does not exist" in str(exc):
            return []
        # Some columns (ja4s/server_name) may be absent depending on Zeek
        # packages; retry with the minimal, always-present set.
        minimal = (
            "SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM ("
            f"SELECT ts, src_ip, src_port, ja3, ja4, sni FROM tls_handshakes {where} "
            "ORDER BY ts DESC) t;"
        )
        try:
            return _query(minimal) or []
        except IntelDBError:
            return []


def fetch_browser_fingerprints(since_hours=None):
    """Return ``browser_fingerprints`` rows (Layer-1 device fingerprints), or
    ``[]`` if the table doesn't exist yet (the fp-collector creates it).

    Selects only the fields the graph + consistency engine need (hashes, vendor/
    renderer, navigator, automation, behavior) — not the bulky raw/screen/webgpu
    columns — to keep the payload small.
    """
    since_hours = config.SINCE_HOURS if since_hours is None else since_hours
    where = ""
    if since_hours and since_hours > 0:
        where = f"WHERE ts >= NOW() - INTERVAL '{int(since_hours)} hours'"
    sql = (
        "SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM ("
        "SELECT ts, site, client_ip, client_port, user_agent, phase, fp_id, "
        "canvas_hash, webgl_hash, webgl_vendor, webgl_renderer, audio_hash, "
        "font_hash, navigator, automation, behavior "
        f"FROM browser_fingerprints {where} ORDER BY ts DESC) t;"
    )
    try:
        return _query(sql) or []
    except IntelDBError as exc:
        if "browser_fingerprints" in str(exc) and "does not exist" in str(exc):
            return []
        return []


def fetch_tcp_fingerprints(since_hours=None):
    """Return ``tcp_fingerprints`` rows (Layer-2 TCP/IP OS inference), or ``[]``
    if the table doesn't exist yet (the tls-shipper creates it)."""
    since_hours = config.SINCE_HOURS if since_hours is None else since_hours
    where = ""
    if since_hours and since_hours > 0:
        where = f"WHERE ts >= NOW() - INTERVAL '{int(since_hours)} hours'"
    sql = (
        "SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM ("
        "SELECT ts, src_ip, src_port, ttl, win_size, win_scale, mss, os_guess, ja4t "
        f"FROM tcp_fingerprints {where} ORDER BY ts DESC) t;"
    )
    try:
        return _query(sql) or []
    except IntelDBError as exc:
        if "tcp_fingerprints" in str(exc) and "does not exist" in str(exc):
            return []
        return []
