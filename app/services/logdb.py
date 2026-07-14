"""One fast, shared path to the proxy stack's central Postgres (``logdb``).

``request_log`` and ``fingerprint_service`` route every query through here. Two
backends, selected by whether ``LOGDB_HOST`` is set (this mirrors the
``crawler_graph.ingest.db`` module exactly, so the app and the analysis package
resolve logdb the same way and read the same env contract):

  * **``LOGDB_HOST`` set** — the container default (see ``docker-compose.app.yml``,
    where it is ``logdb``) and the AWS deployment (where it is the **RDS
    endpoint**): a direct ``psycopg2`` connection to ``LOGDB_HOST:LOGDB_PORT``.
    This is the path that works unchanged against managed Postgres — only the env
    value differs, no code change. The connection is cached on the module (one
    uvicorn process serves every request) and reconnects if it drops.
  * **``LOGDB_HOST`` unset** — e.g. ``make app-dev`` on the host, where the
    ``logdb`` service name isn't resolvable: fall back to the original
    ``docker exec`` / ``docker compose exec`` into the logdb container. The
    container id is resolved once (``docker compose ps -q logdb``) and cached; if
    it's gone (proxy stack recreated) we heal via the slower ``compose exec`` form.

Both return the single JSON value produced by the caller's
``SELECT json_build_object(...)`` query. The credentials/db name come from the
same ``LOGDB_*`` env vars in both backends (no hardcoding), defaulting to the
values in ``docker-compose.proxy.yml``.
"""

import json
import os
import re
import subprocess

from .. import config


class LogDBError(RuntimeError):
    """Raised when the central log database cannot be queried. The message is the
    raw failure detail; callers rewrite the well-known ones ("is not running",
    'relation "..." does not exist') into user guidance / graceful fallbacks."""


# --- connection config (env, matching docker-compose.proxy.yml + crawler_graph) --
LOGDB_HOST = os.environ.get("LOGDB_HOST")            # None -> docker-exec path
LOGDB_PORT = int(os.environ.get("LOGDB_PORT", "5432"))
LOGDB_USER = os.environ.get("LOGDB_USER", "logger")
LOGDB_PASS = os.environ.get("LOGDB_PASS", "logger")
LOGDB_NAME = os.environ.get("LOGDB_NAME", "site_logs")


def _parse_json_value(value):
    """Return the single JSON value as a Python object. psycopg2 auto-adapts the
    ``json`` type to a dict/list already; a plain psql ``-t -A`` shell returns the
    raw text, which we json.loads. ``None``/empty means the query returned nothing."""
    if value is None:
        raise LogDBError("The database returned no data.")
    if isinstance(value, (dict, list)):
        return value
    text = value.strip() if isinstance(value, str) else str(value)
    if not text:
        raise LogDBError("The database returned no data.")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise LogDBError("The database returned an invalid response.") from exc


# --- direct psycopg2 backend (LOGDB_HOST set; also the AWS/RDS path) ----------
_conn = None


def _direct_conn():
    """Return a live autocommit connection, (re)connecting if needed. autocommit
    keeps the connection usable after a failed statement (e.g. an undefined
    fingerprint table), which the callers rely on to retry a degraded query."""
    global _conn
    import psycopg2  # lazy: the docker-exec fallback path needs no psycopg2
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(
            host=LOGDB_HOST, port=LOGDB_PORT, user=LOGDB_USER,
            password=LOGDB_PASS, dbname=LOGDB_NAME,
            connect_timeout=10, options="-c statement_timeout=30000",
        )
        _conn.autocommit = True
    return _conn


def _run_direct(sql):
    global _conn
    try:
        import psycopg2
    except ModuleNotFoundError as exc:
        raise LogDBError("psycopg2 is not installed for the direct DB path.") from exc
    try:
        conn = _direct_conn()
        with conn.cursor() as cur:
            cur.execute(sql)
            row = cur.fetchone()
    except psycopg2.OperationalError as exc:
        _conn = None  # drop the (likely dead) cached connection; reconnect next call
        # Keep the "is not running" marker so the callers' friendly local rewrite
        # ("Start it with `make proxy`") still fires when the proxy stack is down.
        raise LogDBError(
            f"The log database is not running or not reachable at "
            f"{LOGDB_HOST}:{LOGDB_PORT} ({str(exc).strip()})."
        ) from exc
    except psycopg2.Error as exc:
        # A SQL-level failure (e.g. 'relation "tcp_fingerprints" does not exist').
        # autocommit=True leaves the connection usable, and this exact message is
        # what request_log/fingerprint_service key their graceful fallbacks on.
        raise LogDBError(str(exc).strip() or "The database query failed.") from exc
    return _parse_json_value(row[0] if row else None)


# --- docker-exec backend (LOGDB_HOST unset; the portable host path) -----------
def _psql_args():
    return [
        "psql", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1",
        "-U", LOGDB_USER, "-d", LOGDB_NAME, "-c",
    ]


# Cached logdb container id (None = unresolved). Module-level on purpose: one
# uvicorn process serves every request, and the id only changes when the proxy
# stack is recreated — which the fallback below detects and heals.
_container_id = None

_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{12,64}$")
# docker-exec failure details that mean "the cached container is gone" (retry via
# compose), as opposed to "the SQL itself failed" (surface to the caller).
_GONE_MARKERS = ("no such container", "is not running", "is paused", "is restarting")


def _run(command, timeout):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise LogDBError("Docker CLI is not available to the app.") from exc
    except subprocess.TimeoutExpired as exc:
        raise LogDBError("The query timed out.") from exc


def _resolve_container_id():
    """Best-effort ``docker compose ps -q logdb`` (None on any failure)."""
    global _container_id
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(config.PROXY_COMPOSE), "ps", "-q", "logdb"],
            capture_output=True, text=True, timeout=15,
        )
    except Exception:
        return None
    lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    if result.returncode == 0 and lines and _CONTAINER_ID_RE.match(lines[0]):
        _container_id = lines[0]
        return _container_id
    return None


def _run_docker_exec(sql, timeout):
    global _container_id
    cid = _container_id or _resolve_container_id()
    if cid:
        result = _run(["docker", "exec", cid] + _psql_args() + [sql], timeout)
        if result.returncode == 0:
            return _parse_json_value(result.stdout)
        detail = (result.stderr or result.stdout).strip()
        if not any(marker in detail.lower() for marker in _GONE_MARKERS):
            raise LogDBError(detail or "The database query failed.")
        _container_id = None  # container recreated/stopped -> retry the slow way
    result = _run(
        ["docker", "compose", "-f", str(config.PROXY_COMPOSE), "exec", "-T", "logdb"]
        + _psql_args() + [sql],
        timeout,
    )
    if result.returncode != 0:
        raise LogDBError((result.stderr or result.stdout).strip() or "The database query failed.")
    return _parse_json_value(result.stdout)


def run_psql_json(sql, timeout=20):
    """Run one query against logdb and return its single JSON value as a Python
    object. Uses the direct psycopg2 connection when ``LOGDB_HOST`` is set (the
    container default and the AWS/RDS path), else the docker-exec fallback."""
    if LOGDB_HOST:
        return _run_direct(sql)
    return _run_docker_exec(sql, timeout)
