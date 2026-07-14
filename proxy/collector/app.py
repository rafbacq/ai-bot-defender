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

import os
import time
from contextlib import asynccontextmanager

import psycopg2
from psycopg2.extras import Json
from fastapi import FastAPI, Request, Response

DB_HOST = os.environ.get("DB_HOST", "logdb")
DB_USER = os.environ.get("DB_USER", "logger")
DB_PASS = os.environ.get("DB_PASS", "logger")
DB_NAME = os.environ.get("DB_NAME", "site_logs")

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
    headers     jsonb
)
"""

# Additive migration for databases created before client_port existed. nginx now
# forwards the client's source TCP port (X-Client-Port) so the crawler-graph layer
# can join each request to its passively-captured TLS fingerprint by 4-tuple.
# Safe and idempotent; CREATE TABLE IF NOT EXISTS alone never alters an existing
# table, so this ALTER is required on already-deployed proxy stacks.
MIGRATE = "ALTER TABLE all_visits ADD COLUMN IF NOT EXISTS client_port int"

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
        cur.execute(MIGRATE)


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
    yield


app = FastAPI(lifespan=lifespan)


@app.api_route(
    "/{_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
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
        uri = request.url.path
        if request.url.query:
            uri = f"{uri}?{request.url.query}"
        headers = dict(request.headers)

        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO all_visits "
                "(site, client_ip, client_port, user_agent, method, uri, headers) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (site, client_ip, client_port, user_agent, request.method, uri, Json(headers)),
            )
    except Exception as exc:
        # Fire-and-forget: log and move on, never propagate to the client.
        print(f"collector: insert failed: {exc}", flush=True)
        reset_conn()

    return Response(status_code=204)
