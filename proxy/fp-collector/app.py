"""Browser-fingerprint collector for AI Bot Defender (Layer 1).

The honeypot pages embed website/static/js/fp.js, which collects the JS-visible
fingerprint surfaces (canvas, WebGL/WebGPU, audio, fonts, screen/window,
navigator/UA-CH, automation tells) plus behavioral biometrics and POSTs one JSON
payload to /__fpbeacon. nginx routes that exact path here (per-site server block)
with the same X-Site / X-Real-IP / X-Client-Port headers the request mirror uses,
so each fingerprint is attributed to the canonical site and can be joined to the
HTTP request (all_visits) and the TLS/TCP handshake (tls_handshakes /
tcp_fingerprints) by the (client_ip, client_port) 4-tuple.

We write one row per beacon into logdb.browser_fingerprints, then return 204 as
fast as possible. This mirrors proxy/collector/app.py's rules exactly:
  - Never block or fail the real client: the beacon is async (fetch keepalive /
    navigator.sendBeacon) and any DB error here is swallowed + the connection reset.
  - Cap the body size so a malicious client can't push huge payloads into logdb.
"""

import json
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
# Reject oversized payloads (a full fingerprint is a few KB; 64 KB is generous).
MAX_BODY = int(os.environ.get("FP_MAX_BODY", str(64 * 1024)))

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS browser_fingerprints (
    id              serial primary key,
    ts              timestamptz default now(),
    site            text,
    client_ip       text,
    client_port     int,
    user_agent      text,
    phase           text,
    fp_id           text,
    canvas_hash     text,
    canvas_winding  boolean,
    webgl_hash      text,
    webgl_vendor    text,
    webgl_renderer  text,
    webgl_shader_ms double precision,
    audio_hash      text,
    audio_sample    double precision,
    font_hash       text,
    fonts           jsonb,
    screen          jsonb,
    navigator       jsonb,
    automation      jsonb,
    behavior        jsonb,
    webgpu          jsonb,
    raw             jsonb
);
CREATE INDEX IF NOT EXISTS browser_fp_tuple ON browser_fingerprints (client_ip, client_port, ts);
CREATE INDEX IF NOT EXISTS browser_fp_id ON browser_fingerprints (fp_id);
-- Supports the request-log enrichment join, which attaches each request's beacon
-- by (client_ip, user_agent) within a time window (see app/services/request_log.py).
CREATE INDEX IF NOT EXISTS browser_fp_ip_ua ON browser_fingerprints (client_ip, user_agent, ts);
"""

INSERT = """
INSERT INTO browser_fingerprints
    (site, client_ip, client_port, user_agent, phase, fp_id, canvas_hash,
     canvas_winding, webgl_hash, webgl_vendor, webgl_renderer, webgl_shader_ms,
     audio_hash, audio_sample, font_hash, fonts, screen, navigator, automation,
     behavior, webgpu, raw)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s)
"""

_conn = None


def get_conn():
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, dbname=DB_NAME)
        _conn.autocommit = True
    return _conn


def reset_conn():
    global _conn
    try:
        if _conn is not None:
            _conn.close()
    finally:
        _conn = None


def init_db():
    with get_conn().cursor() as cur:
        cur.execute(CREATE_TABLE)


@asynccontextmanager
async def lifespan(app: FastAPI):
    for attempt in range(30):
        try:
            init_db()
            break
        except Exception as exc:  # pragma: no cover - startup resilience
            print(f"fp-collector: waiting for logdb ({attempt}): {exc}", flush=True)
            reset_conn()
            time.sleep(1)
    yield


app = FastAPI(lifespan=lifespan)


def _num(value):
    """Coerce to float or None (fingerprint hashes/timings are best-effort)."""
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _int(value):
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


@app.api_route("/{_path:path}", methods=["POST", "OPTIONS"])
async def collect(_path: str, request: Request) -> Response:
    try:
        body = await request.body()
        if not body or len(body) > MAX_BODY:
            return Response(status_code=204)
        fp = json.loads(body)
        if not isinstance(fp, dict):
            return Response(status_code=204)

        site = request.headers.get("x-site")
        client_ip = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for")
        client_port = _int(request.headers.get("x-client-port"))
        user_agent = request.headers.get("user-agent")

        auto = fp.get("automation") or {}
        row = (
            site,
            client_ip,
            client_port,
            user_agent,
            fp.get("phase"),
            fp.get("fp_id"),
            fp.get("canvas_hash"),
            bool(fp["canvas_winding"]) if isinstance(fp.get("canvas_winding"), bool) else None,
            fp.get("webgl_hash"),
            fp.get("webgl_vendor"),
            fp.get("webgl_renderer"),
            _num(fp.get("webgl_shader_ms")),
            fp.get("audio_hash"),
            _num(fp.get("audio_sample")),
            fp.get("font_hash"),
            Json(fp.get("fonts")) if fp.get("fonts") is not None else None,
            Json(fp.get("screen")) if fp.get("screen") is not None else None,
            Json(fp.get("navigator")) if fp.get("navigator") is not None else None,
            Json(auto) if auto else None,
            Json(fp.get("behavior")) if fp.get("behavior") is not None else None,
            Json(fp.get("webgpu")) if fp.get("webgpu") is not None else None,
            Json(fp),
        )
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute(INSERT, row)
    except Exception as exc:
        # Fire-and-forget: log and move on, never propagate to the client.
        print(f"fp-collector: insert failed: {exc}", flush=True)
        reset_conn()

    return Response(status_code=204)
