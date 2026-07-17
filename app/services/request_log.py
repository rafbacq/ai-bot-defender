"""Read-only access to the reverse proxy's central request log (``all_visits``).

Ported from the Streamlit ``ui/request_log.py``: queries the proxy stack's
``logdb`` Postgres by shelling ``psql`` in the logdb container (via the shared
fast path in ``logdb.py``) and parsing JSON, with filtering/pagination/search
done in SQL and string values safely quoted.
"""

import csv
import json
import os
from io import StringIO

from . import logdb
from .fingerprint_service import verdict_for
from .sites import active_proxy_sites

# How far in time a request may reach to claim a browser-fingerprint beacon as its
# own. Bounds the join so a request can't inherit an unrelated session's device
# from hours/days away (many visitors collapse onto one IP behind the NAT/Docker
# hop), while still spanning a normal pageview (load beacon ~1.8s in, unload beacon
# whenever the visitor leaves). Env-overridable.
FP_JOIN_WINDOW_MIN = int(os.environ.get("FP_JOIN_WINDOW_MIN", "30"))


class RequestLogError(RuntimeError):
    """Raised when the proxy request log cannot be queried."""


def _sql_literal(value):
    return "'" + value.replace("'", "''") + "'"


def _run_json_query(sql):
    try:
        return logdb.run_psql_json(sql)
    except logdb.LogDBError as exc:
        detail = str(exc)
        if "is not running" in detail or "no container found" in detail:
            detail = "The reverse proxy database is not running. Start it with `make proxy`."
        elif 'relation "all_visits" does not exist' in detail:
            detail = "The request log is not ready yet. Wait for the proxy collector to start."
        raise RequestLogError(detail or "The request-log query failed.") from exc


# The core request columns (all_visits is aliased `a` so the fingerprint-enriched
# query below can disambiguate from the joined browser_fingerprints table `b`).
# client_port is the additive column the collector adds (X-Client-Port) — it keys
# the TCP-SYN join below to the request's own connection.
_BASE_COLS = (
    "a.id, a.ts, a.site, a.client_ip, a.client_port, a.user_agent, "
    "a.method, a.uri, a.headers, "
    "to_jsonb(a) ->> 'request_id' AS request_id, "
    "NULLIF(to_jsonb(a) ->> 'response_status', '')::int AS response_status"
)


def _conditions(site, method, search, *, include_fp):
    """Build the WHERE clause. When ``include_fp`` the free-text search also covers
    the joined fingerprint columns (so you can find a device by fp_id / canvas hash
    / WebGL renderer and see the requests it made)."""
    conditions = []
    if site != "All sites":
        conditions.append(f"a.site = {_sql_literal(site)}")
    if method != "All methods":
        conditions.append(f"a.method = {_sql_literal(method)}")
    if search.strip():
        literal = _sql_literal(search.strip().lower())
        fields = (
            "a.site, a.client_ip, a.user_agent, a.method, a.uri, a.headers::text, "
            "to_jsonb(a) ->> 'response_status', to_jsonb(a) ->> 'request_id'"
        )
        if include_fp:
            fields += ", b.fp_id, b.canvas_hash, b.webgl_renderer"
        conditions.append(f"POSITION({literal} IN LOWER(CONCAT_WS(' ', {fields}))) > 0")
    return " AND ".join(conditions) if conditions else "TRUE"


def _plain_sql(where_clause, page_size, offset):
    """Request rows only (used for CSV export and as the no-fingerprint fallback)."""
    return f"""
    WITH filtered AS (
        SELECT {_BASE_COLS} FROM all_visits a WHERE {where_clause}
    ),
    page_rows AS (
        SELECT * FROM filtered ORDER BY ts DESC, id DESC LIMIT {page_size} OFFSET {offset}
    )
    SELECT json_build_object(
        'total', (SELECT COUNT(*) FROM filtered),
        'last_24h', (SELECT COUNT(*) FROM filtered WHERE ts >= NOW() - INTERVAL '24 hours'),
        'unique_sites', (SELECT COUNT(DISTINCT site) FROM filtered),
        'latest_ts', (SELECT MAX(ts) FROM filtered),
        'rows', (SELECT COALESCE(json_agg(row_to_json(page_rows) ORDER BY ts DESC, id DESC), '[]'::json)
                 FROM page_rows)
    );
    """


def _enriched_sql(where_clause, page_size, offset, *, with_tcp):
    """Each request LEFT-JOINed to the browser fingerprint that actually *belongs
    to it*: same client IP **and the same exact User-Agent**, within a bounded time
    window, preferring the richer ``unload`` beacon — plus that IP's latest TCP/IP
    OS inference.

    The UA equality is load-bearing. ``fp.js`` beacons carry the same ``User-Agent``
    header as the page GET that spawned them, so ``(client_ip, user_agent)`` ties a
    request to its own device. Keying on ``client_ip`` *alone* (the old behaviour)
    glued one visitor's latest fingerprint onto **every** request sharing that IP —
    which behind a NAT or the local Docker hop (where many distinct visitors collapse
    onto one address) meant ``curl``, internal probes, and declared bots that never
    ran JS all inherited the operator browser's verdict, lighting up as spurious
    VM / AUTO / INCONSISTENT.

    Three further refinements over a plain nearest-time match:
      * a ``+/- FP_JOIN_WINDOW_MIN`` bound, so a request can't inherit an unrelated
        session's device from hours/days away behind the shared hop;
      * ``ORDER BY (phase='unload') DESC``, because ``fp.js`` emits a ``load``
        beacon ~1.2s in (with *zero* behavior) and ``unload`` beacons on page-leave
        carrying the accumulated clicks/scroll/keystrokes. Nearest-time alone always
        picked the empty ``load`` beacon — which is why interaction read as 0 clicks;
      * a **pageview match** (the ``pv`` lateral): fp.js stamps every beacon of one
        page load with a shared random ``pv_id`` (read here from the collector's
        ``raw`` payload, so no schema change and old rows simply lack it). fp.js
        re-arms its unload beacon (tab away -> come back -> keep interacting sends
        an UPDATED cumulative beacon), so one pageview can own several unload
        beacons; the request first identifies *its own* pageview — the nearest
        beacon at/after the request, since a pageview's beacons always follow its
        page GET (nearest-in-absolute-time could grab the *previous* page's unload
        beacon, which fires the instant that page was left) — then takes that
        pageview's LATEST unload beacon, i.e. the fullest interaction record.
    Falls back to the old nearest-unload-in-window behavior when no beacon carries
    a pv_id, and to the ``load`` beacon when there's no ``unload`` yet. The
    TCP/IP-OS join has no UA to key on (a SYN carries none), so it prefers the SYN
    of the request's *own connection* — the (client_ip, client_port) 4-tuple —
    then falls back to the nearest **earlier** SYN from the same IP. The old
    "latest SYN from this IP ever" join could glue a *different device's* kernel
    OS onto a request behind a shared NAT IP, and on a public IP (where the
    consistency engine trusts the TCP layer) that manufactured a false OS-spoof
    contradiction. The 5s forward slack absorbs Zeek-vs-collector clock skew.
    All are LATERAL and degrade gracefully when the fingerprint tables don't
    exist yet."""
    tcp_select = (
        "t.tcp_os, t.ja4t, t.tcp_match_exact"
        if with_tcp else
        "NULL::text AS tcp_os, NULL::text AS ja4t, FALSE AS tcp_match_exact"
    )
    tcp_join = (
        "LEFT JOIN LATERAL (SELECT os_guess AS tcp_os, ja4t, "
        "COALESCE(tf.src_port = a.client_port, FALSE) AS tcp_match_exact "
        "FROM tcp_fingerprints tf "
        "WHERE tf.src_ip = a.client_ip "
        "AND tf.ts BETWEEN a.ts - INTERVAL '5 minutes' AND a.ts + INTERVAL '5 seconds' "
        "ORDER BY (tf.src_port = a.client_port) DESC NULLS LAST, "
        "abs(extract(epoch FROM (tf.ts - a.ts))) ASC LIMIT 1) t ON TRUE"
        if with_tcp else ""
    )
    window = int(FP_JOIN_WINDOW_MIN)
    return f"""
    WITH filtered AS (
        SELECT {_BASE_COLS},
               b.fp_id, b.canvas_hash, b.webgl_hash, b.webgl_vendor, b.webgl_renderer,
               b.audio_hash, b.font_hash, b.navigator, b.automation, b.behavior,
               b.phase, b.user_agent AS fp_user_agent, {tcp_select}
        FROM all_visits a
        LEFT JOIN LATERAL (
            SELECT bf0.raw ->> 'pv_id' AS pv_id
            FROM browser_fingerprints bf0
            WHERE bf0.client_ip = a.client_ip AND bf0.user_agent = a.user_agent
              AND bf0.raw ->> 'pv_id' IS NOT NULL
              AND bf0.ts BETWEEN a.ts - INTERVAL '{window} minutes'
                             AND a.ts + INTERVAL '{window} minutes'
            ORDER BY (bf0.ts >= a.ts) DESC,
                     abs(extract(epoch FROM (bf0.ts - a.ts))) ASC
            LIMIT 1
        ) pv ON TRUE
        LEFT JOIN LATERAL (
            SELECT user_agent, fp_id, canvas_hash, webgl_hash, webgl_vendor, webgl_renderer,
                   audio_hash, font_hash, navigator, automation, behavior, phase
            FROM browser_fingerprints bf
            WHERE bf.client_ip = a.client_ip AND bf.user_agent = a.user_agent
              AND bf.ts BETWEEN a.ts - INTERVAL '{window} minutes'
                            AND a.ts + INTERVAL '{window} minutes'
            ORDER BY COALESCE(bf.raw ->> 'pv_id' = pv.pv_id, FALSE) DESC,
                     (bf.phase = 'unload') DESC,
                     CASE WHEN bf.raw ->> 'pv_id' = pv.pv_id THEN bf.ts END DESC,
                     abs(extract(epoch FROM (bf.ts - a.ts))) ASC, bf.ts DESC
            LIMIT 1
        ) b ON TRUE
        {tcp_join}
        WHERE {where_clause}
    ),
    page_rows AS (
        SELECT * FROM filtered ORDER BY ts DESC, id DESC LIMIT {page_size} OFFSET {offset}
    )
    SELECT json_build_object(
        'total', (SELECT COUNT(*) FROM filtered),
        'last_24h', (SELECT COUNT(*) FROM filtered WHERE ts >= NOW() - INTERVAL '24 hours'),
        'unique_sites', (SELECT COUNT(DISTINCT site) FROM filtered),
        'latest_ts', (SELECT MAX(ts) FROM filtered),
        'rows', (SELECT COALESCE(json_agg(row_to_json(page_rows) ORDER BY ts DESC, id DESC), '[]'::json)
                 FROM page_rows)
    );
    """


def fetch_requests(*, site="All sites", method="All methods", search="", page=1,
                   page_size=100, enrich=True):
    """Return one filtered page of requests plus summary counts.

    When ``enrich`` (the default, for the page view) each request row is folded
    together with the latest browser fingerprint + TCP/IP inference for its client
    IP and a cross-layer consistency ``verdict`` (reusing the fingerprint service's
    engine). ``enrich=False`` (the CSV export path) returns just the request columns.
    Degrades gracefully if the fingerprint tables don't exist yet.
    """
    safe_page = max(1, int(page))
    safe_page_size = min(500, max(25, int(page_size)))
    offset = (safe_page - 1) * safe_page_size

    if not enrich:
        where = _conditions(site, method, search, include_fp=False)
        return _run_json_query(_plain_sql(where, safe_page_size, offset))

    where_fp = _conditions(site, method, search, include_fp=True)
    try:
        data = _run_json_query(_enriched_sql(where_fp, safe_page_size, offset, with_tcp=True))
    except RequestLogError as exc:
        msg = str(exc)
        if "tcp_fingerprints" in msg and "does not exist" in msg:
            data = _run_json_query(_enriched_sql(where_fp, safe_page_size, offset, with_tcp=False))
        elif "browser_fingerprints" in msg and "does not exist" in msg:
            where_plain = _conditions(site, method, search, include_fp=False)
            return _run_json_query(_plain_sql(where_plain, safe_page_size, offset))
        else:
            raise

    # Compute a cross-layer verdict for EVERY row, not just ones with a beacon: a
    # browser-UA request that never ran JS must still surface the browser_no_js
    # signal (headless/agentic crawler). verdict_for detects fp presence itself.
    for row in data.get("rows") or []:
        row["fp_present"] = bool(row.get("fp_id") or row.get("canvas_hash"))
        row["verdict"] = verdict_for(row)
    return data


def fetch_filter_options():
    """Return all known site and request-method filter values."""
    sql = """
    SELECT json_build_object(
        'sites', (SELECT COALESCE(json_agg(site ORDER BY site), '[]'::json)
                  FROM (SELECT DISTINCT site FROM all_visits
                        WHERE site IS NOT NULL AND site <> '') s),
        'methods', (SELECT COALESCE(json_agg(method ORDER BY method), '[]'::json)
                    FROM (SELECT DISTINCT method FROM all_visits
                          WHERE method IS NOT NULL AND method <> '') m)
    );
    """
    return _run_json_query(sql)


def total_request_count():
    """Best-effort total row count in ``all_visits`` (for landing stats)."""
    try:
        data = _run_json_query("SELECT json_build_object('n', COUNT(*)) FROM all_visits;")
        return data.get("n", 0)
    except RequestLogError:
        return None


def site_status_map():
    """Map each known site to 'active' (a live proxy route) or 'historical'."""
    active = set(active_proxy_sites())
    return active


def requests_to_csv(rows):
    """Serialize request rows to CSV without spreadsheet-formula execution.

    User-Agent, URI, and several header-derived values are attacker controlled.
    Spreadsheet applications may interpret cells beginning with ``=``, ``+``,
    ``-``, or ``@`` (including after whitespace/control prefixes) as formulas.
    A leading apostrophe makes those values literal when an operator opens the
    export, while remaining explicit data for ordinary CSV readers.
    """
    def safe_cell(value):
        if not isinstance(value, str):
            return value
        probe = value.lstrip(" \t\r\n\ufeff")
        if probe.startswith(("=", "+", "-", "@")):
            return "'" + value
        return value

    output = StringIO()
    fields = [
        "id", "ts", "site", "client_ip", "method", "response_status",
        "uri", "user_agent", "request_id", "headers",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        csv_row = {field: safe_cell(row.get(field)) for field in fields}
        csv_row["headers"] = json.dumps(csv_row["headers"], sort_keys=True)
        writer.writerow(csv_row)
    return output.getvalue()
