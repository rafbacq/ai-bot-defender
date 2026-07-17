"""Read-only access to the Layer-1 browser fingerprints (``browser_fingerprints``).

Mirrors ``request_log.py``: queries the proxy stack's ``logdb`` by shelling
``docker compose exec`` and parsing JSON. Each fingerprint is left-joined to the
most-recent TCP/IP-stack inference for the same client IP (``tcp_fingerprints``),
then run through the SAME cross-layer consistency engine the crawler-graph uses
(``crawler_graph.analysis.consistency``) so the page shows, per visitor, whether
the claimed identity (UA / navigator.platform) contradicts the lower layers.
"""

import ipaddress
import re
import time
from urllib.parse import unquote, urlsplit

from . import logdb

# Reuse the cross-layer consistency engine from the crawler-graph package so the
# per-fingerprint verdict here matches the campaign-level analysis exactly.
try:
    from crawler_graph.analysis import consistency as _consistency
except Exception:  # pragma: no cover - surfaced as "no verdict" in the UI
    _consistency = None
# UA classifier + disguise thresholds, reused from the crawler-graph ingest layer
# so the request table, the fingerprint page, and the campaign analysis all agree
# on what "a browser" is and when a device counts as disguised.
try:
    from crawler_graph.ingest import known_crawlers as _known_crawlers
except Exception:  # pragma: no cover
    _known_crawlers = None
try:
    from crawler_graph import config as _cg_config
except Exception:  # pragma: no cover
    _cg_config = None


class FingerprintError(RuntimeError):
    """Raised when the browser-fingerprint store cannot be queried."""


def _sql_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def _run_json_query(sql):
    try:
        return logdb.run_psql_json(sql)
    except logdb.LogDBError as exc:
        detail = str(exc)
        if "is not running" in detail or "no container found" in detail:
            detail = "The reverse proxy database is not running. Start it with `make proxy`."
        elif 'relation "browser_fingerprints" does not exist' in detail:
            detail = ("No browser fingerprints captured yet. They are collected when an "
                      "agentic / JS-capable visitor loads a honeypot page (fp.js -> /__fpbeacon).")
        raise FingerprintError(detail or "The fingerprint query failed.") from exc


def _select_sql(where_clause, page_size, offset, with_tcp=True):
    # Left-join each fingerprint to the TCP/IP OS inference of *its own connection*
    # when we have it: prefer the SYN matching the beacon's (client_ip, client_port)
    # 4-tuple, then fall back to the nearest earlier SYN from the same IP (never a
    # later one — behind a NAT the "latest SYN from this IP" can be a *different
    # device's* kernel, which must not be glued onto this beacon). The join is
    # optional because tcp_fingerprints is created by the Zeek shipper and may not
    # exist yet on a fresh stack. The lower bound prevents source-port reuse or an
    # old same-IP SYN from contaminating a later visitor; 5s of forward slack
    # absorbs clock skew between Zeek and the collector. A same-IP fallback remains
    # visible, but ``tcp_match_exact = false`` prevents it from accusing this row.
    tcp_select = (
        "t.os_guess AS tcp_os, t.ja4t AS ja4t, t.tcp_match_exact"
        if with_tcp else
        "NULL AS tcp_os, NULL AS ja4t, NULL::boolean AS tcp_match_exact"
    )
    tcp_join = (
        "LEFT JOIN LATERAL (SELECT os_guess, ja4t, "
        "COALESCE(tt.src_port = b.client_port, FALSE) AS tcp_match_exact "
        "FROM tcp_fingerprints tt WHERE tt.src_ip = b.client_ip "
        "AND tt.ts BETWEEN b.ts - INTERVAL '5 minutes' AND b.ts + INTERVAL '5 seconds' "
        "ORDER BY (tt.src_port = b.client_port) DESC NULLS LAST, "
        "abs(extract(epoch FROM (tt.ts - b.ts))) ASC LIMIT 1) t ON TRUE"
        if with_tcp else ""
    )
    return f"""
    WITH filtered AS (
        SELECT b.ts, b.site, b.client_ip, b.client_port, b.user_agent, b.phase,
               b.fp_id, b.canvas_hash, b.webgl_hash, b.webgl_vendor, b.webgl_renderer,
               b.audio_hash, b.font_hash, b.navigator, b.automation, b.behavior, b.screen,
               {tcp_select}
        FROM browser_fingerprints b {tcp_join}
        WHERE {where_clause}
    ),
    page_rows AS (
        SELECT * FROM filtered ORDER BY ts DESC LIMIT {page_size} OFFSET {offset}
    )
    SELECT json_build_object(
        'total', (SELECT COUNT(*) FROM filtered),
        'unique_devices', (SELECT COUNT(DISTINCT fp_id) FROM filtered),
        'last_24h', (SELECT COUNT(*) FROM filtered WHERE ts >= NOW() - INTERVAL '24 hours'),
        'latest_ts', (SELECT MAX(ts) FROM filtered),
        'rows', (SELECT COALESCE(json_agg(row_to_json(page_rows) ORDER BY ts DESC), '[]'::json)
                 FROM page_rows)
    );
    """


def fetch_fingerprints(*, site="All sites", search="", page=1, page_size=50):
    """Return one filtered page of browser fingerprints + per-row consistency verdict."""
    conditions = []
    if site != "All sites":
        conditions.append(f"b.site = {_sql_literal(site)}")
    if search.strip():
        literal = _sql_literal(search.strip().lower())
        conditions.append(
            "POSITION(" + literal + " IN LOWER(CONCAT_WS(' ', b.site, b.client_ip, "
            "b.user_agent, b.fp_id, b.canvas_hash, b.webgl_renderer))) > 0"
        )
    where_clause = " AND ".join(conditions) if conditions else "TRUE"
    safe_page = max(1, int(page))
    safe_page_size = min(200, max(10, int(page_size)))
    offset = (safe_page - 1) * safe_page_size

    try:
        data = _run_json_query(_select_sql(where_clause, safe_page_size, offset, with_tcp=True))
    except FingerprintError as exc:
        if "tcp_fingerprints" in str(exc) and "does not exist" in str(exc):
            data = _run_json_query(_select_sql(where_clause, safe_page_size, offset, with_tcp=False))
        else:
            raise

    for row in data.get("rows") or []:
        row["verdict"] = _verdict_for(row)
    return data


def _ua_is_browser(ua):
    """Whether a User-Agent claims to be an interactive browser (not a declared bot)."""
    if _known_crawlers is not None:
        try:
            return bool(_known_crawlers.is_browser_ua(ua))
        except Exception:
            pass
    u = (ua or "").lower()
    return "mozilla/" in u and any(
        t in u for t in ("chrome/", "safari/", "firefox/", "edg/", "opr/")
    )


def _ua_is_declared_crawler(ua):
    if _known_crawlers is None:
        return False
    try:
        return bool(_known_crawlers.is_declared_crawler(ua))
    except Exception:
        return False


def _ua_looks_automated(ua):
    if _known_crawlers is None:
        return False
    try:
        return bool(_known_crawlers.looks_automated(ua))
    except Exception:
        return False


def _is_document_request(row):
    """Whether this row represents the honeypot document that can execute fp.js.

    A missing beacon is meaningful only after a browser loads the HTML document.
    Static assets, robots.txt, favicon requests, HEAD requests, and arbitrary probe
    paths cannot execute the script themselves and must not receive a row-level
    browser-no-JS score merely because they carry a browser-shaped User-Agent.
    """
    if str(row.get("method") or "").upper() != "GET":
        return False
    path, _query = _decoded_request_target(row.get("uri"))
    return path == "/"


def _verdict_for(row):
    """Run the shared consistency engine on one row — a browser fingerprint OR a
    plain request row that carries no beacon.

    Fingerprint presence is detected from the row itself (``fp_id``/``canvas_hash``)
    rather than assumed, so the engine's ``browser_no_js`` rule can finally fire for
    a **browser-UA document request that never executed JS** (a headless/agentic
    crawler — the exact thing this system exists to catch). Resource rows that could
    never execute fp.js are ineligible. On a public IP such a row can also trip the
    UA-vs-TCP-OS contradiction. Automation is left for the engine to decide from the
    tells (strong/weak weighting) instead of pre-flagging it from the raw count."""
    if _consistency is None:
        return None
    has_fp = bool(row.get("fp_id") or row.get("canvas_hash"))
    nav = row.get("navigator") or {}
    auto = row.get("automation") or {}
    beh = row.get("behavior") or {}
    tcp_os = row.get("tcp_os")
    ua = row.get("user_agent") or row.get("ua_top")
    rec = {
        "client_ip": row.get("client_ip"),
        "ua_top": ua,
        "js_platform": nav.get("platform") if has_fp else None,
        "tcp_os": [tcp_os] if tcp_os and tcp_os != "unknown" else [],
        "webgl_renderers": [row["webgl_renderer"]] if row.get("webgl_renderer") else [],
        "automation_score": auto.get("score") or 0,
        "automation_tells": {k: v for k, v in auto.items() if v is True},
        # A transparent tool/scanner UA is independent evidence even without JS.
        # Declared provider UAs are not in this marker list and remain separate.
        "is_automated": _ua_looks_automated(ua),
        "is_browser": _ua_is_browser(ua),
        "is_declared_crawler": _ua_is_declared_crawler(ua),
        "has_browser_fingerprint": has_fp,
        "n_requests": 1 if _is_document_request(row) else 0,
        "tcp_match_exact": row.get("tcp_match_exact"),
        "behavior_synthetic": bool(beh.get("synthetic")) if has_fp else False,
        "behavior_interacted": bool(beh.get("interacted")) if has_fp else False,
    }
    try:
        return _consistency.score_endpoint(rec)
    except Exception:
        return None


# Public alias so other services (e.g. request_log, which now folds the latest
# fingerprint into each request row) can reuse the exact per-visitor consistency
# verdict instead of reaching for a private name.
verdict_for = _verdict_for


# --- Malicious-intent detection from the request TARGET (not just the client) -----
# The cross-layer engine above judges a visitor by whether its *identity* is
# self-consistent. That misses a scanner that tells the truth about itself while
# reaching for something it has no business touching: a request for `/.env` or
# `/wp-login.php` is hostile no matter how honest the User-Agent is (an honest bot
# UA, or a real-looking Googlebot string, would otherwise slip through as "clean").
# The honeypot's Flask app serves exactly one real route (`GET /`) plus a few static
# assets, so any request for a secrets file, a VCS/IDE dir, a framework admin panel,
# or a language/CMS the stack doesn't run is by definition probing, not browsing.
#
# Patterns are drawn from this deployment's own observed scan traffic plus the
# standard scanner dictionaries (Androxgh0st `.env` sweeps, l9scan, zgrab). Path
# and query signatures stay separate: exploit parameters in the query must be
# visible, but an arbitrary benign root query must not trip a path-name rule.
_SAFE_EXACT_PATHS = frozenset({
    "/", "/favicon.ico", "/robots.txt", "/css/site.css", "/js/fp.js",
    "/__fpbeacon", "/sitemap.xml",
    "/sitemap-index.xml", "/sitemap_index.xml",
    "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png",
})
# Only ACME owns a legitimate variable path namespace. Application assets are
# exact because this honeypot currently ships only /css/site.css and /js/fp.js;
# blanket /css/ or /static/ allowlists hide scanner dictionary requests.
_SAFE_PREFIXES = ("/.well-known/acme-challenge/",)
_SAFE_EXACT_WELL_KNOWN = frozenset({"/.well-known/security.txt"})

_PROBE_PATTERNS = [
    # --- Secrets / config / source-control / backup exfiltration ---
    (r"\.env(?:$|[./_~-]|\d|rc\b)", "probing for a secrets file (.env)"),
    (r"\.git(/|$)|\.git/config|\.gitignore", "probing for an exposed .git repository"),
    (r"\.svn(/|$)|\.hg(/|$)|\.bzr(/|$)", "probing for an exposed source-control directory"),
    (r"\.(aws|ssh)(/|$)|id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys",
     "probing for cloud/SSH credentials"),
    (r"\.vscode/|\.idea/|sftp\.json", "probing for exposed IDE/deploy config"),
    (r"\.ds_store", "probing for a leaked .DS_Store directory listing"),
    (r"wp-config(?:-sample)?(?:\.[^/?]+)?|configuration\.php|"
     r"/config\.(json|xml|php|ya?ml)\b|/settings\.py",
     "probing for an application config/credentials file"),
    (r"credentials|secrets?\.(json|ya?ml|txt)|/dump\.sql|storage/logs|laravel\.log|"
     r"(?:^|/)(?:\.netrc|\.pypirc|\.dev\.vars|firebase-debug\.log|debug\.log|error_log)(?:$|[/?])",
     "probing for credentials/log files"),
    (r"phpinfo|/server-status\b|/server-info\b|/_profiler\b|/actuator(/|$|\b)",
     "probing a debug/status endpoint that leaks internals"),
    (r"\.(bak|old|save|swp|orig|sql|dump|pem|key|p12|pfx)($|\?)",
     "probing for a backup/dump/key file"),
    (r"/backup|/backups?\b|\.(zip|tar|tgz|tar\.gz|rar|7z)($|\?)",
     "probing for a downloadable backup archive"),
    # --- Exploit / admin-panel / CMS / device recon ---
    (r"wp-admin|wp-login|wp-includes|wlwmanifest|xmlrpc\.php|/wp-json",
     "WordPress attack-surface probe (this stack runs no WordPress)"),
    (r"login\.action|struts|/geoserver|/druid/|/solr/|jenkins|phpmyadmin|/pma\b|/adminer",
     "known-CVE application/admin-panel probe"),
    (r"/ecp/|/owa/|autodiscover|/mapi/|activesync",
     "Exchange/mail attack-surface probe"),
    (r"cpanel|/whm\b|___proxy_subdomain|/console/|/manager/html|jmx-console|/v2/_catalog",
     "hosting-panel/registry/console probe"),
    (r"/boaform|/cgi-bin/|/hnap1|/goform|/setup\.cgi|/currentsetting\.htm",
     "router/IoT device-exploit probe"),
    (r"/(?:\+webvpn\+|\+cscoe\+|dana-na|remote/login|sslvpnclient|global-protect)(?:/|$)",
     "VPN-appliance attack-surface probe"),
    (r"/(?:graphql(?:/|$)|api/(?:graphql|gql)(?:/|$)|grpc\.reflection\.)",
     "GraphQL/gRPC service-discovery probe"),
    (r"^/(?:api/swagger\.json|swagger-ui\.html|v2/api-docs|graphiql)/?$",
     "API documentation/schema discovery probe"),
    (r"^/_cat/indices/?$|^/app/kibana/?$",
     "Elasticsearch/Kibana service-discovery probe"),
    (r"^/(?:_environment|webroot/index\.php/_environment)/?$|"
     r"^/debug/pprof/cmdline/?$",
     "framework/runtime diagnostics probe"),
    (r"/containers/json(?:/|$)", "Docker API discovery probe"),
    (r"/developmentserver/metadatauploader(?:/|$)",
     "development-server metadata probe"),
    (r"/reportserver(?:/|$)|/debug/default/view(?:/|$)|/@vite/env(?:/|$)|"
     r"/trace\.axd(?:/|$)|/telescope(?:/|$)",
     "probing a debug/status endpoint that leaks internals"),
    (r"/meta-inf/|docker-compose(?:\.[^/]+)?\.ya?ml$|/\.bash_history$|/\.npmrc$|"
     r"/config/(?:production|development|staging)\.json$|/[^/]*service\.pwd$|"
     r"(?:^|/)(?:dockerfile|procfile|serverless\.ya?ml)$|/functions/\.runtimeconfig\.json$",
     "probing for an application config/credentials file"),
    (r"/mcp(?:/|$)|/onvif(?:/|$)|/portal/redlion(?:/|$)",
     "service/device-management discovery probe"),
    (r"^/evox/about/?$|^/nmaplowercheck[^/]*$",
     "scanner/device reconnaissance probe"),
    (r"^/(?:administrator/components/com_jce/jce\.xml|"
     r"administrator/manifests/packages/pkg_jce\.xml|"
     r"plugins/editors/jce/jce\.xml)/?$",
     "Joomla JCE extension-manifest probe"),
    (r"^/wp-content/cache/breeze-extra(?:/|$)",
     "WordPress Breeze cache-plugin probe"),
    # Matched on the path only, so this stays confined to dedicated resolver
    # endpoints and never trips a legitimate query parameter named `name`.
    (r"/dns-query\b|/resolve\b", "open-DNS-resolver abuse probe"),
    (r"\.(php|phtml|php5|asp|aspx|jsp|jspx|cgi|action)($|\?)",
     "requesting a server-side script this static stack does not run"),
    (r"/\.well-known/.*(\.\.|/\.env|password)",
     "malformed/traversal probe under /.well-known"),
]
_PROBE_PATTERNS = [(re.compile(p, re.IGNORECASE), r) for p, r in _PROBE_PATTERNS]

_QUERY_PROBE_PATTERNS = [
    (r"(?:^|[&;+])rest_route\s*=\s*/?(?:wp/|fluentsmtp/|gravitysmtp/|post-smtp/|wp-mail-smtp/)",
     "WordPress API enumeration probe (this stack runs no WordPress)"),
    (r"allow_url_include|auto_prepend_file|php://input",
     "PHP-CGI argument-injection probe"),
]
_QUERY_PROBE_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), reason)
    for pattern, reason in _QUERY_PROBE_PATTERNS
]

_MAX_TARGET_CHARS = 16_384
_DANGEROUS_METHODS = frozenset({"CONNECT", "TRACE"})
_READ_METHODS = frozenset({"GET", "HEAD"})


def _decoded_request_target(uri):
    """Return a normalized ``(path, query)`` without raising on hostile input.

    Two decode passes catch the common double-encoded traversal form without an
    unbounded decoding loop.  The cap is defensive only—nginx's request-line limit
    is already smaller—and keeps direct/unit callers from feeding huge strings to
    the regular expressions.
    """
    if uri is None:
        return "", ""
    raw_target = str(uri).strip()[:_MAX_TARGET_CHARS]
    if not raw_target:
        return "", ""

    # Split the *wire-level* delimiters before percent-decoding. Encoded `%23`
    # and `%3f` bytes are path data, not fragment/query separators; decoding the
    # whole target first let `/%23/.env` collapse to `/` and hid the probe.
    try:
        if "://" in raw_target:
            parsed = urlsplit(raw_target)
            raw_path, raw_query = parsed.path, parsed.query
        else:
            without_fragment = raw_target.split("#", 1)[0]
            raw_path, marker, raw_query = without_fragment.partition("?")
            if not marker:
                raw_query = ""
    except (TypeError, ValueError):
        without_fragment = raw_target.split("#", 1)[0]
        raw_path, marker, raw_query = without_fragment.partition("?")
        if not marker:
            raw_query = ""

    def decode_component(value):
        decoded = value
        for _ in range(2):
            next_value = unquote(decoded, errors="replace")
            if next_value == decoded:
                break
            decoded = next_value
        return decoded

    path = decode_component(raw_path).replace("\\", "/")
    query = decode_component(raw_query)
    return (path or "/").strip().lower(), query.strip().lower()


def _safe_path(path):
    return (
        path in _SAFE_EXACT_PATHS
        or path in _SAFE_EXACT_WELL_KNOWN
        or any(path.startswith(prefix) for prefix in _SAFE_PREFIXES)
    )


def target_assessment(uri, method=None):
    """Classify the request target/method independently of client identity.

    Returns a severity dictionary for a known malicious probe or an unexpected
    route/method, and ``None`` for an allowed honeypot request.  The application
    intentionally serves one document plus a small asset/ACME allowlist, so an
    otherwise unknown route is worth review even when it misses a named exploit
    signature; it is orange rather than red to preserve room for human typos.
    """
    path, query = _decoded_request_target(uri)
    if not path:
        return None
    normalized_method = str(method or "").strip().upper()
    has_traversal = ".." in path

    for pattern, reason in _QUERY_PROBE_PATTERNS:
        if pattern.search(query):
            return {"level": "malicious", "reason": reason}
    for pattern, reason in _PROBE_PATTERNS:
        if pattern.search(path):
            return {"level": "malicious", "reason": reason}
    if has_traversal:
        return {"level": "malicious",
                "reason": "path-traversal attempt in the request URI"}
    if normalized_method in _DANGEROUS_METHODS:
        return {"level": "malicious",
                "reason": f"unsupported high-risk HTTP method ({normalized_method})"}

    if _safe_path(path):
        allowed_methods = {"POST", "OPTIONS"} if path == "/__fpbeacon" else _READ_METHODS
        if normalized_method and normalized_method not in allowed_methods:
            return {"level": "suspicious",
                    "reason": f"unsupported {normalized_method} request to {path}"}
        return None

    return {"level": "suspicious", "reason": f"unexpected honeypot route ({path})"}


def probe_reason(uri, method=None):
    """Return a short reason if ``uri`` is a hostile scan target, else ``None``.

    Judges the request TARGET, independent of the client's claimed identity, so a
    truthful-looking bot reaching for a secrets file / exploit path is still caught.
    Legit honeypot paths (the served route, static assets, ACME) are allowlisted.
    Path traversal (``..``) is never allowlisted — it falls through to the patterns.
    """
    assessment = target_assessment(uri, method)
    if assessment and assessment["level"] == "malicious":
        return assessment["reason"]
    return None


def severity_of(row):
    """Collapse a request's verdict into a 3-tier row severity for the /logs table.

    Returns ``{"level": "clean"|"suspicious"|"malicious", "reason": <short text>}``,
    driven by the cross-layer engine (so it stays consistent with the campaign
    analysis), the identity-rotation flags, AND the request TARGET:
      * **malicious** (red) — a device wearing multiple claimed identities
        (``disguised``, engine/OS/client-kind changes — never version or brand
        churn), a cross-layer contradiction at/above the inconsistency threshold,
        OR a request whose URI is a hostile scan target (a secrets file, a VCS/IDE
        dir, an exploit/admin path, a script this static stack never runs — see
        ``probe_reason``). The last one is judged from the target alone, so an
        honest-looking bot reaching for ``/.env`` is caught even when its identity
        is self-consistent. Certainly a bot.
      * **suspicious** (orange) — an unexpected route/method, or a device roaming
        public networks under one
        identity (``net_roaming`` — proxy/VPN rotation, but equally a phone on
        Wi-Fi/LTE, so never red on its own) or a lesser contradiction
        (browser-UA-but-no-JS, a VM/software GPU, automation tells, synthetic
        input): worth a closer look.
      * **clean** (green) — self-consistent, or an honest non-JS / declared client.
    """
    v = row.get("verdict") or {}
    if row.get("disguised"):
        return {"level": "malicious", "reason": "one device wearing multiple identities"}
    target = target_assessment(row.get("uri"), row.get("method"))
    if target and target["level"] == "malicious":
        return target
    if v.get("inconsistent"):
        return {"level": "malicious", "reason": "cross-layer contradiction (spoofed identity)"}
    if target:
        return target
    if row.get("net_roaming"):
        return {"level": "suspicious",
                "reason": "one device seen from multiple public networks (roaming or proxy/VPN rotation)"}
    if v.get("score"):
        if v.get("vm_cohort"):
            reason = "VM / software-GPU renderer"
        elif v.get("automation"):
            reason = "automation/tooling signature present"
        elif v.get("browser_no_js"):
            reason = "browser User-Agent but never ran JS"
        elif not row.get("fp_present"):
            reason = "cross-layer inconsistency without a browser fingerprint"
        elif v.get("behavior_class") == "synthetic":
            reason = "synthetic (too-regular) input timing"
        else:
            reason = "minor cross-layer mismatch"
        return {"level": "suspicious", "reason": reason}
    if not row.get("fp_present"):
        return {"level": "clean", "reason": "no browser fingerprint (non-JS client)"}
    return {"level": "clean", "reason": "self-consistent"}


def fetch_sites():
    """Distinct site values present in browser_fingerprints (for the filter)."""
    sql = (
        "SELECT COALESCE(json_agg(site ORDER BY site), '[]'::json) FROM "
        "(SELECT DISTINCT site FROM browser_fingerprints WHERE site IS NOT NULL "
        "AND site <> '') s;"
    )
    try:
        return _run_json_query(sql) or []
    except FingerprintError:
        return []


def summary_counts():
    """Best-effort totals for the landing stats (None when unavailable)."""
    out = {"fingerprints": None, "unique_devices": None, "tcp_fingerprints": None}
    try:
        data = _run_json_query(
            "SELECT json_build_object('fingerprints', COUNT(*), "
            "'unique_devices', COUNT(DISTINCT fp_id)) FROM browser_fingerprints;"
        )
        out["fingerprints"] = data.get("fingerprints", 0)
        out["unique_devices"] = data.get("unique_devices", 0)
    except FingerprintError:
        pass
    try:
        data = _run_json_query(
            "SELECT json_build_object('n', COUNT(*)) FROM tcp_fingerprints;"
        )
        out["tcp_fingerprints"] = data.get("n", 0)
    except FingerprintError:
        pass
    return out


# --- Identity-rotation / disguise detection --------------------------------
# A single physical device leaves the SAME composite fp_id on every beacon, so if
# its beacons span more than one *claimed identity* or more than one public
# network it is presenting as more than one visitor — UA spoofing and/or IP
# rotation. This is the canary-token disguise signal viewed through the device
# layer: the honeypot now serves one device one canary set (via the __abd_fp
# cookie), so a device that still shows up under several identities is
# deliberately disguising itself.
#
# Two findings with DIFFERENT severities, both shaped by real false positives:
#   * ``basis="identities"`` — the device claims >=2 version/brand-insensitive
#     identities (``known_crawlers.ua_identity``: engine family + OS family).
#     A browser auto-update (Edg/149 -> Edg/150) and a second Chromium-shell
#     browser on the same machine (Chrome and Edge share one Blink fp_id, iOS
#     shells share WebKit) are ONE identity; a second engine, another claimed
#     OS, a headed->HeadlessChrome flip, a tool, or a bot UA is a real second
#     identity. This basis is the actual disguise — the rows go red.
#   * ``basis="networks"`` — one identity seen from at least
#     ``DISGUISE_DEVICE_ROAM_MIN_NETBLOCKS`` public network blocks, matching the
#     campaign-level mobility guard. A phone hopping Wi-Fi/LTE, a commuter, or
#     a privacy VPN commonly spans 2-3 blocks, so only a wider footprint marks
#     the rows suspicious (orange), never malicious.
#     Blocks are counted per address family (max of v4 /24s and v6 /48s — a
#     dual-stack line is one network, and v6 privacy-extension suffix rotation
#     stays inside its /48); private/loopback/CGNAT sources don't count at all,
#     because behind the local NAT / Docker hop the address is the *gateway's*
#     and recreating the stacks renumbers it (observed live: 172.19.0.1 one
#     week, 172.18.0.1 the next — which once flagged the operator's own browser).


# Last disguise_summary result, so the /logs AJAX paging (which needs the disguised
# fp_id set on every page flip) doesn't re-shell psql each time. Keyed by limit.
_DISGUISE_CACHE = {"at": 0.0, "limit": None, "data": None}


def _ua_identity_count(uas):
    """Distinct *claimed identities* among a device's raw UA strings.

    Version-insensitive: ``Edg/149`` and ``Edg/150`` are one identity (a browser
    update), ``Chrome`` vs ``curl`` vs ``HeadlessChrome`` are separate ones. Falls
    back to raw-string counting when the shared classifier is unavailable."""
    uas = [u for u in (uas or []) if u]
    if _known_crawlers is None or not hasattr(_known_crawlers, "ua_identity"):
        return len(set(uas))
    try:
        return len({_known_crawlers.ua_identity(u) for u in uas})
    except Exception:
        return len(set(uas))


def _public_netblock_count(ips):
    """Distinct PUBLIC network blocks among a device's source addresses.

    Counted per address family and combined as ``max(v4 /24s, v6 /48s)``:
      * private / loopback / link-local / CGNAT sources never count — behind
        the local NAT / Docker hop that address is the gateway's, an artifact
        of topology that renumbers when stacks are recreated;
      * IPv6 groups by /48 so privacy-extension suffix rotation (a new v6
        address every day inside one delegation) isn't misread as rotation;
      * ``max`` (not sum) because a dual-stack visitor beacons one v4 and one
        v6 address of the SAME access line — one network, not two."""
    v4, v6 = set(), set()
    for raw in ips or []:
        try:
            addr = ipaddress.ip_address(str(raw).split("%")[0])
        except ValueError:
            continue
        if not addr.is_global:
            continue
        if addr.version == 4:
            v4.add(ipaddress.ip_network(f"{addr}/24", strict=False))
        else:
            v6.add(ipaddress.ip_network(f"{addr}/48", strict=False))
    return max(len(v4), len(v6))


def _device_disguise_basis(device, *, min_identities, roam_min):
    """Attach normalized counts and return this device's flag basis, if any."""
    device["n_identities"] = _ua_identity_count(device.get("uas"))
    device["n_net"] = _public_netblock_count(device.get("ips"))
    if device["n_identities"] >= min_identities:
        return "identities"
    if device["n_net"] >= roam_min:
        return "networks"
    return None


def disguise_bases(fp_ids, *, chunk_size=500):
    """Return ``{fp_id: identities|networks}`` for every requested device.

    The analytics table may display a device outside ``disguise_summary``'s
    intentionally short top-N list.  Classifying only the IDs on the current
    page keeps row annotation complete without loading every fingerprinted
    device into application memory.  Queries are chunked and SQL literals are
    escaped; a temporarily unavailable fingerprint store degrades to no flags.
    """
    values = [fp_ids] if isinstance(fp_ids, str) else (fp_ids or [])
    normalized = sorted({str(value) for value in values if value})
    if not normalized:
        return {}
    try:
        safe_chunk_size = min(500, max(1, int(chunk_size)))
    except (TypeError, ValueError):
        safe_chunk_size = 500
    min_identities = (
        getattr(_cg_config, "DISGUISE_MIN_UAS", 2) if _cg_config else 2
    )
    roam_min = (
        getattr(_cg_config, "DISGUISE_DEVICE_ROAM_MIN_NETBLOCKS", 4)
        if _cg_config else 4
    )
    flags = {}
    try:
        for offset in range(0, len(normalized), safe_chunk_size):
            chunk = normalized[offset:offset + safe_chunk_size]
            literals = ", ".join(_sql_literal(value) for value in chunk)
            result = _run_json_query(f"""
                SELECT json_build_object(
                    'devices', COALESCE(json_agg(row_to_json(d)), '[]'::json)
                )
                FROM (
                    SELECT fp_id,
                           jsonb_agg(DISTINCT user_agent)
                               FILTER (WHERE user_agent IS NOT NULL) AS uas,
                           jsonb_agg(DISTINCT client_ip)
                               FILTER (WHERE client_ip IS NOT NULL) AS ips
                    FROM browser_fingerprints
                    WHERE fp_id IN ({literals})
                    GROUP BY fp_id
                ) d;
            """)
            for device in result.get("devices") or []:
                fp_id = device.get("fp_id")
                basis = _device_disguise_basis(
                    device,
                    min_identities=min_identities,
                    roam_min=roam_min,
                )
                if fp_id and basis:
                    flags[str(fp_id)] = basis
    except (AttributeError, FingerprintError, TypeError, ValueError):
        return {}
    return flags


def disguise_summary(limit=50, max_age=0):
    """Devices (keyed by fp_id) that wear more than one identity or roam networks.

    Read-only aggregate over ``browser_fingerprints``. Returns
    ``{total_devices, disguised, roaming, devices:[{fp_id, basis, beacons, n_ua,
    n_identities, n_ip, n_net, uas, ips, sites, first_ts, last_ts}]}`` (devices =
    only the flagged ones, identity-based first). SQL only pre-filters cheap
    *candidates* (>=2 raw UA strings or >=2 distinct IPs); the decisive tests run
    here in Python — the normalized identity count (a browser that merely
    auto-updated or a second same-engine browser is ONE identity) and the public
    per-family netblock count (Docker-gateway renumbering, dual-stack, v6
    privacy suffixes, and normal 2-3-network mobility never count as rotation).
    ``basis="identities"`` devices are the real disguise (rows go malicious);
    ``basis="networks"`` requires at least
    ``DISGUISE_DEVICE_ROAM_MIN_NETBLOCKS`` public blocks and merely roams (rows
    go suspicious). Degrades to empty when the table doesn't exist yet.

    ``max_age`` (seconds) lets hot callers — the /logs page and its Prev/Next
    paging fragment — reuse a recent result instead of paying a psql shell-out
    per page flip; the default 0 always queries fresh."""
    if (max_age and _DISGUISE_CACHE["data"] is not None
            and _DISGUISE_CACHE["limit"] == limit
            and time.time() - _DISGUISE_CACHE["at"] < max_age):
        return _DISGUISE_CACHE["data"]
    min_ua = getattr(_cg_config, "DISGUISE_MIN_UAS", 2) if _cg_config else 2
    min_net = getattr(_cg_config, "DISGUISE_MIN_NETBLOCKS", 2) if _cg_config else 2
    roam_min = getattr(
        _cg_config, "DISGUISE_DEVICE_ROAM_MIN_NETBLOCKS", 4
    ) if _cg_config else 4
    sql = f"""
    WITH dev AS (
        SELECT fp_id,
               COUNT(*) AS beacons,
               COUNT(DISTINCT user_agent) AS n_ua,
               COUNT(DISTINCT client_ip) AS n_ip,
               MIN(ts) AS first_ts, MAX(ts) AS last_ts,
               jsonb_agg(DISTINCT user_agent) FILTER (WHERE user_agent IS NOT NULL) AS uas,
               jsonb_agg(DISTINCT client_ip) FILTER (WHERE client_ip IS NOT NULL) AS ips,
               jsonb_agg(DISTINCT site) FILTER (WHERE site IS NOT NULL AND site <> '') AS sites
        FROM browser_fingerprints
        WHERE fp_id IS NOT NULL AND fp_id <> ''
        GROUP BY fp_id
    ),
    candidates AS (
        SELECT * FROM dev WHERE n_ua >= {int(min_ua)} OR n_ip >= {int(min_net)}
    )
    SELECT json_build_object(
        'total_devices', (SELECT COUNT(*) FROM dev),
        'devices', (SELECT COALESCE(json_agg(row_to_json(x)), '[]'::json) FROM (
            SELECT * FROM candidates ORDER BY (n_ua + n_ip) DESC, beacons DESC
            LIMIT {max(int(limit), 400)}
        ) x)
    );
    """
    try:
        result = _run_json_query(sql)
        kept = []
        for dev in result.get("devices") or []:
            basis = _device_disguise_basis(
                dev,
                min_identities=min_ua,
                roam_min=roam_min,
            )
            if not basis:
                continue
            dev["basis"] = basis
            kept.append(dev)
        kept.sort(key=lambda d: (d["basis"] != "identities",
                                 -(d["n_identities"] + d["n_net"]), -(d["beacons"] or 0)))
        result["devices"] = kept[:int(limit)]
        result["disguised"] = sum(1 for d in kept if d["basis"] == "identities")
        result["roaming"] = sum(1 for d in kept if d["basis"] == "networks")
    except FingerprintError:
        result = {"total_devices": None, "disguised": None, "roaming": None, "devices": []}
    # Cache even the degraded result so a down DB isn't re-probed on every page flip.
    _DISGUISE_CACHE.update(at=time.time(), limit=limit, data=result)
    return result
