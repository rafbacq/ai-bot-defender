"""Seed the live logdb with a realistic multi-IP crawler population.

A single host cannot put many distinct source IPs on the wire — the anti-spoof
proxy pins every request to the real TCP peer (the Docker gateway), and forged
``X-Forwarded-For`` is overwritten. So to demonstrate the campaign graph (which is
an inherently *many-IP* feature) on the real ``logdb`` + the real pipeline + the
real renderer, we insert a synthetic population — the same labelled fleet the
offline suite uses (declared crawlers, humans, a disguised stealth fleet, an
agentic cohort, a proxy-rotating device, a VM cohort) — directly into the central
log tables.

Every row is **clearly marked** (UA suffix / handshake ``uid`` = ``AIBDSEED``) so
it is trivially identifiable and removable (``clean_logdb``). We also seed the
ASN cache for the synthetic IPs, so the real recompute attributes them without any
network RDAP lookups. Nothing here is destructive to real traffic.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
# The offline synthetic population generator is the single source of truth.
sys.path.insert(0, str(REPO_ROOT / "testsuite" / "tests"))

PROXY_COMPOSE = REPO_ROOT / "docker-compose.proxy.yml"
SEED_TAG = "AIBDSEED"   # stable marker for identify + cleanup
# Markers the OTHER live features tag their fabricated traffic with (the
# fingerprinting/webapp beacons and page views, the pageview-join probe). Every
# fabricated row any app test writes carries one of these, so cleanup is always
# marker-scoped and can never touch real traffic.
LIVE_TAGS = ("AIBDLive", "regression-test", "pvtest")


# --- population ------------------------------------------------------------
def build_population(scale=3):
    """Return the labelled multi-IP population, with every row marked AIBDSEED."""
    from synthetic import bot_population

    visits, handshakes, browser_fps, tcp_fps, labels = bot_population(scale=scale)
    for v in visits:
        v["user_agent"] = f"{v['user_agent']} {SEED_TAG}"
    for b in browser_fps:
        b["user_agent"] = f"{b['user_agent']} {SEED_TAG}"
    return visits, handshakes, browser_fps, tcp_fps, labels


# --- SQL helpers -----------------------------------------------------------
def _q(value):
    return "'" + str(value).replace("'", "''") + "'"


def _jsonb(value):
    return _q(json.dumps(value)) + "::jsonb"


def _int(value):
    try:
        return str(int(value))
    except (TypeError, ValueError):
        return "NULL"


def _opt(value):
    return _q(value) if value is not None else "NULL"


def _exec(sql_text, timeout=180):
    cmd = ["docker", "compose", "-f", str(PROXY_COMPOSE), "exec", "-T", "logdb",
           "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "logger", "-d", "site_logs"]
    result = subprocess.run(cmd, input=sql_text, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip())
    return result.stdout


def _insert(table, columns, rows, chunk=400):
    """Build chunked multi-row INSERT statements for one table."""
    if not rows:
        return ""
    cols = ", ".join(columns)
    out = []
    for i in range(0, len(rows), chunk):
        values = ",\n".join(rows[i:i + chunk])
        out.append(f"INSERT INTO {table} ({cols}) VALUES\n{values};")
    return "\n".join(out)


# --- seed / clean ----------------------------------------------------------
def clean_logdb():
    """Remove every test-fabricated row from the central log (safe, marker-scoped).

    Covers the seeded campaign population (``AIBDSEED``) *and* the tagged traffic
    the other live features emit (``AIBDLive*``/``regression-test``/``pvtest``
    beacons + page views). Leaving these behind made the real /logs page report
    phantom devices and campaigns long after a test run."""
    ua_terms = " OR ".join(f"user_agent LIKE '%{tag}%'" for tag in (SEED_TAG,) + LIVE_TAGS)
    fp_terms = ua_terms + " OR " + " OR ".join(f"fp_id LIKE '%{tag}%'" for tag in LIVE_TAGS)
    _exec(
        f"DELETE FROM all_visits WHERE {ua_terms};\n"
        f"DELETE FROM browser_fingerprints WHERE {fp_terms};\n"
        f"DELETE FROM tls_handshakes WHERE uid = '{SEED_TAG}';\n"
        f"DELETE FROM tcp_fingerprints WHERE uid = '{SEED_TAG}';\n"
    )


def seed_logdb(visits, handshakes, browser_fps, tcp_fps, canonical_site):
    """Replace any prior seed with this population (idempotent)."""
    av = [
        f"({_q(v['ts'])}, {_q(canonical_site)}, {_q(v['client_ip'])}, {_int(v.get('client_port'))}, "
        f"{_q(v['user_agent'])}, {_q(v.get('method', 'GET'))}, {_q(v.get('uri', '/'))}, "
        f"{_jsonb(v.get('headers') or {})})"
        for v in visits
    ]
    hs = [
        f"({_q(h['ts'])}, {_q(SEED_TAG)}, {_q(h['src_ip'])}, {_int(h.get('src_port'))}, "
        f"{_opt(h.get('ja3'))}, {_opt(h.get('ja4'))}, {_opt(h.get('sni'))})"
        for h in handshakes
    ]
    bf = [
        f"({_q(b['ts'])}, {_q(canonical_site)}, {_q(b['client_ip'])}, {_int(b.get('client_port'))}, "
        f"{_q(b['user_agent'])}, {_q(b.get('phase', 'load'))}, {_opt(b.get('fp_id'))}, "
        f"{_opt(b.get('canvas_hash'))}, {_opt(b.get('webgl_hash'))}, {_opt(b.get('webgl_vendor'))}, "
        f"{_opt(b.get('webgl_renderer'))}, {_opt(b.get('audio_hash'))}, {_opt(b.get('font_hash'))}, "
        f"{_jsonb(b.get('navigator') or {})}, {_jsonb(b.get('automation') or {})}, "
        f"{_jsonb(b.get('behavior') or {})})"
        for b in browser_fps
    ]
    tf = [
        f"({_q(t['ts'])}, {_q(SEED_TAG)}, {_q(t['src_ip'])}, {_int(t.get('src_port'))}, "
        f"{_opt(t.get('os_guess'))}, {_opt(t.get('ja4t'))})"
        for t in tcp_fps
    ]

    sql = (
        f"DELETE FROM all_visits WHERE user_agent LIKE '%{SEED_TAG}%';\n"
        f"DELETE FROM browser_fingerprints WHERE user_agent LIKE '%{SEED_TAG}%';\n"
        f"DELETE FROM tls_handshakes WHERE uid = '{SEED_TAG}';\n"
        f"DELETE FROM tcp_fingerprints WHERE uid = '{SEED_TAG}';\n"
        + _insert("all_visits", ["ts", "site", "client_ip", "client_port", "user_agent",
                                 "method", "uri", "headers"], av) + "\n"
        + _insert("tls_handshakes", ["ts", "uid", "src_ip", "src_port", "ja3", "ja4", "sni"], hs) + "\n"
        + _insert("browser_fingerprints",
                  ["ts", "site", "client_ip", "client_port", "user_agent", "phase", "fp_id",
                   "canvas_hash", "webgl_hash", "webgl_vendor", "webgl_renderer", "audio_hash",
                   "font_hash", "navigator", "automation", "behavior"], bf) + "\n"
        + _insert("tcp_fingerprints", ["ts", "uid", "src_ip", "src_port", "os_guess", "ja4t"], tf)
    )
    _exec(sql)
    return {"all_visits": len(av), "tls_handshakes": len(hs),
            "browser_fingerprints": len(bf), "tcp_fingerprints": len(tf)}


# --- ASN cache (so recompute attributes the synthetic IPs without RDAP) -----
def _asn_cache_path():
    from crawler_graph import config as cg_config
    return cg_config.ASN_CACHE


def seed_asn_cache(visits):
    """Merge the synthetic IP -> ASN mapping into the crawler_graph ASN cache."""
    from crawler_graph import config as cg_config
    cg_config.ensure_output_dir()
    path = _asn_cache_path()
    cache = {}
    if path.exists():
        try:
            cache = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            cache = {}
    for v in visits:
        ip, asn = v.get("client_ip"), v.get("asn")
        if ip and ip not in cache:
            cache[ip] = {"asn": str(asn) if asn is not None else None, "descr": "seeded"}
    path.write_text(json.dumps(cache), encoding="utf-8")
    # Force the enrich module to reload the cache on its next use.
    try:
        from crawler_graph.ingest import enrich
        enrich._ASN_CACHE = None
    except Exception:
        pass


def clean_asn_cache(visits=None):
    """Drop seeded entries from the ASN cache (every seeded entry when ``visits``
    is None — the post-run cleanup path, which has no population in hand)."""
    path = _asn_cache_path()
    if not path.exists():
        return
    try:
        cache = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    seeded = None if visits is None else {v.get("client_ip") for v in visits}
    cache = {k: val for k, val in cache.items()
             if not (isinstance(val, dict) and val.get("descr") == "seeded"
                     and (seeded is None or k in seeded))}
    path.write_text(json.dumps(cache), encoding="utf-8")


# --- standalone interactive report (full fidelity, in-memory) ---------------
def build_campaigns(visits, handshakes, browser_fps, tcp_fps):
    """Build (ip_graph, membership, campaigns) from a population in-memory."""
    from crawler_graph.analysis import consistency
    from crawler_graph.graphing import builder, campaigns as camp_mod, community
    from crawler_graph.ingest import enrich

    enrich.join_fingerprints(visits, handshakes)
    enrich.join_tcp_fingerprints(visits, tcp_fps)
    enrich.enrich_visits(visits, resolve_asn=False)   # use the population's own ASNs
    endpoints = enrich.aggregate_endpoints(visits)
    enrich.attach_browser_fingerprints(endpoints, browser_fps)
    consistency.annotate(endpoints)
    graph = builder.build_graph(endpoints)
    membership, _ = community.detect_communities(graph, method="auto")
    ip_graph = builder.project_to_ip_graph(graph)
    camps = camp_mod.build_campaigns(graph, membership, endpoints)
    return ip_graph, membership, camps


def render_standalone(visits, handshakes, browser_fps, tcp_fps, path):
    """Render the interactive graph from the in-memory population to ``path``."""
    from crawler_graph import reporting
    ip_graph, membership, camps = build_campaigns(visits, handshakes, browser_fps, tcp_fps)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return reporting.render_interactive(ip_graph, membership, camps, path=path), camps


# --- the live recompute the app reads --------------------------------------
def recompute_live():
    """Run the real pipeline against the live logdb (now seeded) and persist the
    campaigns + interactive graph the app's /logs page serves."""
    from crawler_graph import pipeline
    return pipeline.run_intel(resolve_asn=True, use_gnn=False, write=True, render=True)


# --- CLI: clean only -------------------------------------------------------
def _main(argv):
    if argv and argv[0] == "--clean":
        clean_logdb()
        print(f"Removed all {SEED_TAG} rows from the central log.")
        return 0
    print("usage: python -m testsuite.app_tests.seed --clean")
    return 1


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
