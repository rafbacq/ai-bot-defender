"""Crawler Analytics services — the read paths behind the /logs page.

``request_log`` and ``fingerprint_service`` query the proxy's logdb by shelling
``docker compose exec ... psql`` and parsing JSON. With the DB stubbed, these
tests assert the SQL the services build is correctly filtered/escaped/paginated,
that each request row is enriched with a cross-layer consistency verdict, that
CSV export is well-formed, and that everything degrades to a clear, actionable
message (not a crash) when the proxy DB is down or a table is missing.
"""

from __future__ import annotations

import csv
import json
import subprocess
from io import StringIO

PUBLIC_IP = "203.0.113.4"


def _completed(cmd, payload, code=0, stderr=""):
    return subprocess.CompletedProcess(cmd, code, stdout=json.dumps(payload) if code == 0 else "", stderr=stderr)


# --- request_log -----------------------------------------------------------
def test_request_log_escapes_filters_clamps_pages_and_enriches_rows(monkeypatch):
    """Filters are SQL-escaped, page size is clamped, and each row gets a verdict."""
    from app.services import logdb, request_log

    calls = []
    payload = {
        "total": 2, "last_24h": 1, "unique_sites": 1, "latest_ts": "2026-06-01T00:00:00+00:00",
        "rows": [{
            "id": 1, "ts": "2026-06-01T00:00:00+00:00", "site": "O'Brien", "client_ip": PUBLIC_IP,
            "method": "GET", "uri": "/?q=1", "user_agent": "Chrome", "headers": {"accept": "text/html"},
            "fp_id": "fp-1", "canvas_hash": "cv", "webgl_renderer": "Google SwiftShader",
            "navigator": {"platform": "Win32"}, "automation": {"score": 2, "webdriver": True},
            "behavior": {"synthetic": True}, "tcp_os": None,
        }],
    }

    def fake_run(command, capture_output, text, timeout):
        calls.append(command)
        return _completed(command, payload)

    # The runner lives in the shared logdb module (fast docker-exec path with a
    # compose-exec fallback); the last call is always the one carrying the SQL.
    monkeypatch.setattr(logdb, "_container_id", None)
    monkeypatch.setattr(logdb.subprocess, "run", fake_run)
    data = request_log.fetch_requests(site="O'Brien", method="GET", search="Chrome's",
                                      page=-2, page_size=9999)

    sql = calls[-1][-1]
    assert "a.site = 'O''Brien'" in sql          # single-quote escaped
    assert "a.method = 'GET'" in sql
    assert "chrome''s" in sql                     # lowercased + escaped search term
    assert "LIMIT 500 OFFSET 0" in sql            # page_size clamped to 500, page floored to 1
    # The enriched row carries a cross-layer verdict (SwiftShader -> VM cohort).
    row = data["rows"][0]
    assert row["fp_present"] is True
    assert row["verdict"]["vm_cohort"] is True and row["verdict"]["automation"] is True


def test_request_log_join_is_pageview_aware(monkeypatch):
    """The beacon join first identifies the request's OWN pageview (the nearest
    beacon at/after it, by the shared random pv_id fp.js stamps into the payload)
    and then attaches that pageview's LATEST cumulative unload beacon — so a
    visitor who tabs away, returns, and keeps interacting shows the updated
    biometrics, and a request never inherits the previous page's unload beacon."""
    from app.services import logdb, request_log

    calls = []
    payload = {"total": 0, "last_24h": 0, "unique_sites": 0, "latest_ts": None, "rows": []}
    monkeypatch.setattr(logdb, "_container_id", None)
    monkeypatch.setattr(logdb.subprocess, "run",
                        lambda cmd, **kw: (calls.append(cmd), _completed(cmd, payload))[1])
    request_log.fetch_requests()

    sql = calls[-1][-1]
    # Pageview identification: pv_id comes from the collector's raw payload (no
    # schema change; old rows lack it and fall back), preferring beacons after the
    # request (a pageview's beacons always follow its page GET).
    assert "raw ->> 'pv_id'" in sql
    assert "(bf0.ts >= a.ts) DESC" in sql
    # Same-pageview beacons first; unload preferred; latest-in-pageview wins
    # (cumulative counters make the newest beacon the fullest record).
    assert "COALESCE(bf.raw ->> 'pv_id' = pv.pv_id, FALSE) DESC" in sql
    assert "CASE WHEN bf.raw ->> 'pv_id' = pv.pv_id THEN bf.ts END DESC" in sql
    assert "(bf.phase = 'unload') DESC" in sql


def test_request_log_csv_export_is_well_formed(monkeypatch):
    from app.services import request_log

    rows = [{
        "id": 1, "ts": "2026-06-01T00:00:00+00:00", "site": "site-001", "client_ip": PUBLIC_IP,
        "method": "GET", "uri": "/", "user_agent": "Chrome", "headers": {"accept": "text/html"},
    }]
    csv_text = request_log.requests_to_csv(rows)
    assert csv_text.splitlines()[0] == "id,ts,site,client_ip,method,uri,user_agent,headers"
    parsed = list(csv.DictReader(StringIO(csv_text)))
    assert parsed[0]["client_ip"] == PUBLIC_IP
    assert parsed[0]["headers"] == '{"accept": "text/html"}'  # headers JSON-serialized


def test_request_log_surfaces_actionable_startup_guidance(monkeypatch):
    """When the proxy DB container isn't running, the error tells you how to start it."""
    from app.services import logdb, request_log

    monkeypatch.setattr(logdb, "_container_id", None)
    monkeypatch.setattr(logdb.subprocess, "run",
                        lambda *a, **k: _completed(None, None, code=1, stderr="no container found"))
    try:
        request_log.fetch_filter_options()
    except request_log.RequestLogError as exc:
        assert "make proxy" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected RequestLogError")


def test_total_request_count_is_best_effort(monkeypatch):
    """The landing-stats count returns None (not an exception) when logdb is absent."""
    from app.services import logdb, request_log

    monkeypatch.setattr(logdb, "_container_id", None)
    monkeypatch.setattr(logdb.subprocess, "run",
                        lambda *a, **k: _completed(None, None, code=1, stderr="is not running"))
    assert request_log.total_request_count() is None


def test_landing_stats_uses_live_disguised_devices_not_saved_campaigns(monkeypatch):
    """The overview must agree with /logs when a new disguised device arrives.

    Campaign intelligence is an explicit, persisted analysis snapshot; device
    disguise is a cheap live fingerprint aggregate. Reusing the former made the
    front page stay stale until somebody manually recomputed campaigns.
    """
    from app.services import stats

    monkeypatch.setattr(stats.sites, "list_sites", lambda: [{"site_id": "site-001"}])
    monkeypatch.setattr(stats.sites, "active_proxy_sites", lambda: ["site-001.example"])
    monkeypatch.setattr(stats.querying_service, "available_models", lambda: ["mock/a", "mock/b"])
    monkeypatch.setattr(stats.querying_service, "model_ready", lambda model: model == "mock/a")
    monkeypatch.setattr(stats.querying_service, "runs_summary", lambda: {
        "queries_completed": 3,
        "matches_found": 1,
        "best_score": 0.8,
        "total_runs": 2,
    })
    monkeypatch.setattr(stats.request_log, "total_request_count", lambda: 82)
    monkeypatch.setattr(stats.fingerprint_service, "summary_counts", lambda: {
        "fingerprints": 18,
        "unique_devices": 6,
        "tcp_fingerprints": 237,
    })
    monkeypatch.setattr(stats.fingerprint_service, "disguise_summary", lambda: {
        "total_devices": 6,
        "disguised": 1,
        "roaming": 0,
        "devices": [],
    })
    monkeypatch.setattr(stats.graph_intel, "summary", lambda: {
        "campaigns": 4,
        "disguised": 0,  # deliberately stale campaign snapshot
        "contradiction": 2,
        "generated_at": "2026-07-13T20:15:37+00:00",
    })
    monkeypatch.setattr(stats.selfplay_service, "summary", lambda: None)

    result = stats.landing_stats()

    assert result["llm_models"] == 1
    assert result["disguised"] == 1
    assert result["campaigns"] == 4
    assert result["contradictions"] == 2
    assert result["intel_generated_at"] == "2026-07-13T20:15:37+00:00"


# --- fingerprint_service ---------------------------------------------------
def test_fingerprint_viewer_falls_back_without_tcp_table_and_scores_rows(monkeypatch):
    """When tcp_fingerprints is missing the viewer retries without the TCP join and
    still scores each row through the shared consistency engine."""
    from app.services import fingerprint_service

    seen_sql = []

    def fake_query(sql):
        seen_sql.append(sql)
        if "tcp_fingerprints" in sql:
            raise fingerprint_service.FingerprintError('relation "tcp_fingerprints" does not exist')
        return {
            "total": 1, "unique_devices": 1, "last_24h": 1, "latest_ts": "2026-06-01T00:00:00+00:00",
            "rows": [{
                "site": "site-001", "client_ip": PUBLIC_IP, "user_agent":
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0",
                "fp_id": "fp-1", "canvas_hash": "cv", "webgl_renderer": "Google SwiftShader",
                "navigator": {"platform": "Win32"}, "automation": {"score": 2, "webdriver": True},
                "behavior": {"synthetic": True, "interacted": False}, "tcp_os": None,
            }],
        }

    monkeypatch.setattr(fingerprint_service, "_run_json_query", fake_query)
    data = fingerprint_service.fetch_fingerprints(site="site-001", search="Chrome", page=-1, page_size=1)

    assert "b.site = 'site-001'" in seen_sql[0]      # site filter escaped into WHERE
    assert "tcp_fingerprints" in seen_sql[0]         # first attempt tried the TCP join
    assert "LIMIT 10 OFFSET 0" in seen_sql[1]        # page size clamped to the 10 floor
    verdict = data["rows"][0]["verdict"]
    assert verdict["vm_cohort"] is True and verdict["automation"] is True


def test_fingerprint_summary_degrades_when_db_unavailable(monkeypatch):
    """Best-effort summaries return None/[], never raise, when the store is absent."""
    from app.services import fingerprint_service

    def boom(sql):
        raise fingerprint_service.FingerprintError("not ready")

    monkeypatch.setattr(fingerprint_service, "_run_json_query", boom)
    assert fingerprint_service.fetch_sites() == []
    assert fingerprint_service.summary_counts() == {
        "fingerprints": None, "unique_devices": None, "tcp_fingerprints": None,
    }


def test_disguise_summary_groups_by_device_and_flags_identity_rotation(monkeypatch):
    """disguise_summary flags identity rotation (engine/OS changes) as disguised and
    broad network rotation as roaming, while every legitimate shape — a browser
    auto-update, a second same-engine browser, iOS shells, Docker-gateway
    renumbering, dual-stack, v6 privacy churn, and 2-3-network commuting — stays
    unflagged; it degrades to empty when the DB is absent."""
    from app.services import fingerprint_service

    EDGE149 = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0")
    EDGE150 = EDGE149.replace("149", "150")
    CHROME_WIN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
    FIREFOX_WIN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) "
                   "Gecko/20100101 Firefox/127.0")
    CRIOS = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1")
    SAF_IOS = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
               "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1")

    seen = []
    payload = {"total_devices": 8, "devices": [
        # The operator: Edge auto-updated (149 -> 150) behind renumbering Docker
        # gateways. One identity, zero public networks -> must NOT be flagged.
        {"fp_id": "dev-update", "beacons": 50, "n_ua": 2, "n_ip": 2,
         "uas": [EDGE149, EDGE150], "ips": ["172.18.0.1", "172.19.0.1"], "sites": ["site-001"]},
        # Chrome + Edge on one Windows box share a Blink fp_id -> one identity.
        {"fp_id": "dev-dual", "beacons": 8, "n_ua": 2, "n_ip": 1,
         "uas": [EDGE150, CHROME_WIN], "ips": ["45.10.5.9"], "sites": ["site-001"]},
        # iPhone: Chrome-iOS and Safari are both WebKit shells -> one identity.
        {"fp_id": "dev-ios", "beacons": 5, "n_ua": 2, "n_ip": 1,
         "uas": [CRIOS, SAF_IOS], "ips": ["45.10.5.10"], "sites": ["site-001"]},
        # Dual-stack visitor: one v4 + one v6 of the same access line -> one network.
        {"fp_id": "dev-dualstack", "beacons": 4, "n_ua": 1, "n_ip": 2,
         "uas": [CHROME_WIN], "ips": ["45.10.5.11", "2600:1700:1:2::5"], "sites": ["site-001"]},
        # v6 privacy extensions: new suffix daily inside one /48 -> one network.
        {"fp_id": "dev-v6churn", "beacons": 4, "n_ua": 1, "n_ip": 2,
         "uas": [CHROME_WIN], "ips": ["2600:1700:1:2::5", "2600:1700:1:9:abcd::7"],
         "sites": ["site-001"]},
        # A real spoof: one fp_id claiming two ENGINES (a genuine Firefox would
        # have minted a different fp_id) -> disguised, rows go red.
        {"fp_id": "dev-spoof", "beacons": 9, "n_ua": 2, "n_ip": 1,
         "uas": [CHROME_WIN, FIREFOX_WIN], "ips": ["45.10.5.12"], "sites": ["site-001"]},
        # One identity commuting across three public /24s (home/work/cellular)
        # is ordinary mobility and must remain clean.
        {"fp_id": "dev-commuter", "beacons": 7, "n_ua": 1, "n_ip": 3,
         "uas": [CHROME_WIN], "ips": ["45.10.5.13", "45.10.9.1", "45.10.12.7"],
         "sites": ["site-001"]},
        # Four public /24s crosses the campaign-aligned roaming guard -> rows
        # are surfaced as suspicious, but never malicious on this basis alone.
        {"fp_id": "dev-roam", "beacons": 7, "n_ua": 1, "n_ip": 4,
         "uas": [CHROME_WIN],
         "ips": ["45.10.5.13", "45.10.9.1", "45.10.12.7", "45.10.18.4"],
         "sites": ["site-001"]},
    ]}

    def fake_query(sql):
        seen.append(sql)
        return payload

    monkeypatch.setattr(fingerprint_service, "_run_json_query", fake_query)
    out = fingerprint_service.disguise_summary()
    # SQL still groups per device and only pre-filters cheap candidates.
    assert "GROUP BY fp_id" in seen[0] and "COUNT(DISTINCT user_agent)" in seen[0]
    flagged = {d["fp_id"]: d for d in out["devices"]}
    assert set(flagged) == {"dev-spoof", "dev-roam"}, \
        f"exactly the spoof and the roamer should be flagged, got {sorted(flagged)}"
    assert flagged["dev-spoof"]["basis"] == "identities"
    assert flagged["dev-roam"]["basis"] == "networks"
    assert flagged["dev-roam"]["n_net"] == 4
    assert "dev-commuter" not in flagged
    assert out["disguised"] == 1 and out["roaming"] == 1
    # Identity-based disguise sorts above network roaming.
    assert out["devices"][0]["fp_id"] == "dev-spoof"

    # Degrades to an empty (non-raising) result when the store is unavailable.
    def boom(sql):
        raise fingerprint_service.FingerprintError("not ready")

    monkeypatch.setattr(fingerprint_service, "_run_json_query", boom)
    assert fingerprint_service.disguise_summary()["devices"] == []


def test_severity_of_maps_the_verdict_to_the_three_row_tiers():
    """severity_of collapses a request's verdict into clean/suspicious/malicious for the
    row-color the /logs table now uses."""
    from app.services import fingerprint_service as fs

    # malicious — a device wearing multiple identities, OR a cross-layer contradiction.
    assert fs.severity_of({"disguised": True, "fp_present": True, "verdict": {}})["level"] == "malicious"
    assert fs.severity_of({"fp_present": True, "verdict": {"inconsistent": True, "score": 5}})["level"] == "malicious"
    # suspicious — network roaming under ONE identity (phone / VPN / proxy hop):
    # never malicious on its own.
    roam = fs.severity_of({"net_roaming": True, "fp_present": True, "verdict": {"score": 0}})
    assert roam["level"] == "suspicious" and "networks" in roam["reason"]
    # suspicious — a lesser contradiction (here: a browser UA that never ran JS).
    susp = fs.severity_of({"fp_present": False, "verdict": {"score": 1}})
    assert susp["level"] == "suspicious" and "never ran JS" in susp["reason"]
    # suspicious — a VM/software renderer on a real beacon.
    assert fs.severity_of({"fp_present": True, "verdict": {"score": 2, "vm_cohort": True}})["level"] == "suspicious"
    # clean — a self-consistent beacon, and an honest non-JS client.
    assert fs.severity_of({"fp_present": True, "verdict": {"score": 0}})["level"] == "clean"
    assert fs.severity_of({"fp_present": False, "verdict": {"score": 0}})["level"] == "clean"
