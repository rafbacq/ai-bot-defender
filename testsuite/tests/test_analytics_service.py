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
    assert csv_text.splitlines()[0] == (
        "id,ts,site,client_ip,method,response_status,uri,user_agent,request_id,headers"
    )
    parsed = list(csv.DictReader(StringIO(csv_text)))
    assert parsed[0]["client_ip"] == PUBLIC_IP
    assert parsed[0]["headers"] == '{"accept": "text/html"}'  # headers JSON-serialized


def test_request_log_csv_export_neutralizes_formula_cells():
    """Opening attacker-controlled request data in a spreadsheet stays inert."""
    from app.services import request_log

    dangerous_values = (
        "=1+1",
        " +SUM(1,1)",
        "\t-CMD|' /C calc'!A0",
        "\r@SUM(1+1)",
        "\ufeff=HYPERLINK(\"https://attacker.invalid\")",
    )
    rows = []
    for index, value in enumerate(dangerous_values, start=1):
        rows.append({
            "id": index,
            "ts": "2026-07-16T00:00:00+00:00",
            "site": "site-001",
            "client_ip": "203.0.113.7",
            "method": "GET",
            "response_status": 404,
            "uri": "/ordinary",
            "user_agent": value,
            "request_id": "a" * 32,
            "headers": {"user-agent": "=still JSON, not a cell prefix"},
        })

    parsed = list(csv.DictReader(StringIO(request_log.requests_to_csv(rows))))
    assert [row["user_agent"] for row in parsed] == [
        "'" + value for value in dangerous_values
    ]
    assert all(row["uri"] == "/ordinary" for row in parsed)
    assert all(row["response_status"] == "404" for row in parsed)
    assert all(row["headers"].startswith("{") for row in parsed)


def test_request_log_exposes_status_and_only_trusts_exact_bounded_tcp_matches(monkeypatch):
    from app.services import logdb, request_log

    calls = []
    payload = {"total": 0, "last_24h": 0, "unique_sites": 0, "rows": []}
    monkeypatch.setattr(logdb, "_container_id", None)
    monkeypatch.setattr(
        logdb.subprocess, "run",
        lambda cmd, **kw: (calls.append(cmd), _completed(cmd, payload))[1],
    )

    request_log.fetch_requests()
    sql = calls[-1][-1]
    assert "response_status" in sql and "request_id" in sql
    assert "to_jsonb(a) ->> 'response_status'" in sql
    assert "tf.ts BETWEEN a.ts - INTERVAL '5 minutes'" in sql
    assert "a.ts + INTERVAL '5 seconds'" in sql
    assert "tf.src_port = a.client_port" in sql
    assert "tcp_match_exact" in sql


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
    assert "tt.ts BETWEEN b.ts - INTERVAL '5 minutes'" in seen_sql[0]
    assert "b.ts + INTERVAL '5 seconds'" in seen_sql[0]
    assert "tcp_match_exact" in seen_sql[0]
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


def test_disguise_bases_classifies_page_ids_beyond_summary_limit(monkeypatch):
    """Row flags are resolved for the actual page, not only the top-50 card."""
    from app import main
    from app.services import fingerprint_service

    chrome = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36"
    )
    firefox = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) "
        "Gecko/20100101 Firefox/127.0"
    )
    calls = []

    def fake_query(sql):
        calls.append(sql)
        return {"devices": [{
            "fp_id": "device-051",
            "uas": [chrome, firefox],
            "ips": ["104.28.1.9"],
        }]}

    monkeypatch.setattr(fingerprint_service, "_run_json_query", fake_query)
    assert fingerprint_service.disguise_bases(
        ["device-051", "fp'quoted"], chunk_size=1,
    ) == {"device-051": "identities"}
    assert len(calls) == 2
    assert any("fp''quoted" in sql for sql in calls), "fp_ids must be SQL escaped"

    # The presentation summary contains 50 other devices, so the old code left
    # device 51 green/orange. The page-scoped lookup must still make it red.
    summary = {"devices": [
        {"fp_id": f"device-{index:03d}", "basis": "identities"}
        for index in range(1, 51)
    ]}
    data = {"rows": [{
        "fp_id": "device-051",
        "fp_present": True,
        "verdict": {"score": 0, "inconsistent": False},
        "method": "GET",
        "uri": "/",
    }]}
    monkeypatch.setattr(
        fingerprint_service,
        "disguise_bases",
        lambda fp_ids: {"device-051": "identities"},
    )
    main._annotate_rows(data, summary)
    assert data["rows"][0]["disguised"] is True
    assert data["rows"][0]["severity"]["level"] == "malicious"


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
    susp = fs.severity_of({
        "fp_present": False,
        "verdict": {"score": 1, "browser_no_js": True},
    })
    assert susp["level"] == "suspicious" and "never ran JS" in susp["reason"]
    # suspicious — a VM/software renderer on a real beacon.
    assert fs.severity_of({"fp_present": True, "verdict": {"score": 2, "vm_cohort": True}})["level"] == "suspicious"
    # clean — a self-consistent beacon, and an honest non-JS client.
    assert fs.severity_of({"fp_present": True, "verdict": {"score": 0}})["level"] == "clean"
    assert fs.severity_of({"fp_present": False, "verdict": {"score": 0}})["level"] == "clean"


def test_probe_reason_flags_hostile_targets_but_not_legit_paths():
    """probe_reason judges the request TARGET independent of the client identity."""
    from app.services import fingerprint_service as fs

    # Secrets / config / VCS / IDE / backup exfiltration.
    for uri in (
        "/.env", "/.env.production", "/.envrc", "/.env_copy", "/.env2",
        "/.env~", "/api/shared/.env",
        "/.git/config", "/.git/HEAD", "/.aws/credentials", "/.ssh/id_rsa",
        "/.vscode/sftp.json", "/.DS_Store", "/wp-config.php", "/wp-config.txt",
        "/config.json", "/.netrc", "/.pypirc", "/.dev.vars", "/debug.log",
        "/firebase-debug.log", "/storage/logs/laravel.log", "/backup.zip",
        "/db.sql", "/Dockerfile", "/Procfile", "/serverless.yaml",
        "/functions/.runtimeconfig.json", "/actuator/env", "/server-status",
        "/_profiler",
    ):
        assert fs.probe_reason(uri) is not None, uri

    # Exploit / admin-panel / CMS / device / open-resolver recon.
    for uri in (
        "/wp-includes/wlwmanifest.xml", "/wp-login.php", "/xmlrpc.php?rsd",
        "/login.action", "/geoserver/web/", "/druid/index.html",
        "/ecp/Current/exporttool/microsoft.exchange.ediscovery.export",
        "/___proxy_subdomain_cpanel", "/v2/_catalog", "/cgi-bin/luci",
        "/dns-query?name=1.odns.m.dnsmeasure.top&type=A", "/index.php",
    ):
        assert fs.probe_reason(uri) is not None, uri

    # Path traversal is caught even when it hides under an allowlisted prefix.
    assert fs.probe_reason("/.well-known/../../.env") is not None
    assert fs.probe_reason("/static/../../etc/passwd") is not None

    # Legit honeypot paths must stay clean. Query-specific exploit signatures are
    # inspected, but an ordinary `?name=`/`?v=` never reddens the root; and the
    # compatibility helper only returns reasons for red findings, so a bare
    # unexpected `/query` remains non-malicious here (target_assessment makes it
    # orange in the request table).
    for uri in (
        "/", "/favicon.ico", "/robots.txt", "/js/fp.js", "/__fpbeacon",
        "/css/site.css?v=1",
        "/.well-known/acme-challenge/LbAY57zYhGIXkoeBsFYkMN",
        "/.well-known/security.txt", "/sitemap.xml", "/sitemap-index.xml",
        "/sitemap_index.xml", "/apple-touch-icon.png",
        "/apple-touch-icon-precomposed.png",
        "/?name=1.odns.m.dnsmeasure.top&type=A", "/query", "/query?name=x",
        None, "",
    ):
        assert fs.probe_reason(uri) is None, uri


def test_target_assessment_catches_observed_probe_gaps_without_reddening_safe_queries():
    """Regression fixtures from the live table cover query, VPN, API, debug,
    config, and device reconnaissance that previously remained green."""
    from app.services import fingerprint_service as fs

    malicious = (
        ("GET", "/?rest_route=/wp/v2/users/"),
        ("POST", "/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"),
        ("GET", "/+webvpn+/index.html"),
        ("GET", "/+CSCOE+/logon.html"),
        ("GET", "/remote/login"),
        ("GET", "/dana-na"),
        ("GET", "/sslvpnclient?launchplatform=mac"),
        ("POST", "/global-protect/prelogin.esp?clientos=Windows"),
        ("GET", "/containers/json"),
        ("POST", "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"),
        ("GET", "/developmentserver/metadatauploader"),
        ("POST", "/api/gql"),
        ("GET", "/graphql"),
        ("GET", "/ReportServer"),
        ("GET", "/debug/default/view?panel=config"),
        ("GET", "/@vite/env"),
        ("GET", "/trace.axd"),
        ("GET", "/telescope/requests"),
        ("GET", "/s/x/_/;/META-INF/maven/com.atlassian.jira/pom.properties"),
        ("GET", "/docker-compose.yml"),
        ("GET", "/.bash_history"),
        ("HEAD", "/.npmrc"),
        ("GET", "/config/production.json"),
        ("GET", "/_vti_pvt/service.pwd"),
        ("POST", "/mcp"),
        ("POST", "/onvif/device_service"),
        ("GET", "/portal/redlion"),
        ("GET", "/_cat/indices"),
        ("GET", "/_environment"),
        ("GET", "/webroot/index.php/_environment"),
        ("GET", "/debug/pprof/cmdline"),
        ("GET", "/app/kibana"),
        ("GET", "/api/swagger.json"),
        ("GET", "/swagger-ui.html"),
        ("GET", "/v2/api-docs"),
        ("GET", "/graphiql"),
        ("GET", "/evox/about"),
        ("GET", "/nmaplowercheck1784176961"),
        ("GET", "/administrator/components/com_jce/jce.xml"),
        ("GET", "/administrator/manifests/packages/pkg_jce.xml"),
        ("GET", "/plugins/editors/jce/jce.xml"),
        ("GET", "/wp-content/cache/breeze-extra/"),
        ("TRACE", "/"),
    )
    for method, uri in malicious:
        finding = fs.target_assessment(uri, method)
        assert finding is not None and finding["level"] == "malicious", (method, uri, finding)

    # Generic unknown routes and unsupported-but-not-inherently-hostile methods
    # deserve review without being called certain attacks.
    for method, uri in (
        ("GET", "/admin"),
        ("GET", "/login"),
        ("GET", "/about"),
        ("GET", "/pricing"),
        ("GET", "/signup"),
        ("GET", "/wiki"),
        ("GET", "/api/config"),
        ("GET", "/api/env"),
        ("GET", "/version"),
        ("GET", "/server"),
        ("GET", "/css/support_parent.css"),
        ("GET", "/static/css/app.css?v=123"),
        ("POST", "/"),
        ("POST", "/query"),
    ):
        finding = fs.target_assessment(uri, method)
        assert finding is not None and finding["level"] == "suspicious", (method, uri, finding)

    for method, uri in (
        ("GET", "/"),
        ("GET", "/?name=1.odns.m.dnsmeasure.top&type=A"),
        ("HEAD", "/robots.txt"),
        ("GET", "/apple-touch-icon.png"),
        ("GET", "/sitemap_index.xml"),
        ("GET", "/css/site.css?v=1"),
        ("POST", "/__fpbeacon"),
    ):
        assert fs.target_assessment(uri, method) is None, (method, uri)

    # Decode at most twice so encoded traversal cannot hide under a safe prefix;
    # encoded query/fragment bytes remain path data and cannot hide a secret
    # probe; malformed and very long benign input remains bounded/non-raising.
    assert fs.target_assessment("/static/%252e%252e/.env", "GET")["level"] == "malicious"
    for uri in (
        "/%23/.env", "/%2523/.env", "/%3f/.env", "/%253f/.env",
        "http://honeypot.invalid/%23/.env",
    ):
        assert fs.target_assessment(uri, "GET")["level"] == "malicious", uri
    assert fs.target_assessment("/?next=%23/.env", "GET") is None
    assert fs.target_assessment("/?note=%zz" + "x" * 20_000, "GET") is None


def test_row_verdict_scopes_no_js_to_documents_and_exempts_declared_crawler_os_wrappers():
    """Only the HTML document can emit fp.js; OAI's browser wrapper is not its kernel."""
    from app.services import fingerprint_service as fs

    chrome = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"
    )
    root = fs.verdict_for({
        "client_ip": "104.28.1.9", "user_agent": chrome, "method": "GET", "uri": "/",
    })
    assert root["browser_no_js"] is True
    assert root["score"] == 1 and any("never executed JS" in c for c in root["contradictions"])

    for method, uri in (("GET", "/css/site.css"), ("GET", "/js/fp.js"),
                        ("GET", "/favicon.ico"), ("GET", "/robots.txt"),
                        ("HEAD", "/")):
        verdict = fs.verdict_for({
            "client_ip": "104.28.1.9", "user_agent": chrome, "method": method, "uri": uri,
        })
        assert verdict["browser_no_js"] is False, (method, uri, verdict)
        assert verdict["score"] == 0, (method, uri, verdict)

    oai_ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36; compatible; "
        "OAI-SearchBot/1.3; +https://openai.com/searchbot"
    )
    row = {
        "client_ip": "104.210.140.134", "user_agent": oai_ua,
        "method": "GET", "uri": "/robots.txt", "tcp_os": "Linux",
        "tcp_match_exact": True, "fp_present": False,
    }
    row["verdict"] = fs.verdict_for(row)
    assert row["verdict"]["declared_crawler"] is True
    assert row["verdict"]["inconsistent"] is False
    assert fs.severity_of(row)["level"] == "clean"

    # Declared identity never overrides malicious intent.
    row.update(uri="/.env")
    assert fs.severity_of(row)["level"] == "malicious"


def test_transparent_scanner_user_agents_are_suspicious_automation():
    """Honest tool/scanner UAs should not be green merely because they skip JS."""
    from app.services import fingerprint_service as fs
    from crawler_graph.ingest import known_crawlers

    for ua in (
        "curl/8.12.1", "Mozilla/5.0 zgrab/0.x", "l9scan/2.0",
        "CensysInspect/1.1", "Nuclei - Open-source project",
        "Hello from Palo Alto Networks, Cortex-Xpanse scan",
        "Mozilla/5.0 (compatible; InternetMeasurement/1.0)",
        "RecordedFuture Global Inventory Crawler", "CMS-Checker/1.0",
        "CheckHost (https://check-host.net/)", "Scrapy/2.16.0",
        "Mozilla/5.0 (compatible; FlowIQLabsBot/1.0)",
        "Mozilla/5.0 (compatible; ModatScanner/1.2)",
        "Shodan-Pull/1.0", "Mozilla/5.0 (compatible; Infrawatch/1.0)",
        "Linux Gnu (cow)",
        "Mozilla/5.0 Chrome/137.0 Safari/537.36 +https://forestengine.net/#opt-out",
        "StabilityBot/1.0", "DifferentCrawler/2.0",
    ):
        assert known_crawlers.looks_automated(ua) is True, ua
        row = {
            "client_ip": "104.28.1.9", "user_agent": ua,
            "method": "GET", "uri": "/", "fp_present": False,
        }
        row["verdict"] = fs.verdict_for(row)
        assert row["verdict"]["automation"] is True, (ua, row["verdict"])
        assert row["verdict"]["browser_no_js"] is False, (ua, row["verdict"])
        severity = fs.severity_of(row)
        assert severity["level"] == "suspicious", (ua, severity)
        assert "automation" in severity["reason"]

    # Product-token boundaries avoid ordinary names that merely contain a tool
    # substring; the real scanner token remains detectable.
    for ua in (
        "OpenMap/1.0", "Human NmapleBrowser/1.0", "NotModatScannery/1.0",
        "HumanShodan-Puller/1.0", "FlowIQLabsBotanist/1.0",
    ):
        assert known_crawlers.looks_automated(ua) is False, ua
    assert known_crawlers.looks_automated("Nmap/7.95") is True
    assert known_crawlers.looks_automated("GPTBot/1.4") is False


def test_declared_crawler_names_require_product_boundaries():
    """Impostor substrings cannot inherit the declared-crawler TCP exemption."""
    from app.services import fingerprint_service as fs
    from crawler_graph.ingest import known_crawlers

    for ua in ("DefinitelyNotGPTBot", "myGooglebotImpersonator", "NotClaudeBot"):
        assert known_crawlers.provider_for_ua(ua) is None, ua
        browser_ua = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 Chrome/150.0.0.0 Safari/537.36 " + ua
        )
        verdict = fs.verdict_for({
            "client_ip": "104.28.1.9", "user_agent": browser_ua,
            "method": "GET", "uri": "/robots.txt", "tcp_os": "Linux",
            "tcp_match_exact": True,
        })
        assert verdict["declared_crawler"] is False, (ua, verdict)
        assert verdict["inconsistent"] is True, (ua, verdict)

    for ua, provider in (
        ("GPTBot/1.4", "OpenAI"),
        ("Googlebot-Image/1.0", "Google"),
        ("ClaudeBot/1.0", "Anthropic"),
    ):
        assert known_crawlers.provider_for_ua(ua) == provider


def test_severity_of_marks_secrets_and_exploit_probes_malicious():
    """A hostile request target reddens the row even when the client looks honest.

    The `.env` sweeps and tool-UA scanners this deployment actually sees would
    otherwise rate 'clean' (an honest bot UA that never runs JS is self-consistent),
    so the URI signal is what closes the gap the crawler-graph engine leaves open.
    """
    from app.services import fingerprint_service as fs

    # Fake-Googlebot HEAD /.env: no fingerprint, self-consistent identity -> was clean.
    env_probe = fs.severity_of(
        {"uri": "/.env.production", "fp_present": False, "verdict": {"score": 0}}
    )
    assert env_probe["level"] == "malicious" and "secrets" in env_probe["reason"]

    # Tool-UA scanners hitting framework paths (zgrab/Go-http-client) -> malicious.
    assert fs.severity_of(
        {"uri": "/actuator/health", "fp_present": False, "verdict": {"score": 0}}
    )["level"] == "malicious"
    assert fs.severity_of(
        {"uri": "/wp-includes/wlwmanifest.xml", "fp_present": False, "verdict": {"score": 0}}
    )["level"] == "malicious"

    # A real browser hitting the honeypot page stays green (no false positive).
    assert fs.severity_of(
        {"uri": "/", "fp_present": True, "verdict": {"score": 0}}
    )["level"] == "clean"
    # Fingerprint rows (no `uri` key) are unaffected — the engine still decides.
    assert fs.severity_of(
        {"fp_present": True, "verdict": {"score": 0}}
    )["level"] == "clean"
