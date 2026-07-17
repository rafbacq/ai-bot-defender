"""Admin monitoring service, routes, alerts, and network-isolation wiring."""

from __future__ import annotations

import json
import re
import time
from urllib.parse import parse_qs, urlsplit

import pytest


@pytest.fixture(autouse=True)
def _clear_monitoring_cache():
    from app.services import monitoring_service as monitoring

    monitoring._CACHE.update(at=0.0, data=None)
    yield
    monitoring._CACHE.update(at=0.0, data=None)


def _vector(value):
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [{"metric": {}, "value": [1784180480.0, str(value)]}],
        },
    }


def _matrix(*values):
    return {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [{
                "metric": {},
                "values": [
                    [1784180400.0 + (index * 60), str(value)]
                    for index, value in enumerate(values)
                ],
            }],
        },
    }


def _named_vector(values):
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {
                    "metric": {"name": name},
                    "value": [1784180480.0, str(value)],
                }
                for name, value in values.items()
            ],
        },
    }


def _labeled_vector(samples):
    return {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {
                    "metric": labels,
                    "value": [1784180480.0, str(value)],
                }
                for labels, value in samples
            ],
        },
    }


def _empty_alerts():
    return {"status": "success", "data": {"alerts": []}}


def test_monitoring_service_parses_pipeline_trends_rate_and_alerts(monkeypatch):
    from app.services import monitoring_service as monitoring

    expected = [
        ("proxy-nginx", "edge", "Reverse proxy"),
        ("proxy-collector-1", "capture", "Visit collector"),
        ("site-001-web-1", "sites", "site-001 web"),
    ]
    monkeypatch.setattr(monitoring, "_expected_containers", lambda: expected)

    instant_expressions = set()
    range_expressions = set()
    fresh = time.time()
    probe_labels = {
        "job": "public-sites",
        "site": "site-001",
        "hostname": "site-001.example",
        "instance": "https://site-001.example/__abd_health",
        "probe_scheme": "https",
    }
    monkeypatch.setattr(monitoring, "_expected_probe_inventory", lambda: [{
        "site": "site-001",
        "scheme": "https",
        "target": probe_labels["instance"],
        "hostname": probe_labels["hostname"],
    }])

    def fake_get(url, **_kwargs):
        parsed = urlsplit(url)
        if parsed.path.endswith("/grafana/api/health"):
            return {"database": "ok", "version": "11.4.0"}
        if parsed.path.endswith("/-/healthy"):
            return "Prometheus Server is Healthy."
        if parsed.path.endswith("/ready"):
            return "ready"
        if parsed.path == "/loki/api/v1/query":
            assert parse_qs(parsed.query)["query"] == [monitoring._RESPONSE_MIX_QUERY]
            return {"status": "success", "data": {"resultType": "vector", "result": [
                {"metric": {"site": "site-001.example", "status": "200"},
                 "value": [1784180480.0, "40"]},
                {"metric": {"site": "site-001.example", "status": "404"},
                 "value": [1784180480.0, "32"]},
            ]}}
        if parsed.path.endswith("/api/v1/query_range"):
            expression = parse_qs(parsed.query)["query"][0]
            range_expressions.add(expression)
            if "node_cpu_seconds_total" in expression:
                return _matrix(10, 12)
            if "MemAvailable" in expression:
                return _matrix(30, 35)
            raise AssertionError(f"unexpected range PromQL: {expression}")
        if parsed.path.endswith("/api/v1/query"):
            expression = parse_qs(parsed.query)["query"][0]
            instant_expressions.add(expression)
            if "container_cpu_usage_seconds_total" in expression:
                return _named_vector({
                    "proxy-nginx": 2.5,
                    "proxy-collector-1": 1.25,
                })
            if "container_memory_working_set_bytes" in expression:
                return _named_vector({
                    "proxy-nginx": 104857600,
                    "proxy-collector-1": 52428800,
                })
            if expression.startswith("max by (name) (container_last_seen"):
                return _named_vector({
                    "proxy-nginx": fresh,
                    "proxy-collector-1": fresh,
                })
            if "node_cpu_seconds_total" in expression:
                return _vector("12.25")
            if "MemAvailable" in expression:
                return _vector("34.5")
            if "node_filesystem_avail_bytes" in expression:
                return _vector("67.75")
            if expression.startswith("count(container_last_seen"):
                return _vector("21")
            if expression == monitoring._PROBE_QUERIES["success"]:
                return _labeled_vector([(probe_labels, 1)])
            if expression == monitoring._PROBE_QUERIES["http_status"]:
                return _labeled_vector([(probe_labels, 204)])
            if expression == monitoring._PROBE_QUERIES["cert_expiry"]:
                return _labeled_vector([(probe_labels, fresh + (20 * 86400))])
            raise AssertionError(f"unexpected instant PromQL: {expression}")
        if parsed.path.endswith("/api/v1/alerts"):
            return {
                "status": "success",
                "data": {"alerts": [
                    {
                        "state": "firing",
                        "labels": {
                            "alertname": "HostOutOfMemory",
                            "severity": "warning",
                        },
                        "annotations": {"summary": "Less than 10% RAM available"},
                        "activeAt": "2026-07-16T05:00:00Z",
                    },
                    {
                        "state": "pending",
                        "labels": {"alertname": "NotFiringYet"},
                        "annotations": {},
                    },
                ]},
            }
        raise AssertionError(f"unexpected monitoring URL: {url}")

    monkeypatch.setattr(monitoring, "_get_json", fake_get)
    result = monitoring.overview()

    assert result["ok"] is True
    assert result["generated_at"] > 0
    assert result["health"] == {
        "grafana": True,
        "prometheus": True,
        "loki": True,
        "alertmanager": True,
        "blackbox": True,
    }
    # Host resources only: traffic volume is a count in the capture panel, not a
    # per-minute rate that reads 0.0 through this traffic's ~89% idle minutes.
    assert result["kpis"] == {
        "host_cpu_percent": 12.25,
        "host_memory_percent": 34.5,
        "root_disk_percent": 67.75,
        "running_containers": 21,
    }
    # Certificate expiry stays beside each site in the probe table, where one
    # shared cert's countdown is read per serving path.
    assert result["probes"][0]["cert_days_remaining"] == pytest.approx(20.0, abs=0.1)
    assert len(instant_expressions) == 10 + len(monitoring._CAPTURE_QUERIES)
    assert range_expressions == {
        monitoring._KPI_QUERIES["host_cpu_percent"],
        monitoring._KPI_QUERIES["host_memory_percent"],
    }
    assert result["series"] == {
        "host_cpu_percent": [[1784180400.0, 10.0], [1784180460.0, 12.0]],
        "host_memory_percent": [[1784180400.0, 30.0], [1784180460.0, 35.0]],
    }
    containers = {row["name"]: row for row in result["containers"]}
    assert containers["proxy-nginx"]["status"] == "up"
    assert containers["proxy-nginx"]["cpu_percent"] == 2.5
    assert containers["proxy-nginx"]["memory_bytes"] == 104857600
    assert containers["site-001-web-1"]["status"] == "down"
    assert containers["site-001-web-1"]["last_seen_age_s"] is None
    pipeline = {stage["key"]: stage for stage in result["pipeline"]}
    assert pipeline["edge"] == {
        "key": "edge", "label": "Edge", "status": "up", "detail": "1/1 up",
    }
    assert pipeline["capture"]["status"] == "up"
    assert pipeline["sites"] == {
        "key": "sites", "label": "Sites", "status": "down", "detail": "0/1 up",
    }
    assert result["alerts"] == [{
        "name": "HostOutOfMemory",
        "severity": "warning",
        "summary": "Less than 10% RAM available",
        "description": "",
        "active_at": "2026-07-16T05:00:00Z",
        "state": "firing",
        "labels": {
            "alertname": "HostOutOfMemory", "severity": "warning",
        },
    }]
    assert result["probes"] == [{
        "site": "site-001",
        "scheme": "https",
        "target": "https://site-001.example/__abd_health",
        "hostname": "site-001.example",
        "status": "up",
        "http_status": 204,
        "cert_expires_at": round(fresh + (20 * 86400), 3),
        "cert_days_remaining": pytest.approx(20.0, abs=0.1),
    }]
    assert result["notifications"] == {
        "mode": "local-only", "external_delivery": False,
    }


def test_monitoring_service_surfaces_missing_expected_probe_series(monkeypatch):
    from app.services import monitoring_service as monitoring

    monkeypatch.setattr(
        monitoring,
        "_prometheus_query",
        lambda _expression: _labeled_vector([]),
    )
    monkeypatch.setattr(monitoring, "_expected_probe_inventory", lambda: [
        {
            "site": "site-002", "scheme": "http",
            "target": "http://site-002.example/", "hostname": "site-002.example",
        },
        {
            "site": "site-002", "scheme": "https",
            "target": "https://site-002.example/", "hostname": "site-002.example",
        },
    ])

    assert monitoring.endpoint_probes() == [
        {
            "site": "site-002", "scheme": "http",
            "target": "http://site-002.example/", "hostname": "site-002.example",
            "status": "missing", "http_status": None,
            "cert_expires_at": None, "cert_days_remaining": None,
        },
        {
            "site": "site-002", "scheme": "https",
            "target": "https://site-002.example/", "hostname": "site-002.example",
            "status": "missing", "http_status": None,
            "cert_expires_at": None, "cert_days_remaining": None,
        },
    ]


def test_monitoring_service_degrades_offline_without_query_timeout_pileup(monkeypatch):
    from app.services import monitoring_service as monitoring

    calls = []

    def offline(url):
        calls.append(url)
        raise OSError("monitoring is offline")

    monkeypatch.setattr(monitoring, "_get_json", offline)
    result = monitoring.overview()

    assert result["ok"] is False
    assert result["generated_at"] > 0
    assert result["health"] == {
        "grafana": False,
        "prometheus": False,
        "loki": False,
        "alertmanager": False,
        "blackbox": False,
    }
    assert result["kpis"] == {
        "host_cpu_percent": None,
        "host_memory_percent": None,
        "root_disk_percent": None,
        "running_containers": None,
    }
    # Offline is not healthy: capture integrity must say it cannot see, never
    # imply that every visit is landing.
    assert result["capture"]["verdict"] == "blind"
    assert result["response_mix"]["available"] is False
    assert result["series"] == {
        "host_cpu_percent": [],
        "host_memory_percent": [],
    }
    assert result["containers"] == []
    assert result["pipeline"] == []
    assert result["probes"] == []
    assert result["alerts"] == []
    assert len(calls) == 5, "failed health must skip every downstream data call"
    assert monitoring._sample_value(_vector("NaN")) is None
    assert monitoring._sample_value({"status": "success", "data": {"result": []}}) is None
    assert monitoring._matrix_points(_matrix(1, "NaN", 3)) == [
        [1784180400.0, 1.0], [1784180520.0, 3.0],
    ]
    assert monitoring._matrix_points({"status": "success", "data": {}}) == []
    assert monitoring._vector_by_name(_named_vector({"ok": 1, "bad": "NaN"})) == {
        "ok": 1.0,
    }
    assert monitoring._labeled_vector(_labeled_vector([
        ({"site": "site-001"}, 1),
        ({"site": "site-bad"}, "NaN"),
    ])) == [({"site": "site-001"}, 1.0)]


def test_loki_down_keeps_prometheus_metrics_and_skips_loki_data(monkeypatch):
    from app.services import monitoring_service as monitoring

    calls = []
    monkeypatch.setattr(monitoring, "_expected_containers", lambda: [])

    def fake_get(url, **_kwargs):
        calls.append(url)
        parsed = urlsplit(url)
        if parsed.path.endswith("/grafana/api/health"):
            return {"database": "ok"}
        if parsed.path.endswith("/-/healthy"):
            return "healthy"
        if parsed.path.endswith("/ready"):
            raise OSError("loki is down")
        if parsed.path.endswith("/api/v1/alerts"):
            return _empty_alerts()
        if parsed.path.endswith("/api/v1/query_range"):
            return _matrix(1, 2)
        if parsed.path.endswith("/api/v1/query"):
            expression = parse_qs(parsed.query)["query"][0]
            if expression in monitoring._CONTAINER_QUERIES.values():
                return _named_vector({})
            return _vector(10)
        raise AssertionError(f"unexpected monitoring URL: {url}")

    monkeypatch.setattr(monitoring, "_get_json", fake_get)
    result = monitoring.overview()

    assert result["ok"] is False
    assert result["kpis"]["host_cpu_percent"] == 10.0
    assert result["kpis"]["running_containers"] == 10
    # Loki is the only source for the response mix, so it degrades alone; the
    # Prometheus-backed panels are untouched.
    assert result["response_mix"]["available"] is False
    assert result["series"]["host_cpu_percent"]
    assert result["series"]["host_memory_percent"]
    assert result["containers"] == []
    assert result["pipeline"] == []
    assert not any("loki/api" in url for url in calls)


def test_prometheus_down_still_returns_loki_request_rate(monkeypatch):
    from app.services import monitoring_service as monitoring

    calls = []

    def fake_get(url, **_kwargs):
        calls.append(url)
        parsed = urlsplit(url)
        if parsed.path.endswith("/grafana/api/health"):
            return {"database": "ok"}
        if parsed.path.endswith("/-/healthy"):
            raise OSError("prometheus is down")
        if parsed.path.endswith("/ready"):
            return "ready"
        if parsed.path == "/loki/api/v1/query":
            return _vector(72)
        if parsed.path == "/loki/api/v1/query_range":
            return _matrix(45, 55)
        raise AssertionError(f"unexpected monitoring URL: {url}")

    monkeypatch.setattr(monitoring, "_get_json", fake_get)
    result = monitoring.overview()

    assert result["ok"] is False
    assert result["kpis"] == {
        "host_cpu_percent": None,
        "host_memory_percent": None,
        "root_disk_percent": None,
        "running_containers": None,
    }
    assert result["capture"]["verdict"] == "blind"
    # Loki still answers, so the access-log view survives a Prometheus outage.
    assert result["response_mix"]["available"] is True
    assert result["series"] == {
        "host_cpu_percent": [],
        "host_memory_percent": [],
    }
    assert result["containers"] == []
    assert result["pipeline"] == []
    assert result["alerts"] == []
    assert any("loki/api" in url for url in calls)
    assert not any(
        urlsplit(url).path in {"/api/v1/query", "/api/v1/query_range", "/api/v1/alerts"}
        for url in calls
    )


def test_monitoring_overview_ttl_cache_coalesces_pollers(monkeypatch):
    from app.services import monitoring_service as monitoring

    calls = []

    def offline(url):
        calls.append(url)
        raise OSError("offline")

    monkeypatch.setattr(monitoring, "_get_json", offline)
    first = monitoring.overview()
    assert len(calls) == 5
    assert monitoring.overview() is first
    assert len(calls) == 5

    monitoring._CACHE["at"] = 0.0
    assert monitoring.overview() is not first
    assert len(calls) == 10
    assert monitoring._CACHE_TTL < 15


def test_expected_containers_derive_from_deployed_site_inventory(monkeypatch):
    from app.services import monitoring_service as monitoring

    monkeypatch.setattr(monitoring.sites, "list_sites", lambda: [
        {
            "site_id": "site-local", "routed": True,
            "deployed": False, "database": {},
        },
        {
            "site_id": "site-external",
            "deployed": True,
            "database": {"host": "db.internal"},
        },
        {
            "site_id": "site-config-only", "routed": False,
            "deployed": True, "database": {},
        },
    ])
    expected = monitoring._expected_containers()
    names = {row[0] for row in expected}

    assert {row[0] for row in monitoring._EXPECTED_INFRA} <= names
    assert "site-local-web-1" in names
    assert "site-local-db-1" in names
    assert "site-external-web-1" in names
    assert "site-external-db-1" not in names
    assert not any(name.startswith("site-config-only-") for name in names)

    monkeypatch.setattr(
        monitoring.sites,
        "list_sites",
        lambda: (_ for _ in ()).throw(OSError("config unavailable")),
    )
    assert monitoring._expected_containers() == list(monitoring._EXPECTED_INFRA)


@pytest.mark.anyio
async def test_admin_monitoring_routes_gate_every_branch(monkeypatch):
    pytest.importorskip("fastapi")
    from starlette.requests import Request
    from starlette.responses import PlainTextResponse
    from app import config, main
    from app.services import auth_service

    def request(path="/", *, method="GET", session=None):
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "https",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 443),
            "session": session if session is not None else {},
            "app": main.app,
            "router": main.app.router,
        }
        return Request(scope)

    async def reached(_request):
        return PlainTextResponse("reached")

    for path in (
        "/admin", "/admin/auth-check", "/admin/monitoring",
        "/admin/monitoring/status",
    ):
        assert (await main.auth_guard(request(path), reached)).body == b"reached"

    assert main.admin_root().status_code == 307
    assert main.admin_root().headers["location"] == "/admin/approve"
    assert main.admin_auth_check(request("/admin/auth-check")).status_code == 401
    admin_session = {"is_admin": True}
    assert main.admin_auth_check(
        request("/admin/auth-check", session=admin_session)
    ).status_code == 204

    logged_out = main.admin_monitoring_page(request("/admin/monitoring"))
    logged_out_html = logged_out.body.decode()
    assert logged_out.status_code == 200
    assert 'name="next" value="/admin/monitoring"' in logged_out_html

    logged_in = main.admin_monitoring_page(
        request("/admin/monitoring", session=admin_session)
    )
    logged_in_html = logged_in.body.decode()
    assert logged_in.status_code == 200
    assert "Live honeypot pipeline health" in logged_in_html
    # Every panel is rendered from this app's own Prometheus/Loki reads. The
    # Grafana d-solo iframe is gone on purpose: /grafana/ is only a route on the
    # admin nginx vhost, so over the documented loopback/SSH-tunnel path the
    # page's only log surface was a 404 box.
    assert "d-solo" not in logged_in_html
    assert 'id="monitor-response-rows"' in logged_in_html
    assert 'data-monitor-capture-badge' in logged_in_html
    assert 'data-monitor-stage="edge"' in logged_in_html
    assert 'id="monitor-container-rows"' in logged_in_html
    assert 'data-monitor-spark="host_cpu_percent"' in logged_in_html
    assert "expected HTTP/HTTPS series are shown explicitly" in logged_in_html
    assert 'aria-current="page">\n        Monitoring' in logged_in_html

    forbidden = main.admin_monitoring_status(request("/admin/monitoring/status"))
    assert forbidden.status_code == 403
    expected = {
        "ok": True,
        "generated_at": 1784180480.0,
        "health": {
            "grafana": True,
            "prometheus": True,
            "loki": True,
            "alertmanager": True,
            "blackbox": True,
        },
        "kpis": {
            "host_cpu_percent": 1.0,
            "host_memory_percent": 2.0,
            "root_disk_percent": 3.0,
            "running_containers": 4,
            "request_rate_per_min": 5.0,
        },
        "series": {
            "host_cpu_percent": [],
            "host_memory_percent": [],
            "request_rate_per_min": [],
        },
        "containers": [],
        "pipeline": [],
        "probes": [],
        "alerts": [],
        "notifications": {
            "mode": "local-only", "external_delivery": False,
        },
    }
    monkeypatch.setattr(main.monitoring_service, "overview", lambda: expected)
    allowed = main.admin_monitoring_status(
        request("/admin/monitoring/status", session=admin_session)
    )
    assert allowed.status_code == 200
    assert json.loads(allowed.body) == expected
    assert "no-store" in allowed.headers["cache-control"]

    monkeypatch.setattr(config, "ADMIN_SECRET", "test-admin-secret")
    auth_service._reset_rate_limits()
    wrong_session = {}
    wrong = main.admin_login(
        request("/admin/login", method="POST", session=wrong_session),
        "wrong",
        "/admin/monitoring",
    )
    assert wrong.status_code == 403
    assert 'name="next" value="/admin/monitoring"' in wrong.body.decode()

    monitor_session = {}
    unlocked = main.admin_login(
        request("/admin/login", method="POST", session=monitor_session),
        "test-admin-secret",
        "/admin/monitoring",
    )
    assert unlocked.status_code == 303
    assert unlocked.headers["location"] == "/admin/monitoring"
    assert monitor_session == {"is_admin": True}

    for unsafe in ("https://evil.example", "//evil.example", "/admin/unknown", ""):
        auth_service._reset_rate_limits()
        session = {}
        response = main.admin_login(
            request("/admin/login", method="POST", session=session),
            "test-admin-secret",
            unsafe,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/admin/approve"


def _service_block(compose: str, service: str) -> str:
    declaration = re.search(
        rf"^  {re.escape(service)}:\n", compose, flags=re.MULTILINE
    )
    assert declaration is not None, f"service {service!r} is missing"
    tail = compose[declaration.end():]
    match = re.search(r"^  [a-zA-Z0-9_-]+:\n", tail, flags=re.MULTILINE)
    return tail[:match.start()] if match else tail


def _location_block(nginx: str, declaration: str) -> str:
    return nginx.split(f"location {declaration} {{", 1)[1].split("}", 1)[0]


def test_monitoring_static_contracts_preserve_auth_alerts_and_isolation(repo_root):
    admin_conf = (repo_root / "proxy" / "admin.d" / "admin.conf").read_text()
    monitoring_compose = (repo_root / "docker-compose.monitoring.yml").read_text()
    app_compose = (repo_root / "docker-compose.app.yml").read_text()
    proxy_compose = (repo_root / "docker-compose.proxy.yml").read_text()
    prometheus = (repo_root / "monitoring" / "prometheus.yml").read_text()
    alerts = (repo_root / "monitoring" / "alerts.yml").read_text()
    blackbox = (repo_root / "monitoring" / "blackbox.yml").read_text()
    alertmanager = (repo_root / "monitoring" / "alertmanager.yml").read_text()
    datasources = (
        repo_root / "monitoring" / "grafana" / "provisioning"
        / "datasources" / "datasources.yml"
    ).read_text()
    server_source = (repo_root / "website" / "server.py").read_text()
    makefile = (repo_root / "Makefile").read_text()
    site_compose = (
        repo_root / "ansible" / "roles" / "configure" / "templates"
        / "docker-compose.yml.j2"
    ).read_text()
    site_conf = (
        repo_root / "ansible" / "roles" / "configure" / "templates"
        / "site.conf.j2"
    ).read_text()
    site_alerts = (
        repo_root / "ansible" / "roles" / "configure" / "templates"
        / "site-alerts.yml.j2"
    ).read_text()
    configure_tasks = (
        repo_root / "ansible" / "roles" / "configure" / "tasks" / "main.yml"
    ).read_text()
    publish_tasks = (
        repo_root / "ansible" / "roles" / "publish" / "tasks" / "main.yml"
    ).read_text()
    configure_handlers = (
        repo_root / "ansible" / "roles" / "configure" / "handlers" / "main.yml"
    ).read_text()
    all_yml = (repo_root / "ansible" / "group_vars" / "all.yml").read_text()
    gitignore = (repo_root / ".gitignore").read_text()
    login = (repo_root / "app" / "templates" / "admin_login.html").read_text()
    monitoring_page = (
        repo_root / "app" / "templates" / "admin_monitoring.html"
    ).read_text()

    assert "map $http_upgrade $connection_upgrade" in admin_conf
    auth_block = _location_block(admin_conf, "= /_gfauth")
    assert "internal;" in auth_block
    assert "proxy_pass_request_body off;" in auth_block
    assert "/admin/auth-check" in auth_block
    for declaration in ("/grafana/", "/grafana/api/live/"):
        block = _location_block(admin_conf, declaration)
        assert "auth_request /_gfauth;" in block
        assert "error_page 401 = @gf_login;" in block
        assert "X-Forwarded-For $remote_addr" in block
        assert "$proxy_add_x_forwarded_for" not in block
        assert "add_header" not in block
    live_block = _location_block(admin_conf, "/grafana/api/live/")
    assert "proxy_http_version 1.1;" in live_block
    assert "Upgrade $http_upgrade" in live_block
    assert "Connection $connection_upgrade" in live_block
    assert "proxy_read_timeout 300s;" in live_block
    assert "mirror /_mirror;" not in admin_conf
    assert "include /etc/nginx/snippets/mirror.conf;" not in admin_conf

    published = re.findall(r'^\s+- "([^"\n]+:\d+:\d+)"$', monitoring_compose, re.MULTILINE)
    assert published and all(binding.startswith("127.0.0.1:") for binding in published)
    assert "proxy_net" not in monitoring_compose
    for service in ("prometheus", "loki", "grafana", "alertmanager"):
        assert "networks: [default, monitoring_bridge]" in _service_block(
            monitoring_compose, service
        )
    assert 'network_mode: "container:proxy-nginx"' in _service_block(
        monitoring_compose, "blackbox"
    )
    for service in ("node-exporter", "cadvisor", "promtail"):
        assert "monitoring_bridge" not in _service_block(monitoring_compose, service)
    assert "ghcr.io/google/cadvisor:v0.60.5" in monitoring_compose
    assert "quay.io/prometheus/blackbox-exporter:v0.28.0" in monitoring_compose
    assert "quay.io/prometheus/alertmanager:v0.32.1" in monitoring_compose
    blackbox_block = _service_block(monitoring_compose, "blackbox")
    assert "ports:" not in blackbox_block
    assert "./monitoring/alerts.d:/etc/prometheus/alerts.d:ro" in monitoring_compose
    assert "./monitoring/targets.d:/etc/prometheus/targets.d:ro" in monitoring_compose
    for setting in (
        "GF_SERVER_SERVE_FROM_SUB_PATH", "GF_SECURITY_ALLOW_EMBEDDING",
        "GF_AUTH_ANONYMOUS_ENABLED", "GF_AUTH_ANONYMOUS_ORG_ROLE: Viewer",
        "GF_SECURITY_COOKIE_SECURE", "GF_SECURITY_COOKIE_SAMESITE: strict",
    ):
        assert setting in monitoring_compose
    assert "GF_SERVER_ROOT_URL" in monitoring_compose
    assert "PROXY_BASE_DOMAIN" in monitoring_compose
    assert "metrics_path: /grafana/metrics" in prometheus
    assert "/etc/prometheus/alerts.d/*.yml" in prometheus
    assert 'targets: ["alertmanager:9093"]' in prometheus
    assert 'job_name: visit-collector' in prometheus
    assert 'targets: ["collector:8000"]' in prometheus
    assert 'targets: ["proxy-nginx:9115"]' in prometheus
    assert 'files: ["/etc/prometheus/targets.d/*.yml"]' in prometheus
    for label in ("__param_target", "__param_hostname", "__param_module"):
        assert label in prometheus
    assert 'probe_success{job="public-sites"} == 0' in alerts
    assert "probe_ssl_earliest_cert_expiry" in alerts
    assert "abd_collector_status_sync_healthy" in alerts
    assert "abd_collector_status_sync_last_success_unixtime_seconds" in alerts
    assert "abd_collector_status_records_missed_total" in alerts
    assert "abd_collector_status_sync_errors_total" in alerts
    assert "abd_collector_status_records_unusable_total" in alerts
    assert (
        'increase(abd_collector_status_records_unusable_total'
        '{job="visit-collector"}[10m]) > 0'
    ) in alerts
    assert "abd_collector_mirror_rows_inserted_total" in alerts
    assert "abd_collector_mirror_insert_errors_total" in alerts
    assert "abd_collector_status_startup_race_correlated_total" in alerts
    assert "abd_collector_status_startup_unresolved_total" in alerts
    assert "insecure_skip_verify: false" in blackbox
    assert "fail_if_not_ssl: true" in blackbox
    assert "valid_status_codes: [204]" in blackbox
    assert "receiver: local-only" in alertmanager
    assert "- name: local-only" in alertmanager
    assert not any(
        token in alertmanager
        for token in ("slack_configs", "email_configs", "webhook_configs")
    )
    assert "type: alertmanager" in datasources
    assert "implementation: prometheus" in datasources

    health_block = site_conf.split(
        "location = /__abd_health {", 1
    )[1].split("\n    }", 1)[0]
    assert "access_log off;" in health_block
    assert "allow 127.0.0.1;" in health_block
    assert "allow ::1;" in health_block
    assert "deny all;" in health_block
    assert "mirror " not in health_block
    assert "proxy_pass http://$upstream:8080$request_uri;" in health_block
    health_handler = server_source.split(
        "@app.route('/__abd_health', methods=['GET'])", 1
    )[1].split("@app.route('/', methods=['GET'])", 1)[0]
    assert 'connection.execute(text("SELECT 1"))' in health_handler
    assert "FROM new_visits LIMIT 0" in health_handler
    assert "FROM new_agents_vars LIMIT 0" in health_handler
    for required_column in (
        "browser_version", "device_family", "timestamp", "view_count",
        "var10", "last_visited", "fp_id",
    ):
        assert required_column in health_handler
    assert "validate_runtime_dependencies(" in health_handler
    assert "genmode=GENMODE" in health_handler
    assert "required_assets=(ACTIVE_FP_SCRIPT,)" in health_handler
    assert "update_page(" not in health_handler

    assert 'container_last_seen{name="site-001-web-1"}' not in alerts
    assert 'container_last_seen{name="proxy-nginx"}' in alerts
    assert 'absent(container_last_seen{name="{{ site_id }}-web-1"})' in site_alerts
    assert 'absent(container_last_seen{name="{{ site_id }}-db-1"})' in site_alerts
    assert site_alerts.count("alert: HoneypotSiteProbeMissing") == 2
    assert 'probe_scheme="http"' in site_alerts
    assert 'probe_scheme="https"' in site_alerts
    assert site_alerts.count(
        'hostname="{{ proxy.server_name | default(site_id ~ \'.\' ~ proxy.base_domain) }}"'
    ) == 2
    assert 'instance="http://{{ proxy.server_name' in site_alerts
    assert 'instance="https://{{ proxy.server_name' in site_alerts
    assert "database.host is not defined" in site_alerts
    assert "site-alerts.yml.j2" not in configure_tasks
    assert "site-alerts.yml.j2" in publish_tasks
    assert "notify: Reload prometheus rules" not in publish_tasks
    assert "Inspect Prometheus before applying published rules" in publish_tasks
    assert "docker kill --signal=HUP" in publish_tasks
    assert "register: published_prometheus" in publish_tasks
    prometheus_publish_reload = publish_tasks.split(
        "- name: Inspect Prometheus before applying published rules", 1
    )[1].split("# The union certificate", 1)[0]
    assert "failed_when: false" not in prometheus_publish_reload
    assert "docker kill --signal=HUP" in configure_handlers
    assert "failed_when: false" not in configure_handlers
    assert "rules_dir: \"{{ project_root }}/monitoring/alerts.d\"" in all_yml
    assert "monitoring/alerts.d/*.yml" in gitignore

    app_block = _service_block(app_compose, "app")
    trainer_block = _service_block(app_compose, "trainer")
    assert "networks: [default, proxy_net, monitoring_bridge]" in app_block
    for setting in (
        "PROMETHEUS_URL", "GRAFANA_PUBLIC_PATH", "ALERTMANAGER_URL",
        "BLACKBOX_URL", "ALERT_DELIVERY_MODE",
    ):
        assert setting in app_block
    assert "monitoring_bridge" not in trainer_block
    assert "networks: [default, proxy_net, monitoring_bridge]" in _service_block(
        proxy_compose, "nginx"
    )
    collector_block = _service_block(proxy_compose, "collector")
    assert "networks: [default, monitoring_bridge]" in collector_block
    assert "ports:" not in collector_block
    assert "monitoring_bridge" not in site_compose

    assert "ensure-monitoring-net:" in makefile
    assert "monitoring:" in makefile
    assert "monitoring-down:" in makefile
    assert "monitoring-logs:" in makefile
    assert 'name="next"' in login
    assert "fetch('/admin/monitoring/status'" in monitoring_page
    # No embedded Grafana panel: it only resolves through the admin nginx vhost,
    # so it 404'd over the loopback/SSH-tunnel path this app is documented to be
    # reached on. Logs are rendered natively instead; Grafana stays a link.
    assert "d-solo" not in monitoring_page
    assert "monitor-frame" not in monitoring_page
    assert 'id="monitor-response-rows"' in monitoring_page
    assert "renderResponses" in monitoring_page
    assert "renderCapture" in monitoring_page
    assert 'data-monitor-capture="{{ key }}"' in monitoring_page
    assert "('visits_lost', 'Visits lost'" in monitoring_page
    # The corpus tile is the real log's row count, never the collector's
    # process-local counter (which resets on restart and read 37 vs 3,043).
    assert "('requests_captured', 'Requests captured'" in monitoring_page
    # Certificate expiry belongs beside each serving path, not in a lone tile.
    assert "<th>Certificate</th>" in monitoring_page
    assert "probe.cert_days_remaining !== null" in monitoring_page
    # A per-minute traffic rate is gone: this traffic is ~89% idle minutes, so
    # the tile read 0.0 nearly always and spiked meaninglessly during bursts.
    assert "request_rate_per_min" not in monitoring_page
    assert "Honeypot requests" not in monitoring_page
    assert 'data-monitor-stage="{{ key }}"' in monitoring_page
    assert 'id="monitor-container-rows"' in monitoring_page
    assert 'id="monitor-probe-rows"' in monitoring_page
    assert "do not prove that an off-host client" in monitoring_page
    assert "Alert delivery: local only" in monitoring_page
    assert "renderProbes" in monitoring_page
    assert 'data-monitor-spark="{{ key }}"' in monitoring_page
    assert "monitor-frame--dashboard" not in monitoring_page
    assert "kiosk&refresh=30s" not in monitoring_page


def test_collector_starvation_alert_uses_reset_aware_deficit_and_narrow_credit(
    repo_root,
):
    """Only bounded startup-race matches may offset missing live log records."""
    alerts = (repo_root / "monitoring" / "alerts.yml").read_text(encoding="utf-8")
    starvation_rule = alerts.split(
        "- alert: CollectorStatusRecordStarvation", 1
    )[1].split("- alert:", 1)[0]
    assert "abd_collector_status_records_seen_total" in starvation_rule
    assert "abd_collector_status_startup_race_correlated_total" in starvation_rule
    assert (
        "abd_collector_status_records_correlated_total" not in starvation_rule
    ), "general correlations must not hide missing live status records"
    for metric in (
        "abd_collector_mirror_rows_inserted_total",
        "abd_collector_status_records_seen_total",
        "abd_collector_status_startup_race_correlated_total",
    ):
        assert f'increase({metric}{{job="visit-collector"}}[10m])' in starvation_rule
    assert "delta(" not in starvation_rule, "counter-reset-aware increase() is required"
    assert ">" in starvation_rule

    # These values model increase() output, including a range containing a
    # process reset: one startup match accounts for one insert, cannot hide a
    # larger deficit, and normal live records account for their own inserts.
    def starved(inserted, live_seen, startup_matched):
        return inserted > live_seen + startup_matched

    assert not starved(1, 0, 1)
    assert starved(5, 0, 1)
    assert not starved(5, 5, 0)

    misses_rule = alerts.split(
        "- alert: CollectorStatusCorrelationMisses", 1
    )[1].split("- alert:", 1)[0]
    assert "abd_collector_status_records_missed_total" in misses_rule
    assert "abd_collector_status_startup_unresolved_total" in misses_rule


# --- Capture integrity: is the honeypot actually recording anything? --------
def _capture_get(values):
    """A fake _get_json answering only the collector queries, from ``values``."""
    from app.services import monitoring_service as monitoring

    by_expression = {
        monitoring._CAPTURE_QUERIES[name]: value
        for name, value in values.items()
    }

    def fake_get(url, **_kwargs):
        parsed = urlsplit(url)
        if parsed.path.endswith("/api/v1/query"):
            expression = parse_qs(parsed.query)["query"][0]
            if expression in by_expression:
                return _vector(by_expression[expression])
        raise AssertionError(f"unexpected capture URL: {url}")

    return fake_get


def _healthy_capture_values():
    return {
        "visits_lost": 0, "status_missed": 0, "status_pending": 0,
        "sync_errors": 0, "sync_healthy": 1, "sync_thread_up": 1,
        "access_log_present": 1, "sync_last_success": time.time() - 5,
        "recent_visits_lost": 0, "recent_status_missed": 0,
    }


def _corpus(monkeypatch, **overrides):
    """Stub the central-log read. The offline suite must never touch Docker."""
    from app.services import monitoring_service as monitoring

    data = {
        "total": 3043, "last_24h": 2079, "newest": time.time() - 90,
        "hourly": [[time.time() - 3600, 12], [time.time(), 30]],
        **overrides,
    }
    monkeypatch.setattr(monitoring.logdb, "run_psql_json", lambda sql, **kw: data)
    return data


def test_capture_corpus_reports_the_real_log_not_a_process_counter(monkeypatch):
    """The corpus comes from all_visits, because the collector cannot know it.

    ``abd_collector_mirror_rows_inserted_total`` is process-local and resets on
    every collector restart: it read 37 on the live instance while all_visits
    actually held 3,043 rows. Presenting that as the research corpus was simply
    wrong, which is why the panel reads the log itself.
    """
    from app.services import monitoring_service as monitoring

    _corpus(monkeypatch)
    corpus = monitoring.capture_corpus()

    assert corpus["total"] == 3043
    assert corpus["last_24h"] == 2079
    assert 80 < corpus["newest_age_s"] < 120
    assert len(corpus["hourly"]) == 2
    # The counter the panel must never use for this is not even queried here.
    assert "visits_logged" not in monitoring._CAPTURE_QUERIES


def test_capture_corpus_unreadable_log_is_unknown_not_zero(monkeypatch):
    """"No data" and "we cannot see the data" are different facts."""
    from app.services import monitoring_service as monitoring

    def boom(sql, **kw):
        raise monitoring.logdb.LogDBError("logdb is not running")

    monkeypatch.setattr(monitoring.logdb, "run_psql_json", boom)
    corpus = monitoring.capture_corpus()

    assert corpus["total"] is None and corpus["last_24h"] is None
    assert corpus["newest"] is None and corpus["hourly"] == []


def test_capture_integrity_reports_healthy_capture(monkeypatch):
    """All counters clean and the sync fresh: every mirrored visit landed."""
    from app.services import monitoring_service as monitoring

    _corpus(monkeypatch)
    monkeypatch.setattr(
        monitoring, "_get_json", _capture_get(_healthy_capture_values()),
    )
    capture = monitoring.capture_integrity()

    assert capture["verdict"] == "healthy"
    assert capture["reasons"] == []
    assert capture["visits_lost"] == 0
    # Corpus facts ride along with the verdict, from the log itself.
    assert capture["requests_captured"] == 3043
    assert capture["last_24h"] == 2079
    assert capture["sync_age_s"] < 30


@pytest.mark.parametrize(
    "override, verdict, reason_fragment",
    [
        # A dropped visit is research data that no longer exists anywhere: the
        # collector is fire-and-forget and swallows the database error, so this
        # counter is the only trace it ever happened.
        ({"visits_lost": 3, "recent_visits_lost": 3}, "failing",
         "3 visit(s) failed to reach"),
        ({"status_missed": 2, "recent_status_missed": 2}, "failing",
         "2 final status(es) were dropped"),
        ({"access_log_present": 0}, "failing", "access log is unreadable"),
        ({"sync_thread_up": 0}, "degraded", "sync thread is not running"),
        ({"sync_healthy": 0}, "degraded", "sync poll failed"),
        ({"sync_last_success": time.time() - 3600}, "degraded",
         "no successful sync poll"),
    ],
)
def test_capture_integrity_names_each_way_capture_breaks(
    monkeypatch, override, verdict, reason_fragment,
):
    """Each failure mode is stated in operator terms, not left to an alert."""
    from app.services import monitoring_service as monitoring

    _corpus(monkeypatch)
    values = {**_healthy_capture_values(), **override}
    monkeypatch.setattr(monitoring, "_get_json", _capture_get(values))
    capture = monitoring.capture_integrity()

    assert capture["verdict"] == verdict
    assert any(reason_fragment in reason for reason in capture["reasons"]), (
        f"{reason_fragment!r} not in {capture['reasons']}"
    )
    assert reason_fragment in capture["headline"]


def test_capture_integrity_is_blind_rather_than_healthy_when_silent(monkeypatch):
    """A collector reporting nothing must never render as 'everything landed'.

    This is the whole point of the panel: the worst outage this system can have
    is every container green while nothing reaches the central log.
    """
    from app.services import monitoring_service as monitoring

    _corpus(monkeypatch)

    def no_data(url, **_kwargs):
        return {"status": "success", "data": {"resultType": "vector", "result": []}}

    monkeypatch.setattr(monitoring, "_get_json", no_data)
    capture = monitoring.capture_integrity()

    assert capture["verdict"] == "blind"
    assert capture["visits_lost"] is None
    assert "not reporting" in capture["headline"]


def test_capture_verdict_tracks_now_while_totals_remember_the_incident(monkeypatch):
    """Loss that stopped must read as 'lost earlier', never as still failing.

    The collector's counters are cumulative, so driving the badge off them would
    pin it red until the collector restarted — the alarm fatigue that teaches an
    operator to ignore the page. The windowed reads mirror the
    CollectorMirrorInsertFailures rule, so page and pager cannot disagree.
    """
    from app.services import monitoring_service as monitoring

    _corpus(monkeypatch)
    healed = {
        **_healthy_capture_values(),
        "visits_lost": 9, "recent_visits_lost": 0,   # happened, then stopped
    }
    monkeypatch.setattr(monitoring, "_get_json", _capture_get(healed))
    capture = monitoring.capture_integrity()

    assert capture["verdict"] == "healed"
    assert capture["reasons"] == []          # nothing is wrong right now
    assert capture["visits_lost"] == 9       # but the record has a hole
    assert "9 visit(s)" in capture["headline"]
    assert "cannot be recovered" in capture["headline"]

    # Still losing: the verdict escalates and names the live failure.
    ongoing = {**healed, "recent_visits_lost": 4}
    monkeypatch.setattr(monitoring, "_get_json", _capture_get(ongoing))
    live = monitoring.capture_integrity()
    assert live["verdict"] == "failing"
    assert "4 visit(s) failed to reach" in live["headline"]


# --- Response mix: the one thing only the access log knows -------------------
def _mix_get(series):
    """A fake _get_json answering the LogQL response-mix query."""
    def fake_get(url, **_kwargs):
        assert "/loki/api/v1/query" in url
        return {"status": "success", "data": {"resultType": "vector", "result": [
            {"metric": {"site": site, "status": status},
             "value": [1784180480.0, str(count)]}
            for site, status, count in series
        ]}}
    return fake_get


def test_response_mix_buckets_by_what_an_operator_does_about_it(monkeypatch):
    from app.services import monitoring_service as monitoring

    monkeypatch.setattr(monitoring, "_loki_metric_query",
                        lambda expr, **kw: _mix_get([
                            ("site-001.example", "200", 105),
                            ("site-001.example", "304", 6),
                            ("site-001.example", "404", 403),
                            ("site-001.example", "444", 2),
                            ("site-001.example", "499", 4),
                            ("site-002.example", "200", 20),
                            ("site-002.example", "500", 3),
                            ("bogus.example", "444", 5),
                        ])("http://loki/loki/api/v1/query"))
    mix = monitoring.response_mix()

    assert mix["available"] is True
    by_host = {row["host"]: row for row in mix["hosts"]}
    # 2xx/3xx served a page; 404 is probing; 444/499 are refusals; 5xx is broken.
    assert by_host["site-001.example"] == {
        "host": "site-001.example", "total": 520, "served": 111,
        "not_found": 403, "refused": 6, "errors": 0,
    }
    assert by_host["bogus.example"]["refused"] == 5
    assert mix["totals"] == {
        "served": 131, "not_found": 403, "refused": 11, "errors": 3,
        "total": 548, "hosts": 3,
    }
    # The broken host is listed first even though it is the quieter one: the
    # reason to open this panel is to find what is failing.
    assert mix["hosts"][0]["host"] == "site-002.example"
    assert mix["hosts"][0]["errors"] == 3


def test_response_mix_is_an_aggregate_not_a_copy_of_the_request_log(monkeypatch):
    """Loki earns its place here by answering what no other source can.

    Crawler Analytics already lists request rows (with fingerprints, verdicts and
    export), so re-printing them would be a strictly worse copy. nginx has no
    metrics exporter, the blackbox probe only hits a synthetic health endpoint,
    and all_visits never sees catch-all-dropped traffic — so what every host
    actually *returned* exists nowhere else.
    """
    from app.services import monitoring_service as monitoring

    expression = monitoring._RESPONSE_MIX_QUERY
    assert expression.startswith("sum by (site, status)")
    assert "count_over_time" in expression and "[24h]" in expression
    # Aggregated server-side: an unwrapped per-request read trips Loki's
    # 500-series limit outright.
    assert "unwrap" not in expression
    # This console's own traffic is never counted as research traffic.
    assert 'filename!="/var/log/nginx-proxy/admin.access.log"' in expression


def test_response_mix_degrades_without_loki(monkeypatch):
    from app.services import monitoring_service as monitoring

    def boom(expression, **kw):
        raise RuntimeError("loki is down")

    monkeypatch.setattr(monitoring, "_loki_metric_query", boom)
    mix = monitoring.response_mix()
    assert mix == {"hosts": [], "totals": {}, "hours": 24, "available": False}

    # A successful query with no lines is "no traffic", not "cannot read".
    monkeypatch.setattr(
        monitoring, "_loki_metric_query",
        lambda expression, **kw: {"status": "success", "data": {"result": []}},
    )
    quiet = monitoring.response_mix()
    assert quiet["available"] is True and quiet["hosts"] == []
