"""LIVE: the running FastAPI web application (http://localhost:8000).

Drives the real app over HTTP: every page renders (200), the stats API reflects
real data, the back-compat routes redirect to the merged pages, and the safe form
actions work — the membership demo and a **mock**-model detection run (no API key,
no destructive action: no deploy, no DB reset, no template generation).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_unauthenticated_requests_are_redirected_to_login(app_url):
    import requests

    response = requests.get(app_url + "/logs", allow_redirects=False, timeout=15)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?next=")


def test_stats_api_returns_live_metrics(app_url, app_session):
    data = app_session.get(app_url + "/api/stats", timeout=15).json()
    for key in ("sites_live", "sites_configured", "llm_models", "requests_logged", "query_runs"):
        assert key in data, f"/api/stats missing {key}"
    assert isinstance(data["requests_logged"], int) and data["requests_logged"] >= 0


def test_every_page_renders(app_url, app_session):
    """All primary pages return 200 with rendered HTML (the consolidated layout)."""
    pages = {
        "/": "AI Bot",
        "/sites": "Site",
        "/logs": "Crawler Analytics",
        "/query": "Forensics",
        "/generator": "Template",
    }
    for path, marker in pages.items():
        resp = app_session.get(app_url + path, timeout=20)
        assert resp.status_code == 200, f"GET {path} -> {resp.status_code}"
        assert marker.lower() in resp.text.lower(), f"GET {path} missing expected content {marker!r}"


def test_back_compat_routes_redirect_to_merged_pages(app_url, app_session):
    """The retired standalone pages redirect (not 404) into /logs and /query."""
    for path, dest in [("/fingerprints", "/logs"), ("/intel", "/logs"), ("/provenance", "/query")]:
        resp = app_session.get(app_url + path, allow_redirects=False, timeout=15)
        assert resp.status_code in (301, 302, 307, 308), f"{path} did not redirect ({resp.status_code})"
        assert resp.headers.get("location") == dest, f"{path} -> {resp.headers.get('location')} (want {dest})"


def test_membership_demo_form_runs(app_url, app_session):
    """POST the offline membership demo; it redirects back to a 200 page."""
    resp = app_session.post(app_url + "/provenance/membership-demo", data={"n": "12"},
                            timeout=30, allow_redirects=True)
    assert resp.status_code == 200
    assert resp.url.rstrip("/").endswith("/query") or "/query" in resp.url


def test_local_mock_detection_run_completes_via_the_app(app_url, app_session, site):
    """POST a local detection run with mock models and follow it to its result page."""
    resp = app_session.post(
        app_url + "/query/run",
        data=[("mode", "local"), ("site_id", site["site_id"]),
              ("models", "mock/scraper-sim"), ("models", "mock/honest-llm"),
              ("max_questions", "3"), ("seed", "7")],
        timeout=60, allow_redirects=True,
    )
    assert resp.status_code == 200, f"run page returned {resp.status_code}"
    assert "/query/runs/" in resp.url, f"did not land on a run result page: {resp.url}"
    # The result page shows the detection outcome for the mock models.
    assert "scraper-sim" in resp.text or "Detection" in resp.text or "leak" in resp.text.lower()
