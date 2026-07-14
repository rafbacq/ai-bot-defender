"""LIVE: training-data provenance against the real site (mock models / backend).

Two checks, both API-key-free:
  * the membership-inference demo (mock backend) returns a calibrated "member"
    verdict for served watermarks, and
  * a real provenance run against the deployed site — scraping the live page,
    reading the per-visitor crawl times from ``new_visits``, and probing the mock
    models — completes and reports the scraper-sim leak.
"""

from __future__ import annotations

import os

import pytest

from .conftest import PROXY_HTTP

pytestmark = pytest.mark.integration


def test_membership_demo_reports_member(app_url):
    """The offline membership demo runs end to end (mock backend)."""
    from app.services import provenance_service

    result = provenance_service.membership_demo(n=16, seed=4)
    assert result["backend"] == "mock"
    assert result["is_member"] is True
    assert result["auc"] > 0.9


def test_provenance_run_against_real_site_completes_and_reports_leak(site, proxy):
    from querying import provenance

    run = provenance.run_provenance(
        target_url=PROXY_HTTP + "/",
        host_header=site["local_hostname"],
        verify_tls=False,
        site_id=site["site_id"],
        db_name=site["db_name"],
        db_user=site["database"]["user"],
        project_root=os.environ["PROJECT_ROOT"],
        models=["mock/scraper-sim", "mock/honest-llm"],
        max_questions=3, seed=7, persist=False,
    )

    assert run["status"] == "completed", f"provenance run failed: {run.get('error')}"
    assert run["subject"], "no subject scraped"
    leak = run["leak_by_model"]["mock/scraper-sim"]
    assert leak.get("n_leaked", 0) >= 1, "scraper-sim did not leak the live site's canaries"
    # The crawl/mint times come from the site's own new_visits log.
    assert isinstance(run.get("crawlers"), list)
