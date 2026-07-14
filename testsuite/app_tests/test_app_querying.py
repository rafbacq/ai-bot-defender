"""LIVE: the LLM detection pipeline against the real honeypot site.

Runs the actual querying pipeline (scrape the live page through the proxy, probe
target models, match against the site's real minted canaries) using the offline
**mock** models — so it needs no API key, per the requirement. The scraper-sim
model regurgitates the site's own canary tokens and must register as a confirmed
leak; the honest model must stay clean.
"""

from __future__ import annotations

import os

import pytest

from .conftest import PROXY_HTTP

pytestmark = pytest.mark.integration


def test_detection_pipeline_catches_a_leak_against_the_real_site(site, proxy):
    from querying.pipeline import QueryRequest, run_query

    req = QueryRequest(
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
    run = run_query(req)

    assert run["status"] == "completed", f"pipeline failed: {run.get('error')}"
    assert run["subject"], "no subject scraped from the live honeypot page"
    assert "db:" in (run["ground_truth_source"] or ""), "ground truth was not read from the site DB"

    by_model = {r["model"]: r for r in run["results"]}
    assert by_model["mock/scraper-sim"]["leaked"] is True, "scraper-sim leak not detected on the live site"
    assert by_model["mock/scraper-sim"]["best_match"]["jaccard_score"] >= 0.3
    assert by_model["mock/honest-llm"]["leaked"] is False, "honest model wrongly flagged as a leak"
