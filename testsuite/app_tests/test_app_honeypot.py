"""LIVE: honeypot canary assignment on the real deployed site.

Floods the running honeypot (through the proxy) with a diverse bot fleet, then
reads the site's own ``new_visits`` / ``new_agents_vars`` tables to prove the real
``server.py`` logic: every request is logged with the visitor's identity, each
distinct visitor gets a stable, unique canary set, repeat visits reuse it and bump
the view count, and generation is on (no "Null" tokens).
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.integration


def _our_agent_rows(site, tag):
    """The site's minted canary rows (new_agents_vars) for our tagged visitors."""
    from querying.ground_truth import load_site_rows
    rows = load_site_rows(os.environ["PROJECT_ROOT"], site["site_id"],
                          site["db_name"], site["database"]["user"])
    return [r for r in rows if tag in (r.get("user_agent") or "")]


def test_every_request_is_logged_with_identity(simulated_traffic, site, site_db):
    """Each simulated page view becomes a ``new_visits`` row carrying the visitor's
    parsed identity (browser family, etc.)."""
    tag = simulated_traffic["tag"]
    n_visits = site_db.count("new_visits", f"user_agent LIKE '%{tag}%'")
    assert n_visits == simulated_traffic["page_views"], \
        f"new_visits has {n_visits} of our {simulated_traffic['page_views']} page views"

    # The Windows-Chrome visitor is identified down to the browser + OS family
    # (the real UA parser ran inside server.py for every visit).
    clean_ua = simulated_traffic["clean_ua"]
    data = site_db.query(
        "SELECT json_build_object('rows', COALESCE(json_agg(json_build_object("
        "'browser', browser_family, 'os', os_family)), '[]'::json)) "
        f"FROM new_visits WHERE user_agent = '{clean_ua}';")
    chrome = data["rows"]
    assert chrome, "the Windows-Chrome visitor was not logged"
    assert all(r["browser"] == "Chrome" for r in chrome)
    assert all(r["os"] == "Windows" for r in chrome)


def test_canaries_are_unique_per_visitor_and_generation_is_on(simulated_traffic, site):
    """Each distinct (UA) visitor minted exactly one canary row with a full,
    non-"Null" token set, and every visitor's set is distinct."""
    rows = _our_agent_rows(site, simulated_traffic["tag"])
    assert len(rows) == simulated_traffic["n_uas"], \
        f"{len(rows)} canary rows minted for our {simulated_traffic['n_uas']} distinct visitors"

    var_keys = [f"var{i}" for i in range(1, 11)]
    sets = []
    for row in rows:
        values = [row.get(k) for k in var_keys]
        assert all(v and v != "Null" for v in values), f"a visitor got Null canaries: {row.get('user_agent')}"
        sets.append(tuple(values))
    assert len(set(sets)) == len(sets), "two visitors received the same canary set"


def test_repeat_visits_reuse_the_same_canary_set_and_bump_view_count(simulated_traffic, site):
    """A visitor seen N times keeps ONE row whose view_count == N (stability)."""
    rows = _our_agent_rows(site, simulated_traffic["tag"])
    by_ua = {r["user_agent"]: r for r in rows}
    expected = {info["ua"]: info["views"] for info in simulated_traffic["labels"].values()}

    for ua, views in expected.items():
        if views <= 0:
            continue
        assert ua in by_ua, f"no canary row for visitor {ua[:50]!r}"
        assert int(by_ua[ua]["view_count"]) == views, \
            f"view_count {by_ua[ua]['view_count']} != {views} visits for {ua[:50]!r}"
