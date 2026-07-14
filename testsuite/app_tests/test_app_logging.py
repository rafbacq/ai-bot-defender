"""LIVE: central request logging through the reverse proxy.

The same simulated burst that hit the honeypot must also land in the proxy's
central ``all_visits`` table via the nginx mirror -> collector path, tagged with
the site's canonical hostname and carrying the User-Agent and the source-port
join key. This verifies the real cross-site logging pipeline end to end.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_all_simulated_requests_reach_the_central_log(simulated_traffic, proxy):
    """Every page view we sent is recorded in all_visits (allowing for the async
    mirror to settle, which the fixture already waited on)."""
    tag = simulated_traffic["tag"]
    n = proxy.count("all_visits", f"user_agent LIKE '%{tag}%'")
    assert n is not None and n >= simulated_traffic["page_views"], \
        f"all_visits has {n} of our {simulated_traffic['page_views']} page views"


def test_logged_requests_carry_canonical_site_ua_and_port(simulated_traffic, proxy, site):
    """Rows are tagged with the canonical site name and keep the UA + client port
    (the 4-tuple key that ties a request to its TLS/TCP fingerprint)."""
    tag = simulated_traffic["tag"]
    data = proxy.query(
        "SELECT json_build_object("
        "'sites', (SELECT COALESCE(json_agg(DISTINCT site), '[]'::json) FROM all_visits "
        f"          WHERE user_agent LIKE '%{tag}%'),"
        "'with_port', (SELECT COUNT(*) FROM all_visits "
        f"             WHERE user_agent LIKE '%{tag}%' AND client_port IS NOT NULL),"
        "'total', (SELECT COUNT(*) FROM all_visits "
        f"          WHERE user_agent LIKE '%{tag}%'));")

    # Even though we addressed the site by its *.localhost alias, the mirror records
    # the canonical hostname (so all_visits.site is never an arbitrary client value).
    assert data["sites"] == [site["hostname"]], \
        f"expected canonical site {site['hostname']!r}, got {data['sites']}"
    assert data["total"] >= simulated_traffic["page_views"]
    assert data["with_port"] == data["total"], "every mirrored request should carry a client port"


def test_declared_crawler_uas_are_present_verbatim(simulated_traffic, proxy):
    """The declared-bot User-Agents we sent are stored intact (so attribution and
    the Crawler Analytics view can recognize them)."""
    tag = simulated_traffic["tag"]
    for token in ("GPTBot", "ClaudeBot", "Googlebot"):
        n = proxy.count("all_visits", f"user_agent LIKE '%{token}%' AND user_agent LIKE '%{tag}%'")
        assert n and n > 0, f"declared crawler {token} not found in all_visits"
