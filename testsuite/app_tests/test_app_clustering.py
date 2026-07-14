"""LIVE: crawler-graph clustering over the real central log.

Runs the actual ``crawler_graph`` pipeline against the live ``logdb`` (the same
code the /logs "Recompute" action calls) after the simulated burst, and checks it
ingests the real traffic and attributes the declared-crawler User-Agents we sent
to the right providers.

Scope note: all host-originated traffic shares one source IP (the Docker host),
so this verifies the live ingest -> enrich -> graph -> campaign attribution path
on real data; the *multi-IP* disguise / proxy-rotation clustering scenarios are
covered exhaustively by the offline suite (``run_tests.py``), which can vary the
source IP/ASN that the anti-spoof proxy otherwise pins to the real client.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_live_pipeline_ingests_traffic_and_attributes_declared_crawlers(simulated_traffic, proxy):
    pytest.importorskip("networkx")
    from crawler_graph import pipeline

    # resolve_asn=False keeps it offline (no RDAP); write=False leaves the app's
    # persisted campaigns.json untouched — read-only against the live log.
    result = pipeline.run_intel(resolve_asn=False, use_gnn=False, write=False, render=False)

    meta, findings, campaigns = result["meta"], result["findings"], result["campaigns"]
    assert meta["n_visits"] >= simulated_traffic["page_views"], "pipeline saw fewer visits than we sent"
    assert findings["n_campaigns"] >= 1, "no campaigns formed from live traffic"

    # Every declared crawler we simulated should be recognized somewhere in the
    # attribution (the shared-IP endpoint carries all of their provider labels).
    attributed = set()
    for camp in campaigns:
        attributed.update(camp.get("declared_providers") or [])
    ours = set(simulated_traffic["providers"])
    assert ours & attributed, (
        f"none of our declared providers {sorted(ours)} were attributed; got {sorted(attributed)}")
    # We sent five distinct declared crawlers; expect most to be recognized.
    assert len(ours & attributed) >= 3, f"only {sorted(ours & attributed)} attributed of {sorted(ours)}"
