"""LIVE: populate the campaigns graph and render it interactively.

A single host can't put many source IPs on the wire (the anti-spoof proxy pins
every request to the Docker gateway), so this seeds the live ``logdb`` with a
realistic multi-IP crawler population, runs the REAL pipeline + renderer, and
checks the app's campaigns view becomes richly populated with many distinct,
hover-able clusters — both in the app (``/intel/graph.html``) and as a standalone
report (``testsuite/reports/campaigns_graph.html``).

The seeded rows are clearly marked (``AIBDSEED``) and removable with
``python testsuite/run_app_tests.py --clean-seed``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from . import seed

pytestmark = pytest.mark.integration

REPORT_PATH = Path(seed.REPO_ROOT) / "testsuite" / "reports" / "campaigns_graph.html"


@pytest.fixture(scope="session")
def seeded_graph(site, proxy):
    """Seed the live log, recompute the real campaigns, and render both graphs."""
    bots = int(os.environ.get("BOT_DEFENDER_APP_BOTS", "40"))
    scale = max(3, bots // 14)

    visits, handshakes, browser_fps, tcp_fps, labels = seed.build_population(scale=scale)
    seed.seed_asn_cache(visits)
    counts = seed.seed_logdb(visits, handshakes, browser_fps, tcp_fps, site["hostname"])

    # Standalone interactive report (full fidelity, straight from the population).
    sv, sh, sb, st, _ = seed.build_population(scale=scale)
    std_path, std_camps = seed.render_standalone(sv, sh, sb, st, REPORT_PATH)

    # The real recompute the app reads (writes campaigns.json + the interactive HTML).
    result = seed.recompute_live()
    return {"counts": counts, "labels": labels, "result": result,
            "standalone_path": std_path, "standalone_campaigns": std_camps}


def _distinct_hues(text):
    return {h for h in re.findall(r"hsl\((\d+)", text)}


def test_seeding_produces_many_distinct_campaigns(seeded_graph):
    """The seeded population forms a richly-populated campaign graph (not 1-2 blobs)."""
    findings = seeded_graph["result"]["findings"]
    assert findings["n_campaigns"] >= 6, f"only {findings['n_campaigns']} campaigns formed"
    assert findings["n_disguised"] >= 1, "the disguised stealth fleet was not flagged"
    assert findings["n_vm_cohort"] >= 1, "the VM cohort was not flagged"
    meta = seeded_graph["result"]["meta"]
    assert meta["browser_fingerprints_present"] and meta["tcp_fingerprints_present"]


def test_persisted_campaigns_json_is_populated(seeded_graph):
    """The campaigns.json the app's /logs page reads now holds the many clusters."""
    from app.services import graph_intel
    report = graph_intel.load_report()
    assert report is not None
    assert report["findings"]["n_campaigns"] >= 6


def test_interactive_graph_has_distinct_colors_and_hover(seeded_graph):
    """Both the app's and the standalone interactive graphs use many distinct
    colours (not blue shades) and carry per-cluster hover rundowns."""
    from crawler_graph import config as cg_config

    for path in (cg_config.GRAPH_VIZ_HTML, REPORT_PATH):
        assert Path(path).exists(), f"interactive graph not written: {path}"
        text = Path(path).read_text(encoding="utf-8")
        hues = _distinct_hues(text)
        assert len(hues) >= 6, f"only {len(hues)} distinct hues in {path}"
        # Spread across the spectrum, not a band of blues (blue ≈ hue 200–250).
        assert any(int(h) < 180 or int(h) > 280 for h in hues), "colours look blue-only"
        assert "RUN[cid]" in text and "mousemove" in text, "no hover rundown wiring"
        assert 'class="lg"' in text, "no clickable campaign legend"


def test_app_serves_the_interactive_graph(seeded_graph, app_url, app_session):
    """The running app serves the interactive graph and embeds it on /logs."""
    graph = app_session.get(app_url + "/intel/graph.html", timeout=20)
    assert graph.status_code == 200, f"/intel/graph.html -> {graph.status_code} (restart `make app`?)"
    assert "text/html" in graph.headers.get("content-type", "")
    assert "hsl(" in graph.text and "RUN[cid]" in graph.text

    logs = app_session.get(app_url + "/logs", timeout=30)
    assert logs.status_code == 200
    assert "/intel/graph.html" in logs.text, "the analytics page does not embed the interactive graph"
