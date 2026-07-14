"""Crawler intelligence — clustering & attribution (crawler_graph pipeline).

Simulates a large, diverse bot population hitting the honeypot and asserts the
system can (a) **log who they are** — attribute declared crawlers to the right
provider — and (b) **cluster them** correctly — group a disguised fleet, an
agentic-browser population, a proxy-rotating device, and a VM cohort into the
right campaigns with the right flags, while NOT raising the serious flags on
ordinary humans.

This exercises the real pipeline end to end (ingest -> fingerprint joins ->
enrichment -> identity graph -> community detection -> campaign synthesis),
driven only by the synthetic populations in ``synthetic.py``.
"""

from __future__ import annotations

import os

import pytest

from .synthetic import bot_population


def _run(scale=1, method="louvain"):
    pytest.importorskip("networkx")
    if method == "louvain":
        pytest.importorskip("community")
    from crawler_graph import pipeline

    visits, handshakes, browser_fps, tcp_fps, labels = bot_population(scale=scale)
    result = pipeline.run_intel(
        visits=visits, handshakes=handshakes, browser_fps=browser_fps, tcp_fps=tcp_fps,
        resolve_asn=False, use_gnn=False, method=method, write=False, render=False,
    )
    return result, labels, len(visits)


def _campaigns_for(campaigns, ips):
    ips = set(ips)
    return [c for c in campaigns if ips & set(c["sample_ips"])]


def test_pipeline_ingests_all_layers_and_joins_fingerprints():
    """Every request is ingested and the TLS/TCP/browser fingerprint layers join on."""
    result, _labels, n_visits = _run()
    meta = result["meta"]

    assert meta["n_visits"] == n_visits
    assert meta["n_endpoints"] > 0
    assert meta["n_handshakes"] > 0 and meta["n_browser_fps"] > 0 and meta["n_tcp_fps"] > 0
    assert meta["fingerprints_present"] is True
    assert meta["browser_fingerprints_present"] is True
    assert meta["tcp_fingerprints_present"] is True
    # A real partition was produced over the identity graph.
    assert result["findings"]["n_campaigns"] >= 5
    assert meta["graph"]["ip_nodes"] > 0 and meta["graph"]["attr_nodes"] > 0


def test_declared_crawlers_are_attributed_to_the_right_provider():
    """Honest GPTBot/ClaudeBot/Googlebot fleets attribute to their provider, unflagged."""
    result, labels, _ = _run()
    campaigns = result["campaigns"]

    expected = {
        "declared_openai": "OpenAI",
        "declared_anthropic": "Anthropic",
        "declared_google": "Google",
    }
    for pop, provider in expected.items():
        matched = _campaigns_for(campaigns, labels[pop])
        assert matched, f"{pop} formed no campaign"
        camp = max(matched, key=lambda c: c["n_ips"])
        assert provider in camp["label"], f"{pop} mislabeled as {camp['label']!r}"
        assert provider in camp["declared_providers"]
        # An honest, self-declaring crawler must not raise any disguise/contradiction flag.
        assert not camp["disguise_suspected"], f"{pop} wrongly flagged disguised"
        assert not camp["agentic_suspected"], f"{pop} wrongly flagged agentic"
        assert not camp["contradiction_suspected"], f"{pop} wrongly flagged inconsistent"


def test_disguised_stealth_fleet_is_caught_via_shared_fingerprint_and_os_contradiction():
    """A browser-UA crawler spread across ASNs on one JA4, with a Linux SYN under a
    Windows UA, is flagged as disguised AND cross-layer inconsistent."""
    result, labels, _ = _run()
    findings, campaigns = result["findings"], result["campaigns"]

    assert findings["n_disguised"] >= 1
    assert findings["n_contradiction"] >= 1

    stealth = _campaigns_for(campaigns, labels["stealth"])
    assert stealth, "stealth fleet formed no campaign"
    # The shared JA4 should collapse the fleet into one dominant campaign.
    camp = max(stealth, key=lambda c: c["n_ips"])
    assert camp["n_asns"] >= 2, "stealth fleet should span multiple ASNs"
    assert camp["shared_fingerprint"] and camp["systematic"]
    assert camp["disguise_suspected"], "stealth fleet not flagged disguised"
    assert camp["contradiction_suspected"], "stealth OS contradiction (UA vs SYN) missed"
    assert not camp["declared_providers"], "stealth fleet should carry no declared bot UA"


def test_agentic_browser_population_is_flagged_agentic_not_disguised():
    """A shared-fingerprint, casual-volume, self-consistent browser cohort reads as
    agentic (FP-Agent territory), not as a deliberate stealth crawl."""
    result, labels, _ = _run()
    campaigns = result["campaigns"]

    agentic = [c for c in _campaigns_for(campaigns, labels["agentic"]) if c["agentic_suspected"]]
    assert agentic, "agentic-browser population not flagged agentic"
    camp = max(agentic, key=lambda c: c["n_ips"])
    assert camp["n_ips"] >= 5, "the agentic cohort should cluster, not fragment"
    assert not camp["systematic"], "agentic cohorts are casual-volume, not systematic"
    assert not camp["disguise_suspected"], "self-consistent agentic cohort wrongly flagged disguise"


def test_proxy_rotator_is_stitched_into_one_campaign_by_device_fingerprint():
    """One machine sharing a canvas/fp_id across several ASNs collapses into a SINGLE
    campaign flagged as a shared device rotating IPs."""
    result, labels, _ = _run()
    campaigns = result["campaigns"]

    stitched = _campaigns_for(campaigns, labels["rotator"])
    assert len(stitched) == 1, f"rotator split across {len(stitched)} campaigns"
    camp = stitched[0]
    assert labels["rotator"] <= set(camp["sample_ips"]), "not all rotator IPs in one campaign"
    assert camp["shared_device_fingerprint"], "shared device fingerprint not flagged"
    assert camp["n_asns"] >= 2 and camp["disguise_suspected"], \
        "rotator across ASNs should read as disguise via device stitching"


def test_vm_headless_cohort_is_flagged_as_vm_cohort():
    """A SwiftShader/software-renderer headless cohort is flagged vm_cohort."""
    result, labels, _ = _run()
    findings, campaigns = result["findings"], result["campaigns"]

    assert findings["n_vm_cohort"] >= 1
    vm = [c for c in _campaigns_for(campaigns, labels["vm"]) if c["vm_cohort_suspected"]]
    assert vm, "VM/headless cohort not flagged vm_cohort"


def test_ordinary_humans_do_not_raise_serious_disguise_flags():
    """Self-consistent human browsers must never be flagged disguised / contradictory /
    VM (the false-positive guard for privacy-hardened real users)."""
    result, labels, _ = _run()
    campaigns = result["campaigns"]

    for camp in _campaigns_for(campaigns, labels["humans"]):
        # Humans share their campaign with nobody disguised: assert no serious flag.
        assert not camp["disguise_suspected"], f"human campaign flagged disguised: {camp['sample_ips']}"
        assert not camp["contradiction_suspected"], "consistent human flagged inconsistent"
        assert not camp["vm_cohort_suspected"], "human flagged as VM cohort"


@pytest.mark.stress
def test_large_disguised_fleet_still_clusters_under_load():
    """Scaling the stealth fleet keeps it clustered and flagged (stress dimension).

    The fleet is held together by ONE shared JA4 hub; that hub is kept only while
    it stays under the attribute-hub cap (``INTEL_ATTR_HUB_CAP``, default 400), so
    we cap the effective fleet below it — past the cap is a different regime (a
    giant hub is dropped as noise), not a clustering failure."""
    requested = int(os.environ.get("BOT_DEFENDER_BOTS", "0")) // 14
    scale = max(6, min(requested or 6, 25))  # 25 * 14 = 350 IPs, under the 400 hub cap
    result, labels, n_visits = _run(scale=scale)
    campaigns = result["campaigns"]

    assert result["meta"]["n_visits"] == n_visits
    stealth = _campaigns_for(campaigns, labels["stealth"])
    assert stealth, "stealth fleet vanished under load"
    # Under load Louvain may split the fleet into sub-communities — but EVERY one of
    # them must stay flagged disguised + contradictory (no part leaks into a benign
    # cluster), and together they must still account for essentially the whole fleet.
    assert all(c["disguise_suspected"] and c["contradiction_suspected"] for c in stealth), \
        "part of the stealth fleet escaped the disguise/contradiction flags under load"
    covered = sum(c["n_ips"] for c in stealth)
    assert covered >= 0.8 * len(labels["stealth"]), \
        f"stealth campaigns cover only {covered}/{len(labels['stealth'])} of the fleet"


def test_greedy_community_detection_is_a_working_fallback():
    """The pipeline still attributes + flags when only networkx greedy modularity is
    available (no python-louvain) — the zero-optional-deps path."""
    result, labels, _ = _run(method="greedy")
    assert result["meta"]["community_method"] == "greedy"
    assert any("OpenAI" in c["label"] for c in result["campaigns"])
    assert result["findings"]["n_disguised"] >= 1
