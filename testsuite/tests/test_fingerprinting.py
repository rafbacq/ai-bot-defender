"""Device fingerprinting — Layers 1/2/3 (browser, TCP/IP, cross-layer consistency).

Covers the fingerprinting feature's analysis logic:

  * **Layer 1 (browser)** — folding fp.js beacons onto endpoints
    (``enrich.attach_browser_fingerprints``): device-correlation keys, automation
    score, and behavioral class propagate; the fp.js<->fp-collector payload
    contract holds.
  * **HTTP header signature (JA4H)** — ``enrich.compute_ja4h`` distinguishes a
    real browser's header set from an automation client's, and excludes nginx's
    own injected headers.
  * **Layer 3 (cross-layer consistency)** — ``analysis.consistency`` flags VM /
    software-renderer cohorts, automation tells, synthetic behavior, and the
    spoofed-OS contradiction (UA/JS OS vs. the TCP/IP kernel) — but ONLY trusts
    the TCP layer for **publicly-routed** clients (behind a local NAT the SYN is
    the proxy's, so a contradiction there must not accuse the operator's browser).
  * the **fingerprint viewer** verdict service (``fingerprint_service``) reusing
    that same engine per row.
"""

from __future__ import annotations

import pytest

from .conftest import load_module_from_path

PUBLIC_IP = "104.28.1.9"
PRIVATE_IP = "10.0.0.9"
WIN_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"


# --- Layer 1: browser fingerprint folding + payload contract ---------------
def test_browser_fingerprints_fold_onto_endpoints_with_device_keys():
    """fp.js beacons attach device-correlation keys + automation/behavior to an endpoint."""
    pytest.importorskip("networkx")
    from crawler_graph.ingest import enrich

    endpoints = {PUBLIC_IP: {"client_ip": PUBLIC_IP, "n_requests": 5}}
    beacons = [{
        "client_ip": PUBLIC_IP, "fp_id": "dev-1", "canvas_hash": "cv", "webgl_hash": "wg",
        "audio_hash": "au", "font_hash": "fo", "webgl_renderer": "Google SwiftShader",
        "navigator": {"platform": "Win32"}, "automation": {"score": 3, "webdriver": True},
        "behavior": {"synthetic": True, "interacted": False},
    }]
    enrich.attach_browser_fingerprints(endpoints, beacons)
    rec = endpoints[PUBLIC_IP]

    assert rec["has_browser_fingerprint"] is True
    assert rec["fpid"] == ["dev-1"] and rec["canvas"] == ["cv"]
    assert rec["n_device_keys"] == 5  # canvas+webgl+audio+font+fp_id
    assert rec["webgl_renderers"] == ["Google SwiftShader"]
    assert rec["js_platform"] == "Win32"
    assert rec["automation_score"] == 3 and rec["automation_tells"].get("webdriver") is True
    assert rec["behavior_synthetic"] is True

    # An endpoint with no beacon still gets the defaulted fields (uniform schema).
    bare = {"x": {"client_ip": "1.2.3.4"}}
    enrich.attach_browser_fingerprints(bare, [])
    assert bare["x"]["has_browser_fingerprint"] is False and bare["x"]["n_device_keys"] == 0


def test_fpjs_payload_keys_match_the_collector_contract(repo_root):
    """fp.js emits the beacon path + the exact payload keys fp-collector persists."""
    js = (repo_root / "website" / "static" / "js" / "fp.js").read_text(encoding="utf-8")
    collector = (repo_root / "proxy" / "fp-collector" / "app.py").read_text(encoding="utf-8")

    assert 'BEACON_PATH = "/__fpbeacon"' in js
    assert "navigator.sendBeacon" in js and "fetch(BEACON_PATH" in js
    for key in ["fp_id", "canvas_hash", "webgl_hash", "webgl_renderer", "audio_hash",
                "font_hash", "navigator", "automation", "behavior", "webgpu"]:
        assert key in js, f"fp.js never emits {key}"
        assert key in collector, f"fp-collector never stores {key}"
    # Every beacon of one page load shares a pv_id (lands in the collector's `raw`
    # jsonb — no dedicated column) so the request log can pick the newest
    # cumulative beacon of the RIGHT pageview.
    assert "p.pv_id = PV_ID" in js, "fp.js must stamp each beacon with the pageview id"


def test_fpjs_unload_beacon_rearms_after_tab_return(repo_root):
    """The unload beacon must NOT be one-shot: a visitor who tabs away (first
    beacon), comes back, and keeps interacting sends an UPDATED cumulative beacon
    on the next hide — the old `flushed` boolean silently dropped everything after
    the first tab-away. Idempotent hides (no new interaction) stay suppressed."""
    js = (repo_root / "website" / "static" / "js" / "fp.js").read_text(encoding="utf-8")
    assert "var flushed = false" not in js, "one-shot flush guard is back — later interaction would be lost"
    assert "flushedAt" in js and "total === flushedAt" in js
    # Idle-gap guard: pauses (reading / hidden tab) must not pollute the timing
    # distributions the synthetic-humanization check reads.
    assert "IDLE_GAP_MS" in js


# --- HTTP header signature (JA4H) ------------------------------------------
def test_ja4h_separates_browser_from_automation_and_drops_proxy_headers():
    """The header fingerprint differs for a real browser vs. an automation client,
    and never includes nginx's own injected headers."""
    from crawler_graph.ingest import enrich

    browser = {"accept": "text/html", "accept-language": "en-US,en;q=0.9",
               "accept-encoding": "gzip, deflate, br", "referer": "https://x/", "cookie": "a=b"}
    automation = {"accept-encoding": "gzip", "user-agent": "python-requests/2.31"}

    sig_browser = enrich.compute_ja4h(browser, "GET")
    sig_auto = enrich.compute_ja4h(automation, "GET")
    assert sig_browser and sig_auto and sig_browser != sig_auto

    # nginx-injected headers must not change the client's signature.
    proxied = dict(browser, **{"x-site": "site-001", "x-real-ip": "1.2.3.4",
                               "x-forwarded-for": "1.2.3.4", "host": "h"})
    assert enrich.compute_ja4h(proxied, "GET") == sig_browser
    assert enrich.compute_ja4h({}, "GET") is None


# --- Layer 3: cross-layer consistency engine -------------------------------
def _score(**rec):
    from crawler_graph.analysis import consistency
    base = {"client_ip": PUBLIC_IP, "is_browser": True, "has_browser_fingerprint": True,
            "n_requests": 5}
    base.update(rec)
    return consistency.score_endpoint(base)


def test_consistency_flags_spoofed_os_only_for_public_clients():
    """A Windows UA over a Linux SYN is a contradiction for a public client, but is
    NOT asserted for a NAT/private client (the SYN would be the proxy's there)."""
    public = _score(ua_top=WIN_UA, js_platform="Win32", tcp_os=["Linux"], client_ip=PUBLIC_IP)
    assert public["claimed_os"] == "Windows" and public["tcp_os"] == "Linux"
    assert public["tcp_os_trusted"] is True
    assert public["inconsistent"] is True
    assert any("TCP/IP stack" in c for c in public["contradictions"])

    private = _score(ua_top=WIN_UA, js_platform="Win32", tcp_os=["Linux"], client_ip=PRIVATE_IP)
    assert private["tcp_os_trusted"] is False
    assert private["inconsistent"] is False, "must not accuse a NAT/private client of OS spoofing"

    carrier_nat = _score(
        ua_top=WIN_UA,
        js_platform="Win32",
        tcp_os=["Linux"],
        client_ip="100.64.0.1",
    )
    assert carrier_nat["tcp_os_trusted"] is False
    assert carrier_nat["inconsistent"] is False, \
        "RFC6598 carrier/Tailscale NAT cannot prove the browser's client kernel"


def test_consistency_does_not_treat_declared_crawler_compat_ua_as_host_os():
    """OAI-SearchBot's Macintosh/Chrome wrapper is crawler compatibility syntax,
    not a claim that OpenAI's fetch host runs an Apple kernel."""
    oai_ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36; compatible; "
        "OAI-SearchBot/1.3; +https://openai.com/searchbot"
    )
    declared = _score(
        ua_top=oai_ua,
        tcp_os=["Linux"],
        client_ip="104.210.140.134",
        is_browser=False,
        is_declared_crawler=True,
        has_browser_fingerprint=False,
    )
    assert declared["declared_crawler"] is True
    assert declared["tcp_os_trusted"] is True
    assert declared["inconsistent"] is False
    assert not any("User-Agent claims Apple" in c for c in declared["contradictions"])

    # The exemption is scoped to declared crawlers; a normal Mac browser on the
    # same exact Linux SYN remains a strong contradiction.
    browser = _score(
        ua_top=oai_ua.split("; compatible;", 1)[0],
        tcp_os=["Linux"],
        client_ip="104.210.140.134",
        is_declared_crawler=False,
    )
    assert browser["inconsistent"] is True


def test_consistency_does_not_trust_same_ip_tcp_fallback_for_a_row():
    """A non-exact same-IP SYN remains visible but cannot accuse this request."""
    verdict = _score(
        ua_top=WIN_UA,
        tcp_os=["Linux"],
        client_ip=PUBLIC_IP,
        tcp_match_exact=False,
    )
    assert verdict["tcp_os"] == "Linux"
    assert verdict["tcp_os_trusted"] is False
    assert verdict["inconsistent"] is False
    assert not any("TCP/IP stack" in c for c in verdict["contradictions"])


def test_consistency_flags_vm_renderer_automation_and_synthetic_behavior():
    """Software/VM renderer, automation tells, and humanized-but-synthetic behavior
    are each independent bot signals."""
    vm = _score(ua_top=WIN_UA, webgl_renderers=["Google SwiftShader"])
    assert vm["vm_cohort"] is True
    assert any("virtual/software adapter" in c for c in vm["contradictions"])

    auto = _score(ua_top=WIN_UA, automation_score=2, automation_tells={"webdriver": True})
    assert auto["automation"] is True
    assert any("automation" in c for c in auto["contradictions"])

    synth = _score(ua_top=WIN_UA, behavior_synthetic=True)
    assert any("synthetic" in c for c in synth["contradictions"])
    assert synth["behavior_class"] == "synthetic"

    # Stacked tells (VM renderer + automation) cross the inconsistency threshold.
    combined = _score(ua_top=WIN_UA, webgl_renderers=["llvmpipe"], automation_score=2,
                      automation_tells={"webdriver": True})
    assert combined["inconsistent"] is True


def test_automation_requires_independent_weak_signal_families():
    """Correlated mobile/privacy and VM booleans count once per surface."""
    from crawler_graph.analysis import consistency

    assert consistency.automated_from_tells({
        "noPlugins": True,
        "noMimeTypes": True,
    }) is False
    assert consistency.automated_from_tells({
        "swRenderer": True,
        "zeroHardware": True,
    }) is False
    # A second independent surface crosses the default two-family threshold.
    assert consistency.automated_from_tells({
        "noPlugins": True,
        "noMimeTypes": True,
        "languagesEmpty": True,
    }) is True
    # Strong automation evidence remains conclusive by itself.
    assert consistency.automated_from_tells({"webdriver": True}) is True


def test_consistency_flags_browser_that_never_ran_js():
    """A browser-UA endpoint that fetched the page but never beaconed fp.js (no JS)
    is flagged — a headless / privacy-hardened tell."""
    rec = _score(ua_top=WIN_UA, has_browser_fingerprint=False, is_automated=False, n_requests=4)
    assert any("never executed JS" in c for c in rec["contradictions"])


def test_self_consistent_real_browser_is_not_flagged():
    """A genuine, self-consistent browser (UA/JS/TCP all agree, human behavior) is clean."""
    rec = _score(ua_top=WIN_UA, js_platform="Win32", tcp_os=["Windows"], client_ip=PUBLIC_IP,
                 webgl_renderers=["ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11)"],
                 behavior_interacted=True)
    assert rec["inconsistent"] is False
    assert rec["contradictions"] == []
    assert rec["behavior_class"] == "human"


def test_consistency_ignores_ambiguous_multi_os_tcp():
    """Two different OSes from one IP usually means NAT (many devices) and must not be
    read as a contradiction."""
    rec = _score(ua_top=WIN_UA, tcp_os=["Linux", "Apple"], client_ip=PUBLIC_IP)
    assert rec["tcp_os"] is None
    assert not any("TCP/IP stack" in c for c in rec["contradictions"])


def test_tcp_shipper_keeps_unrecognized_ttl64_shapes_unknown(repo_root):
    """The crowded TTL-64 family must not default every incomplete/new SYN to Linux."""
    pytest.importorskip("psycopg2")
    shipper = load_module_from_path(
        "proxy_tls_shipper_ambiguous",
        repo_root / "proxy" / "tls-shipper" / "app.py",
    )
    assert shipper.infer_os(64, None, None, 1460) == "unknown"
    assert shipper.infer_os(64, 12345, 3, 1460) == "unknown"
    assert shipper.infer_os(64, 65535, 8, 1460) == "unknown"
    assert shipper.infer_os(64, 65535, 6, 1460) == "Apple"
    assert shipper.infer_os(63, 29200, 7, 1460) == "Linux"

    # With the SYN option order captured, a recognized order resolves the bucket
    # even for windows the legacy heuristic never listed; an unrecognized order
    # (or none at all) stays "unknown" so no false OS-spoof accusation is minted.
    assert shipper.infer_os(64, 62727, 7, 1460, [2, 4, 8, 1, 3]) == "Linux"
    assert shipper.infer_os(64, 65535, 6, 1432, [2, 1, 3, 1, 1, 8, 4]) == "Apple"
    assert shipper.infer_os(64, 65535, 7, 1460, [2, 1, 3, 4, 8]) == "unknown"
    assert shipper.infer_os(64, 62727, 7, 1460, None) == "unknown"
    assert shipper.infer_os(64, 40000, 9, 1460, []) == "unknown"  # empty options match nothing


# --- The fingerprint viewer's per-row verdict (reuses the same engine) ------
def test_fingerprint_service_verdict_matches_the_engine_for_a_public_row():
    """``fingerprint_service.verdict_for`` reproduces the consistency verdict on a
    raw browser_fingerprints row (public client: the OS contradiction fires)."""
    from app.services import fingerprint_service as fs

    verdict = fs.verdict_for({
        "client_ip": PUBLIC_IP,
        "user_agent": WIN_UA,
        "navigator": {"platform": "Win32"},
        "automation": {"score": 2, "webdriver": True},
        "behavior": {"synthetic": True, "interacted": False},
        "webgl_renderer": "Google SwiftShader",
        "tcp_os": "Linux",
    })
    assert verdict["inconsistent"] is True
    assert verdict["vm_cohort"] is True and verdict["automation"] is True
    assert verdict["claimed_os"] == "Windows" and verdict["tcp_os"] == "Linux"
