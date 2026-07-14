"""LIVE: device fingerprinting through the real fp.js -> fp-collector path.

The simulated fleet POSTs fp.js-shaped beacons to ``/__fpbeacon`` through nginx;
they must land in ``logdb.browser_fingerprints`` and, when read back through the
app's own fingerprint service, carry the right cross-layer verdict — a headless /
software-renderer bot flagged as a VM cohort with automation tells, a real browser
left clean. (The OS-vs-kernel contradiction is intentionally NOT raised here: the
traffic originates on the local Docker host, a private address the engine does not
trust for TCP-OS accusations — exactly the NAT-aware behavior.)
"""

from __future__ import annotations

import pytest

from .conftest import poll

pytestmark = pytest.mark.integration


def test_beacons_land_in_the_fingerprint_store(simulated_traffic, proxy):
    """Our fp beacons are recorded in browser_fingerprints (async; we poll)."""
    if simulated_traffic["beacons"] == 0:
        pytest.skip("no beacons were accepted by the collector")
    tag = simulated_traffic["tag"]
    landed = poll(lambda: proxy.count("browser_fingerprints", f"user_agent LIKE '%{tag}%'") or 0,
                  want=simulated_traffic["beacons"], timeout=20)
    assert landed >= simulated_traffic["beacons"], \
        f"only {landed} of {simulated_traffic['beacons']} beacons reached browser_fingerprints"


def test_consistency_verdicts_flag_the_vm_bot_and_clear_the_real_browser(simulated_traffic, proxy, site):
    """Read the beacons back through the app's fingerprint service and check the
    per-device cross-layer verdicts."""
    if simulated_traffic["beacons"] == 0:
        pytest.skip("no beacons were accepted by the collector")
    tag = simulated_traffic["tag"]
    # Ensure they have landed before reading.
    poll(lambda: proxy.count("browser_fingerprints", f"user_agent LIKE '%{tag}%'") or 0,
         want=simulated_traffic["beacons"], timeout=20)

    from app.services import fingerprint_service
    data = fingerprint_service.fetch_fingerprints(site=site["hostname"], search=tag, page_size=50)
    rows = {r["user_agent"]: r for r in data["rows"] if tag in (r.get("user_agent") or "")}
    assert rows, "fingerprint service returned none of our tagged beacons"

    vm = rows.get(simulated_traffic["vm_ua"])
    assert vm and vm.get("verdict"), "the headless/VM beacon was not read back with a verdict"
    assert vm["verdict"]["vm_cohort"] is True, "SwiftShader bot not flagged as a VM cohort"
    assert vm["verdict"]["automation"] is True, "automation tells on the VM bot were missed"

    clean = rows.get(simulated_traffic["clean_ua"])
    assert clean and clean.get("verdict"), "the real-browser beacon was not read back with a verdict"
    assert clean["verdict"]["vm_cohort"] is False, "a real browser was wrongly flagged as a VM cohort"
