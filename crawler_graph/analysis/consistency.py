"""Cross-layer consistency engine — the reference doc's central thesis.

Modern fingerprinting hunts for **internal contradiction** rather than rarity: a
genuine device is self-consistent across the browser, network, and OS layers,
while bots and anti-detect browsers betray themselves with *improbable
combinations* — "a Chrome User-Agent rendering text through a Firefox pipeline,
an iOS handshake on a Linux kernel, a fresh device whose every randomized
attribute is individually rare."

For each enriched endpoint we cross-check the claimed identity (User-Agent,
JS ``navigator.platform``) against the spoof-resistant lower layers (the TCP/IP
kernel inference from the SYN, the GPU/WebGL renderer, automation tells, and the
behavioral class) and emit a list of concrete contradictions + a weighted
``score``. The OS contradiction — claimed UA/JS OS vs. the kernel the packets
reveal — is the headline signal because the TCP/IP stack survives proxies/VPNs.

This is deliberately conservative to bound false positives on privacy-hardened
real users (the doc's "privacy counter-pressure"): we only assert an OS
contradiction when the TCP inference is unambiguous, and we treat "too clean"
as a low-weight note, not a hard flag.

We also never read the TCP/IP OS layer for a visitor whose source address is
local/NAT (loopback, RFC1918, link-local). Behind a local NAT / the Docker
userland proxy (the local build) the captured SYN is the *proxy host's*, not the
real client's, so every visitor's kernel looks identical (typically "Linux")
regardless of their actual OS — reading that as a spoof would flag the operator's
own browser. Real crawlers arrive from routable public addresses, where the
SYN genuinely is the client's and the TCP layer stays trustworthy.

Known residual limit on PUBLIC addresses: an enterprise egress / forwarding
proxy (Zscaler-style) terminates the client's TCP and re-originates it from its
own (usually Linux) stack on a public IP, so employees browsing through one can
read as an OS contradiction. ``dominant_tcp_os`` already stands down when one IP
shows several kernel families (a NAT of mixed devices); a single-OS corporate
egress is indistinguishable from a genuine spoof at this layer — tune the
``os_ua_vs_tcp`` weight down via env if that population matters in a deployment.
"""

import ipaddress
from collections import Counter

from .. import config


def os_from_ua(ua):
    """Coarse OS family claimed by a User-Agent (Windows / Apple / Linux / None).

    Android and ChromeOS are Linux kernels, so they map to ``Linux`` — that keeps
    an Android UA on a Linux SYN *consistent* (no false contradiction)."""
    u = (ua or "").lower()
    if "windows" in u or "win64" in u or "win32" in u:
        return "Windows"
    if "android" in u or "cros" in u:
        return "Linux"
    if "iphone" in u or "ipad" in u or "ipod" in u:
        return "Apple"
    if "mac os x" in u or "macintosh" in u or "darwin" in u:
        return "Apple"
    if "linux" in u or "ubuntu" in u or "fedora" in u or "debian" in u or "x11" in u:
        return "Linux"
    return None


def os_from_platform(platform):
    """OS family from JS ``navigator.platform`` (a separate spoof surface from UA)."""
    p = (platform or "").lower()
    if not p:
        return None
    if "win" in p:
        return "Windows"
    if "iphone" in p or "ipad" in p or "ipod" in p:
        return "Apple"
    if "mac" in p:
        return "Apple"
    if "android" in p or "cros" in p:
        return "Linux"
    if "linux" in p:
        return "Linux"
    return None


def tcp_os_is_trustworthy(rec):
    """Whether this endpoint's SYN-derived OS describes the *real client*.

    It only does when the captured packet actually came from the client. Behind a
    local NAT / Docker userland-proxy (the local build) the client address is a
    private/loopback hop and the SYN is the proxy host's, so the OS inference is
    meaningless for spoof detection — every visitor reads as the proxy's kernel.
    A routable public client address means source-preserving delivery, so the
    TCP layer is trusted. Override with ``INTEL_TRUST_PRIVATE_TCP=1`` for a
    genuine same-LAN / source-preserving-DNAT deployment."""
    if config.TRUST_TCP_FROM_PRIVATE:
        return True
    ip = rec.get("client_ip")
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_unspecified or addr.is_reserved)


def dominant_tcp_os(rec):
    """The unambiguous TCP/IP OS family for an endpoint, or ``None``.

    ``rec['tcp_os']`` is the set of SYN-derived OS guesses. We drop the ambiguous
    ``Network/BSD`` bucket and only return a family when exactly one meaningful
    value is present — multiple distinct OSes from one IP usually means NAT (many
    devices), which we must not misread as a contradiction."""
    oses = [o for o in (rec.get("tcp_os") or []) if o and o not in ("unknown", "Network/BSD")]
    if not oses:
        return None
    counts = Counter(oses)
    if len(counts) == 1:
        return next(iter(counts))
    return None


def _vm_cohort(rec):
    """Return the offending renderer string if the endpoint is a VM/software
    cohort (virtual display adapter / software rasterizer / common cloud GPU)."""
    for renderer in rec.get("webgl_renderers") or []:
        low = (renderer or "").lower()
        for marker in config.VM_RENDERER_MARKERS:
            if marker in low:
                return renderer
    if (rec.get("automation_tells") or {}).get("swRenderer"):
        return "software renderer (WebGL)"
    return None


def automated_from_tells(tells):
    """Decide 'automated' from the fp.js automation tells with strong/weak weighting.

    The old rule (``score >= 1``) flipped a visitor to *automated* on any single
    tell — but ``noPlugins``/``noMimeTypes`` (Tor/Brave/privacy Firefox),
    ``chromeMissing`` (in-app WebViews) and ``swRenderer``/``zeroHardware``
    (VMs/RDP/corp machines) are all legitimately true for real users. So a STRONG
    tell (``webdriver``/``cdc``/``headlessUA``/``toStringTampered`` — things a real
    browser never trips) is conclusive on its own, while WEAK tells must appear in
    combination (``>= WEAK_AUTOMATION_MIN``, default 2) before we call automation."""
    keys = {str(k).lower() for k, v in (tells or {}).items() if v is True}
    if keys & config.STRONG_AUTOMATION_TELLS:
        return True
    weak = keys - config.STRONG_AUTOMATION_TELLS
    return len(weak) >= config.WEAK_AUTOMATION_MIN


def _behavior_class(rec, automation):
    if not rec.get("has_browser_fingerprint"):
        return "no-js"
    if rec.get("behavior_synthetic"):
        return "synthetic"
    if automation:
        return "automated"
    if rec.get("behavior_interacted"):
        return "human"
    return "passive"


def score_endpoint(rec):
    """Return the cross-layer consistency verdict for one endpoint record."""
    weights = config.CONSISTENCY_WEIGHTS
    contradictions = []
    score = 0

    ua_os = os_from_ua(rec.get("ua_top") or "")
    js_os = os_from_platform(rec.get("js_platform"))
    tcp_os = dominant_tcp_os(rec)
    # Only the TCP layer can be spoof-resistant proof of OS — and only when the
    # SYN actually came from the client. Behind a local NAT (the Docker build)
    # it is the proxy host's kernel, so we observe it but do not let it accuse.
    tcp_trusted = tcp_os is not None and tcp_os_is_trustworthy(rec)

    if tcp_trusted and ua_os and ua_os != tcp_os:
        contradictions.append(
            f"User-Agent claims {ua_os} but the TCP/IP stack looks like {tcp_os} "
            "(kernel betrays a spoofed OS)")
        score += weights["os_ua_vs_tcp"]
    if tcp_trusted and js_os and js_os != tcp_os:
        contradictions.append(
            f"navigator.platform reports {js_os} but the TCP/IP stack looks like {tcp_os}")
        score += weights["os_js_vs_tcp"]
    if ua_os and js_os and ua_os != js_os:
        contradictions.append(
            f"User-Agent claims {ua_os} but navigator.platform reports {js_os}")
        score += weights["os_ua_vs_js"]

    vm = _vm_cohort(rec)
    if vm:
        contradictions.append(f"WebGL renderer is a virtual/software adapter ({vm})")
        score += weights["vm_cohort"]

    # Weighted automation decision (strong tell alone, or >=2 weak tells) OR'd with
    # the UA-derived flag (declared crawlers / automation libraries by User-Agent).
    automation = automated_from_tells(rec.get("automation_tells")) or bool(rec.get("is_automated"))
    if automation:
        tells = ", ".join(sorted((rec.get("automation_tells") or {}).keys()))
        contradictions.append(
            "automation tells present" + (f" ({tells})" if tells else " (automation User-Agent)"))
        score += weights["automation"]

    if rec.get("behavior_synthetic"):
        contradictions.append(
            "behavioral biometrics look synthetically humanized (timing too regular)")
        score += weights["synthetic_behavior"]

    if (rec.get("is_browser") and not rec.get("is_automated")
            and not rec.get("has_browser_fingerprint") and rec.get("n_requests", 0) > 0):
        contradictions.append(
            "browser User-Agent fetched the page but never executed JS "
            "(no fingerprint beacon — headless or privacy-hardened)")
        score += weights["browser_no_js"]

    return {
        "contradictions": contradictions,
        "score": score,
        "inconsistent": score >= config.INCONSISTENCY_FLAG_SCORE,
        "vm_cohort": bool(vm),
        "automation": automation,
        "behavior_class": _behavior_class(rec, automation),
        "claimed_os": ua_os,
        "js_os": js_os,
        "tcp_os": tcp_os,
        "tcp_os_trusted": tcp_trusted,
    }


def annotate(endpoints):
    """Attach a ``consistency`` verdict to every endpoint record (in place)."""
    for rec in endpoints.values():
        rec["consistency"] = score_endpoint(rec)
    return endpoints
