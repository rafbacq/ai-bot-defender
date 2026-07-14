"""Turn communities into campaign objects + the disguise / agentic findings.

A *campaign* is one community's worth of client IPs acting as a unit. For each
we compute who it is (declared providers from UAs; published-range verification
if available; optional GNN-predicted provider) and the load-bearing flags:

  * ``disguise_suspected`` — the actual research signal. Raised when a cohort is
    held together by a shared TLS fingerprint or /24 but spreads across ASNs and
    presents browser/automation UAs (i.e. it hides what it is), or when a
    declared-crawler UA appears from **outside** that provider's published IP
    ranges (impersonation / undeclared infra).
  * ``agentic_suspected`` — browser-engine UAs with a coherent real-browser
    fingerprint and no bot UA: the agentic-AI-browser population (FP-Agent
    territory), which can only be separated by fingerprint, not UA.

Honest, self-declaring crawlers come out as plainly attributed campaigns with
neither flag — which is the correct, proportionate outcome for them.
"""

import statistics
from collections import Counter

from .. import config
from ..ingest import known_crawlers


def _kind(graph, node):
    return graph.nodes.get(node, {}).get("kind")


def build_campaigns(graph, membership, endpoints, gnn_preds=None, ranges=None):
    """Return a list of campaign dicts, largest first."""
    ranges = ranges if ranges is not None else known_crawlers.load_ranges(config.CRAWLER_RANGES)
    gnn_preds = gnn_preds or {}

    # Group IP nodes by community.
    groups = {}
    for node, cid in membership.items():
        if _kind(graph, node) == "ip":
            groups.setdefault(cid, []).append(node)

    campaigns = []
    for cid, ips in groups.items():
        recs = [endpoints[ip] for ip in ips if ip in endpoints]
        if not recs:
            continue
        campaigns.append(_summarize(cid, recs, gnn_preds, ranges))

    campaigns.sort(key=lambda c: (c["n_requests"], c["n_ips"]), reverse=True)
    for i, camp in enumerate(campaigns):
        camp["campaign_id"] = i
    return campaigns


def _summarize(cid, recs, gnn_preds, ranges):
    ips = [r["client_ip"] for r in recs]
    asns = Counter(r.get("asn") for r in recs if r.get("asn"))
    netblocks = {r.get("netblock") for r in recs if r.get("netblock")}
    ja4 = set()
    ja3 = set()
    uas = Counter()
    declared = Counter()
    gnn_votes = Counter()
    n_requests = 0
    sites = set()
    browser_ips = 0
    automated_ips = 0
    fp_ips = 0
    # Layer-1/2/3 fingerprint + cross-layer-consistency accumulators.
    ja4h = set()
    tcp_os_counter = Counter()
    device_canvas = set()
    device_webgl = set()
    device_fpid = set()
    browser_fp_ips = 0
    vm_cohort_ips = 0
    automation_xlayer_ips = 0
    contradiction_ips = 0
    inconsistency_reasons = []

    for r in recs:
        n_requests += r.get("n_requests", 0)
        ja4 |= set(r.get("ja4") or [])
        ja3 |= set(r.get("ja3") or [])
        for ua, n in (r.get("user_agents") or {}).items():
            uas[ua] += n
        for p in r.get("providers_ua") or []:
            declared[p] += 1
        sites |= set(r.get("sites") or [])
        if r.get("is_browser"):
            browser_ips += 1
        if r.get("is_automated"):
            automated_ips += 1
        if r.get("has_fingerprint"):
            fp_ips += 1
        ja4h |= set(r.get("ja4h") or [])
        device_canvas |= set(r.get("canvas") or [])
        device_webgl |= set(r.get("webgl_fp") or [])
        device_fpid |= set(r.get("fpid") or [])
        if r.get("has_browser_fingerprint"):
            browser_fp_ips += 1
        cons = r.get("consistency") or {}
        if cons.get("vm_cohort"):
            vm_cohort_ips += 1
        if cons.get("automation"):
            automation_xlayer_ips += 1
        if cons.get("inconsistent"):
            contradiction_ips += 1
        if cons.get("tcp_os"):
            tcp_os_counter[cons["tcp_os"]] += 1
        inconsistency_reasons.extend(cons.get("contradictions") or [])
        pred = gnn_preds.get(r["client_ip"])
        if pred and pred.get("provider") and pred["provider"] != "unknown":
            gnn_votes[pred["provider"]] += 1

    # When did this cohort operate, and how regular was it? Burstiness in [-1, 1]
    # (+1 very bursty, 0 Poisson-like, -1 metronomic) — a metronomic, sustained
    # cohort reads as automated infrastructure; a bursty one as human-driven.
    first_seen = min((r.get("first_ts") for r in recs if r.get("first_ts")), default=None)
    last_seen = max((r.get("last_ts") for r in recs if r.get("last_ts")), default=None)
    bursts = [r.get("burstiness") for r in recs if r.get("burstiness") is not None]
    mean_burstiness = round(statistics.fmean(bursts), 3) if bursts else None

    n_ips = len(ips)
    fingerprints = ja4 or ja3
    # Cohesion: does ONE fingerprint dominate the whole cohort? (Strong "same
    # client stack" signal across otherwise-disparate IPs.)
    shared_fp = bool(fingerprints) and len(fingerprints) <= max(1, round(0.25 * n_ips))
    multi_asn = len(asns) > 1
    declared_providers = [p for p, _ in declared.most_common()]
    gnn_provider = gnn_votes.most_common(1)[0][0] if gnn_votes else None
    mean_req_per_ip = (n_requests / n_ips) if n_ips else 0.0
    # Systematic crawling (lots of requests per IP) vs. casual browsing — this is
    # what separates a stealth crawler from an agentic-browser population.
    systematic = mean_req_per_ip >= config.SYSTEMATIC_MIN_REQ_PER_IP

    # --- IP-range verification for declared crawlers -----------------------
    range_violations = []
    for r in recs:
        for prov in r.get("providers_ua") or []:
            verdict = known_crawlers.ip_in_declared_ranges(r["client_ip"], prov, ranges)
            if verdict is False:
                range_violations.append({"ip": r["client_ip"], "claimed_provider": prov})

    # --- Disguise / agentic flags ------------------------------------------
    browser_share = browser_ips / n_ips if n_ips else 0.0
    disguise_reasons = []
    if range_violations:
        disguise_reasons.append(
            f"{len(range_violations)} IP(s) claim a crawler UA but fall outside "
            "that provider's published ranges (impersonation / undeclared infra)"
        )
    if shared_fp and multi_asn and not declared_providers and (systematic or automated_ips):
        disguise_reasons.append(
            "one TLS fingerprint shared across multiple ASNs at crawl volume on "
            "browser/automation UAs with no declared bot UA (stealth crawling signature)"
        )
    if gnn_provider and not declared_providers and (browser_ips or automated_ips):
        disguise_reasons.append(
            f"GNN attributes this cohort to {gnn_provider} despite no declared bot UA"
        )
    # Layer-1 device-graph stitching: one device fingerprint dominating a cohort
    # that spans multiple ASNs is the same physical machine rotating IPs/proxies
    # (the doc's credential-stuffing / proxy-rotation signal). Cohesion is checked
    # per key TYPE (a device legitimately has both a canvas and an fp_id, so the
    # combined set would over-count) — a single value dominating ANY type counts.
    def _cohesive(values):
        return bool(values) and len(values) <= max(1, round(0.25 * n_ips))
    shared_device = (_cohesive(device_canvas) or _cohesive(device_webgl)
                     or _cohesive(device_fpid))
    # A stitched device across ASNs is only a *campaign* disguise when the cohort
    # also behaves like infrastructure: crawl volume, automation tells, or an ASN
    # footprint beyond human roaming (DISGUISE_DEVICE_MIN_ASNS). One person's
    # phone legitimately carries a single fingerprint across home Wi-Fi and LTE
    # (2 ASNs) at casual volume — that is mobility, not proxy rotation.
    if shared_device and multi_asn and (
            systematic or automated_ips
            or len(asns) >= config.DISGUISE_DEVICE_MIN_ASNS):
        disguise_reasons.append(
            "one device fingerprint (canvas / WebGL / composite fp_id) shared across "
            "multiple ASNs — the same physical machine rotating IPs/proxies"
        )
    # Cross-layer consistency: claimed identity contradicting the lower layers.
    if contradiction_ips:
        disguise_reasons.append(
            f"{contradiction_ips} IP(s) show cross-layer contradictions (claimed "
            "OS/browser vs. TCP/IP stack, WebGL renderer, or automation tells)"
        )

    # Agentic browser: a coherent real-browser fingerprint on browser UAs, but
    # *casual* volume (not a systematic crawl) — the FP-Agent population. Disguise
    # (a deliberate stealth crawl) takes precedence when both could apply.
    agentic = (
        not disguise_reasons
        and browser_share >= 0.5
        and shared_fp
        and not declared_providers
        and automated_ips == 0
        and not systematic
    )

    label, confidence = _label(declared_providers, gnn_provider, disguise_reasons, agentic)

    return {
        "community_id": cid,
        "label": label,
        "confidence": confidence,
        "n_ips": n_ips,
        "n_requests": n_requests,
        "asns": [{"asn": a, "ips": n} for a, n in asns.most_common()],
        "n_asns": len(asns),
        "n_netblocks": len(netblocks),
        "declared_providers": declared_providers,
        "gnn_provider": gnn_provider,
        "ja4": sorted(ja4),
        "ja3": sorted(ja3),
        "shared_fingerprint": shared_fp,
        "mean_req_per_ip": round(mean_req_per_ip, 1),
        "systematic": systematic,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "mean_burstiness": mean_burstiness,
        "top_user_agents": [ua for ua, _ in uas.most_common(5)],
        "n_user_agents": len(uas),
        "sites": sorted(s for s in sites if s),
        "browser_ips": browser_ips,
        "automated_ips": automated_ips,
        "fingerprinted_ips": fp_ips,
        "disguise_suspected": bool(disguise_reasons),
        "disguise_reasons": disguise_reasons,
        "agentic_suspected": bool(agentic),
        "range_violations": range_violations,
        # --- Fingerprint layers (browser / HTTP-header / TCP-OS) + consistency ---
        "ja4h": sorted(ja4h)[:10],
        "tcp_os": [{"os": o, "ips": n} for o, n in tcp_os_counter.most_common()],
        "browser_fingerprinted_ips": browser_fp_ips,
        "device_fingerprints": {
            "canvas": sorted(device_canvas)[:10],
            "webgl": sorted(device_webgl)[:10],
            "fp_id": sorted(device_fpid)[:10],
            "n_canvas": len(device_canvas),
            "n_webgl": len(device_webgl),
            "n_fp_id": len(device_fpid),
        },
        "shared_device_fingerprint": shared_device,
        "vm_cohort_ips": vm_cohort_ips,
        "automation_ips": automation_xlayer_ips,
        "contradiction_ips": contradiction_ips,
        "inconsistency_reasons": list(dict.fromkeys(inconsistency_reasons))[:8],
        "vm_cohort_suspected": vm_cohort_ips > 0,
        "contradiction_suspected": contradiction_ips > 0,
        "sample_ips": ips[:25],
    }


def _label(declared, gnn_provider, disguise_reasons, agentic):
    """A human label + a coarse confidence for the campaign card."""
    if declared and not disguise_reasons:
        return (f"{declared[0]} (declared)", "high")
    if disguise_reasons:
        who = declared[0] if declared else (gnn_provider or "unknown")
        return (f"Suspected undeclared / disguised — {who}", "medium")
    if agentic:
        return ("Suspected agentic browser", "medium")
    if gnn_provider:
        return (f"{gnn_provider} (GNN-attributed)", "low")
    return ("Unattributed campaign", "low")


def findings(campaigns):
    """Pull out the headline findings for quick display: disguised + agentic +
    VM/container cohorts + cross-layer contradictions."""
    disguised = [c for c in campaigns if c["disguise_suspected"]]
    agentic = [c for c in campaigns if c["agentic_suspected"]]
    vm_cohort = [c for c in campaigns if c.get("vm_cohort_suspected")]
    contradiction = [c for c in campaigns if c.get("contradiction_suspected")]
    return {
        "n_campaigns": len(campaigns),
        "n_disguised": len(disguised),
        "n_agentic": len(agentic),
        "n_vm_cohort": len(vm_cohort),
        "n_contradiction": len(contradiction),
        "disguised": disguised,
        "agentic": agentic,
        "vm_cohort": vm_cohort,
        "contradiction": contradiction,
    }
