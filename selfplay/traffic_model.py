"""Generative traffic simulator.

Produces request rows in the *exact* shape ``crawler_graph.pipeline.run_intel``
consumes (verified against ``crawler_graph/tests/test_pipeline.py``): ``visits``
(+ ``asn`` pre-attached so the oracle runs ``resolve_asn=False``), ``handshakes``
(TLS JA4 by 4-tuple), ``browser_fps`` (the fp.js beacon, by IP), and ``tcp_fps``
(the SYN OS inference by 4-tuple).

Two producers:

* ``sample_background()`` — honest declared crawlers + human browsers + datacenter
  automation from the fitted ``personas`` — the realistic backdrop the attacker's
  cohort is embedded in (so cohort-level disguise signals have context) and the
  reference distribution for the Phase-0 calibration test.
* ``CohortState`` + ``realize_step()`` — the attacker's own campaign, built up
  action-by-action from the policy. The attacker operates a *pool of proxy
  identities*; rotation + stack choices decide whether the cohort shares one TLS
  fingerprint / device / ASN (the levers the disguise detector keys on).

All synthetic client IPs are **public/routable** on purpose: the TCP-OS
contradiction layer (``consistency.tcp_os_is_trustworthy``) is inert on private
addresses, so a private-IP simulator would silently disable that whole rung.
"""

import random
from datetime import datetime, timedelta, timezone

from . import personas as personas_mod

_BASE_TS = datetime(2026, 6, 1, tzinfo=timezone.utc)

_REAL_GPUS = [
    "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "Apple GPU",
]
_VM_GPUS = ["Google SwiftShader", "llvmpipe (LLVM 15.0.7, 256 bits)", "VMware SVGA 3D"]
_REQ_PER_STEP = {"fast": 6, "human": 3, "slow": 1}
_STRONG_TELLS = {"webdriver": True, "cdc": True}


def _ip(prefix, rng):
    return f"{prefix}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def _ua_for(stack, rng, vary=False):
    """A user-agent string for a stack preset's claimed OS / kind."""
    if stack.ua_kind == "declared":
        ua, _, _ = rng.choice(personas_mod.DECLARED_CRAWLERS)
        return ua, "Linux", None
    if stack.ua_kind == "automation":
        return rng.choice(["python-requests/2.31.0", "Go-http-client/2.0",
                           "curl/8.4.0", "okhttp/4.12.0"]), "Linux", None
    triples = [t for t in personas_mod.HUMAN_UAS if t[1] == stack.claim_os] or personas_mod.HUMAN_UAS
    ua, os_fam, plat = rng.choice(triples) if vary else triples[0]
    return ua, os_fam, plat


def _gaps(n, mean_gap, pattern, rng):
    """Inter-arrival seconds for ``n`` requests under a timing pattern."""
    out = []
    for _ in range(n):
        if pattern == "regular":
            out.append(mean_gap)
        elif pattern == "bursty":
            out.append(rng.expovariate(1.0 / max(1e-3, mean_gap)) * (2.0 if rng.random() < 0.3 else 0.2))
        else:  # poisson
            out.append(rng.expovariate(1.0 / max(1e-3, mean_gap)))
    return out


class Bundle:
    """The four row-lists run_intel consumes, growable in place."""

    __slots__ = ("visits", "handshakes", "browser_fps", "tcp_fps", "_port")

    def __init__(self):
        self.visits, self.handshakes, self.browser_fps, self.tcp_fps = [], [], [], []
        self._port = [20000]

    def next_port(self):
        self._port[0] += 1
        return self._port[0]

    def extend(self, other):
        self.visits += other.visits
        self.handshakes += other.handshakes
        self.browser_fps += other.browser_fps
        self.tcp_fps += other.tcp_fps

    def as_tuple(self):
        return self.visits, self.handshakes, self.browser_fps, self.tcp_fps


class CohortState:
    """The attacker's evolving campaign: a pool of proxy identities + shared assets."""

    def __init__(self, tm, rng):
        self.tm = tm
        self.rng = rng
        self.bundle = Bundle()
        # Base (shared) identity assets — used unless an action rotates them.
        self.base_ja4 = f"t13d1516h2_ATTACKER_{rng.randint(1000, 9999)}"
        self.base_canvas = f"canvas_attacker_{rng.randint(1000, 9999)}"
        self.base_fpid = f"fp_attacker_{rng.randint(1000, 9999)}"
        self.base_asn = f"AS{rng.randint(20000, 60000)}"
        self.ips = {}                 # ip -> asset dict
        self.req_counts = {}          # ip -> total requests
        self.t = _BASE_TS
        self.steps = 0

    # -- observation signals -------------------------------------------------
    def n_ips(self):
        return len(self.ips)

    def n_asns(self):
        return len({a["asn"] for a in self.ips.values()})

    def mean_req_per_ip(self):
        return (sum(self.req_counts.values()) / len(self.req_counts)) if self.req_counts else 0.0


class TrafficModel:
    def __init__(self, personas=None, cfg=None, seed=0):
        self.personas = personas or personas_mod.default_personas()
        self.cfg = cfg
        self.rng = random.Random(seed)

    # ---------------------------------------------------------------- cohort
    def new_cohort(self, seed=None):
        rng = random.Random(seed if seed is not None else self.rng.randint(0, 2**31))
        return CohortState(self, rng)

    def realize_step(self, state, dec, cohort_cap):
        """Realize one attacker action into new rows; return a lightweight endpoint
        record for the wave (for the dense consistency reward) + step signals."""
        rng = state.rng
        stack = dec["stack"]
        # Pick or mint the IP this wave touches.
        mint = (dec["rotate_asn"] or dec["rotate_ua"] or dec["identity"] == "rotate_both"
                or state.n_ips() == 0) and state.n_ips() < cohort_cap
        if mint:
            prefix = rng.choice(self._prefixes(stack.ip_flavor))
            ip = _ip(prefix, rng)
            asn = f"AS{rng.randint(20000, 60000)}" if dec["rotate_asn"] else state.base_asn
            ja4 = f"t13d_{rng.randint(0, 10**6)}" if dec["rotate_ua"] else state.base_ja4
            ua, os_fam, plat = _ua_for(stack, rng, vary=dec["rotate_ua"])
            # Device fp: shared across the cohort unless the attacker rotates the
            # whole machine (rotate_both) — keeping it shared while rotating ASN is
            # the proxy-rotator disguise the detector stitches.
            if stack.runs_js:
                canvas = f"canvas_{rng.randint(0, 10**6)}" if dec["identity"] == "rotate_both" else state.base_canvas
                fpid = f"fp_{rng.randint(0, 10**6)}" if dec["identity"] == "rotate_both" else state.base_fpid
            else:
                canvas = fpid = None
            state.ips[ip] = {
                "asn": asn, "ja4": ja4, "ua": ua, "claim_os": stack.claim_os,
                "js_os": plat, "canvas": canvas, "fpid": fpid,
                "webgl": None if not stack.runs_js else (rng.choice(_VM_GPUS) if stack.vm_renderer else rng.choice(_REAL_GPUS)),
                "tells": dict(_STRONG_TELLS) if stack.strong_tell else {},
                "synthetic": stack.synthetic_timing,
                "tcp_os": stack.claim_os if stack.tcp_matches_claim else "Linux",
                "runs_js": stack.runs_js, "ua_kind": stack.ua_kind,
                "fp_emitted": False,
            }
            state.req_counts[ip] = 0
        else:
            ip = rng.choice(list(state.ips.keys()))
        asset = state.ips[ip]

        n = _REQ_PER_STEP[dec["speed_name"]]
        throttled = dec["speed_name"] == "fast" and state.mean_req_per_ip() > 12
        if throttled:
            n = max(1, n // 3)
        path = "/trap/harvest-bait" if dec["take_bait"] else rng.choice(personas_mod.PATHS)
        gaps = _gaps(n, dec["mean_gap_s"], dec["pattern"], rng)
        for g in gaps:
            state.t = state.t + timedelta(seconds=max(0.5, g))
            port = state.bundle.next_port()
            state.bundle.visits.append(_visit_row(ip, asset["ua"], asset["asn"], path, state.t, port))
            state.bundle.handshakes.append(_handshake_row(ip, port, asset["ja4"], state.t))
            state.bundle.tcp_fps.append(_tcp_row(ip, port, asset["tcp_os"], state.t))
            state.req_counts[ip] += 1
        # One browser-fp beacon per IP (first time it runs JS).
        if asset["runs_js"] and not asset["fp_emitted"]:
            asset["fp_emitted"] = True
            state.bundle.browser_fps.append(_bfp_row(ip, asset, state.bundle.next_port(), state.t))

        state.steps += 1
        wave_rec = _wave_endpoint_record(ip, asset, state.req_counts[ip])
        return {
            "endpoint": wave_rec,
            "served_trap": dec["take_bait"],
            "throttled": throttled,
            "content_value": 0.0 if dec["take_bait"] else dec["content_value"] * n,
            "n_requests": n,
            "infra_cost": stack.infra_cost,
        }

    def _prefixes(self, flavor):
        return {
            "datacenter": personas_mod.DATACENTER_PREFIXES,
            "residential": personas_mod.RESIDENTIAL_PREFIXES,
            "cloud": personas_mod.CLOUD_PREFIXES,
        }.get(flavor, personas_mod.DATACENTER_PREFIXES)

    # ------------------------------------------------------------ background
    def sample_background(self, n_endpoints=60, seed=None):
        """A realistic honest+declared+automation backdrop from the personas.

        The endpoint budget is allocated *proportionally* to each persona's base
        rate (not sampled per-pick) so the mix is stable across seeds — otherwise a
        few high-``n_ips`` human picks can crowd out declared/automation entirely.
        """
        rng = random.Random(seed if seed is not None else self.rng.randint(0, 2**31))
        bundle = Bundle()
        total_rate = sum(max(0.01, p.base_rate) for p in self.personas) or 1.0
        for p in self.personas:
            share = max(1, round(n_endpoints * max(0.01, p.base_rate) / total_rate))
            made = 0
            guard = 0
            while made < share and guard < share * 20 + 5:
                guard += 1
                # Each declared/automation "cluster" shares one stack fp + ASN.
                shared_ja4 = f"t13d_{p.label}_{rng.randint(0, 9999)}" if p.shares_ja4 else None
                base_asn = rng.choice(p.asn_pool) if p.asn_pool else str(rng.randint(1000, 60000))
                n_ips = min(share - made, rng.randint(p.n_ips_lo, max(p.n_ips_lo, p.n_ips_hi)))
                for _ in range(n_ips):
                    made += 1
                    self._emit_background_ip(bundle, p, rng, shared_ja4, base_asn)
        return bundle

    def _emit_background_ip(self, bundle, p, rng, shared_ja4, base_asn):
        ua, os_fam, plat = rng.choice(p.uas) if p.uas else ("Mozilla/5.0", "Linux", None)
        prefix = rng.choice(p.ip_prefixes)
        asn = base_asn if p.shares_ja4 else (rng.choice(p.asn_pool) if p.asn_pool else str(rng.randint(1000, 60000)))
        # Honest declared crawlers must originate from their provider's published
        # IP home, so range-verification does NOT flag them as impersonators.
        if p.kind == "declared":
            from crawler_graph.ingest import known_crawlers
            prov = known_crawlers.provider_for_ua(ua)
            if prov and prov in personas_mod.PROVIDER_PREFIXES:
                prefix = personas_mod.PROVIDER_PREFIXES[prov]
        ip = _ip(prefix, rng)
        ja4 = shared_ja4 or f"t13d_uniq_{rng.randint(0, 10**7)}"
        n = rng.randint(p.req_per_ip_lo, max(p.req_per_ip_lo, p.req_per_ip_hi))
        t = _BASE_TS + timedelta(seconds=rng.randint(0, 6 * 3600))
        for g in _gaps(n, p.mean_gap_s, p.gap_kind, rng):
            t = t + timedelta(seconds=max(0.5, g))
            port = bundle.next_port()
            bundle.visits.append(_visit_row(ip, ua, asn, rng.choice(personas_mod.PATHS), t, port))
            bundle.handshakes.append(_handshake_row(ip, port, ja4, t))
            bundle.tcp_fps.append(_tcp_row(ip, port, os_fam, t))
        if rng.random() < p.runs_js:
            asset = {"ua": ua, "claim_os": os_fam, "js_os": plat,
                     "canvas": f"canvas_bg_{rng.randint(0, 10**7)}",
                     "fpid": f"fp_bg_{rng.randint(0, 10**7)}",
                     "webgl": rng.choice(_REAL_GPUS), "tells": {}, "synthetic": False}
            bundle.browser_fps.append(_bfp_row(ip, asset, bundle.next_port(), t))


# --------------------------------------------------------------------- rows
def _visit_row(ip, ua, asn, uri, ts, port):
    return {"id": None, "ts": ts.isoformat(), "site": "site-001", "client_ip": ip,
            "client_port": port, "user_agent": ua, "method": "GET", "uri": uri, "asn": asn,
            "headers": {"user-agent": ua, "accept": "*/*", "accept-language": "en-US"}}


def _handshake_row(ip, port, ja4, ts):
    return {"ts": ts.isoformat(), "src_ip": ip, "src_port": port, "ja3": None,
            "ja4": ja4, "sni": "site-001.dukecodeplus.example"}


def _tcp_row(ip, port, os_guess, ts):
    return {"ts": ts.isoformat(), "src_ip": ip, "src_port": port, "ttl": None,
            "win_size": None, "win_scale": None, "mss": None, "os_guess": os_guess,
            "ja4t": "synthetic"}


def _bfp_row(ip, asset, port, ts):
    tells = dict(asset.get("tells") or {})
    if asset.get("webgl") in _VM_GPUS:
        tells["swRenderer"] = True
    return {"ts": ts.isoformat(), "site": "site-001", "client_ip": ip, "client_port": port,
            "user_agent": asset["ua"], "phase": "load", "fp_id": asset.get("fpid"),
            "canvas_hash": asset.get("canvas"), "webgl_hash": (asset.get("canvas") or "") + "_gl",
            "webgl_vendor": None, "webgl_renderer": asset.get("webgl"), "audio_hash": None,
            "font_hash": None, "navigator": {"platform": asset.get("js_os")} if asset.get("js_os") else {},
            "automation": {**{k: True for k in tells}, "score": 2 if tells else 0},
            "behavior": {"synthetic": bool(asset.get("synthetic")),
                         "interacted": not bool(asset.get("synthetic"))}}


def _wave_endpoint_record(ip, asset, n_requests):
    """A minimal endpoint record for the *dense* consistency reward, matching the
    fields ``consistency.score_endpoint`` reads (which is the real scorer)."""
    from crawler_graph.ingest import known_crawlers
    ua = asset["ua"]
    return {
        "client_ip": ip,
        "ua_top": ua,
        "js_platform": asset.get("js_os"),
        "tcp_os": [asset["tcp_os"]] if asset.get("tcp_os") else [],
        "webgl_renderers": [asset["webgl"]] if asset.get("webgl") else [],
        "automation_tells": {**(asset.get("tells") or {}),
                             **({"swRenderer": True} if asset.get("webgl") in _VM_GPUS else {})},
        "behavior_synthetic": bool(asset.get("synthetic")),
        "is_browser": known_crawlers.is_browser_ua(ua),
        "is_automated": known_crawlers.looks_automated(ua),
        "has_browser_fingerprint": bool(asset.get("runs_js", asset.get("canvas"))),
        "n_requests": n_requests,
    }
