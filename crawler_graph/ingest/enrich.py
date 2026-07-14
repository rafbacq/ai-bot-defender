"""Enrich raw visit rows and aggregate them into per-endpoint feature records.

Steps:
  1. ``join_fingerprints`` attaches each visit's connection JA3/JA4 from the
     ``tls_handshakes`` rows, joining on the TCP 4-tuple (client_ip, client_port)
     and the most-recent handshake at/before the request — which correctly maps
     one TLS connection (one ClientHello, one fingerprint) to the many requests
     it carried (HTTP/2 multiplexing / keep-alive).
  2. ``enrich_visits`` adds ASN, /24 netblock, declared-provider (from UA), and
     browser/automation flags.
  3. ``aggregate_endpoints`` collapses visits to one record per client IP with
     the request/timing/diversity features the graph and GNN consume.

ASN lookups use ``ipwhois`` (already a project dependency) and are cached to
``output/asn_cache.json`` so repeated runs don't re-hit RDAP. Everything degrades
gracefully if ``ipwhois`` is missing or a lookup fails.
"""

import hashlib
import json
import math
import statistics
from datetime import datetime

from .. import config
from . import known_crawlers

# Headers nginx injects or rewrites on the way to the collector — excluded from
# the JA4H signature so it reflects the client's own header set, not the proxy's.
_PROXY_HEADERS = {
    "x-site", "x-real-ip", "x-client-port", "x-forwarded-for", "x-forwarded-proto",
    "x-forwarded-host", "x-forwarded-port", "connection", "host",
}

_ASN_CACHE = None


def _load_asn_cache():
    global _ASN_CACHE
    if _ASN_CACHE is None:
        try:
            with open(config.ASN_CACHE, encoding="utf-8") as handle:
                _ASN_CACHE = json.load(handle)
        except (OSError, json.JSONDecodeError):
            _ASN_CACHE = {}
    return _ASN_CACHE


def _save_asn_cache():
    if _ASN_CACHE is None:
        return
    try:
        config.ensure_output_dir()
        with open(config.ASN_CACHE, "w", encoding="utf-8") as handle:
            json.dump(_ASN_CACHE, handle)
    except OSError:
        pass


def asn_for_ip(ip):
    """Return ``(asn, asn_description)`` for an IP, cached. ``(None, None)`` on failure."""
    if not ip:
        return None, None
    cache = _load_asn_cache()
    if ip in cache:
        entry = cache[ip]
        return entry.get("asn"), entry.get("descr")
    asn = descr = None
    try:
        from ipwhois import IPWhois

        res = IPWhois(ip).lookup_rdap(depth=0)
        asn = res.get("asn")
        descr = (res.get("asn_description") or "").split(",")[0] or None
    except Exception:
        asn = descr = None
    cache[ip] = {"asn": asn, "descr": descr}
    return asn, descr


def netblock(ip):
    """Derive the network address (IPv4 /24, IPv6 /64-ish) — matches server.py."""
    if not ip:
        return None
    if ":" in ip:  # IPv6 — first 4 hextets
        return ":".join(ip.split(":")[:4])
    return ".".join(ip.split(".")[:3])


def _parse_ts(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def join_fingerprints(visits, handshakes):
    """Attach ja3/ja4/sni to each visit from the matching TLS handshake.

    Join key is (client_ip == src_ip, client_port == src_port), choosing the
    handshake with the greatest ts <= the request ts (handles port reuse).
    Visits without a client_port (un-migrated rows) or without a matching
    handshake simply get ``ja3=ja4=None``.
    """
    by_tuple = {}
    for hs in handshakes or []:
        key = (hs.get("src_ip"), str(hs.get("src_port")) if hs.get("src_port") is not None else None)
        by_tuple.setdefault(key, []).append(hs)
    for entries in by_tuple.values():
        entries.sort(key=lambda h: str(h.get("ts") or ""))

    for visit in visits:
        visit["ja3"] = visit.get("ja3")
        visit["ja4"] = visit.get("ja4")
        visit["sni"] = visit.get("sni")
        port = visit.get("client_port")
        if port is None:
            continue
        key = (visit.get("client_ip"), str(port))
        candidates = by_tuple.get(key)
        if not candidates:
            continue
        vts = str(visit.get("ts") or "")
        chosen = None
        for hs in candidates:  # ascending ts; last one at/before the request
            if str(hs.get("ts") or "") <= vts:
                chosen = hs
            else:
                break
        chosen = chosen or candidates[0]
        visit["ja3"] = chosen.get("ja3")
        visit["ja4"] = chosen.get("ja4")
        visit["sni"] = chosen.get("sni") or chosen.get("server_name")
    return visits


def join_tcp_fingerprints(visits, tcp_fps):
    """Attach the client's TCP/IP-stack OS inference to each visit (Layer 2).

    Same 4-tuple join as the TLS handshake (the page request, its TLS ClientHello,
    and its SYN all share (client_ip, client_port)). Each visit gets ``tcp_os``
    and ``ja4t`` from the matching SYN, or ``None`` when there is no capture.
    """
    by_tuple = {}
    for fp in tcp_fps or []:
        key = (fp.get("src_ip"), str(fp.get("src_port")) if fp.get("src_port") is not None else None)
        by_tuple.setdefault(key, []).append(fp)
    for entries in by_tuple.values():
        entries.sort(key=lambda f: str(f.get("ts") or ""))

    # Also index by IP alone: the SYN for a request's own connection shares the
    # 4-tuple, but a fingerprint may have arrived on a sibling connection from the
    # same host — fall back to the most recent SYN from that IP.
    by_ip = {}
    for fp in tcp_fps or []:
        by_ip.setdefault(fp.get("src_ip"), []).append(fp)
    for entries in by_ip.values():
        entries.sort(key=lambda f: str(f.get("ts") or ""))

    for visit in visits:
        visit["tcp_os"] = visit.get("tcp_os")
        visit["ja4t"] = visit.get("ja4t")
        ip = visit.get("client_ip")
        chosen = None
        port = visit.get("client_port")
        if port is not None:
            chosen = _latest_at_or_before(by_tuple.get((ip, str(port))), visit.get("ts"))
        if chosen is None:
            chosen = _latest_at_or_before(by_ip.get(ip), visit.get("ts"))
        if chosen:
            visit["tcp_os"] = chosen.get("os_guess")
            visit["ja4t"] = chosen.get("ja4t")
    return visits


def _latest_at_or_before(candidates, ts):
    """Pick the candidate with the greatest ts <= the request ts (ascending list)."""
    if not candidates:
        return None
    vts = str(ts or "")
    chosen = None
    for cand in candidates:
        if str(cand.get("ts") or "") <= vts:
            chosen = cand
        else:
            break
    return chosen or candidates[0]


def compute_ja4h(headers, method):
    """A JA4H-style HTTP-header fingerprint from the stored request headers.

    True JA4H hashes the raw client header *ordering*; behind nginx we see a
    partly-normalized view (and exclude the proxy's own injected headers), so
    this is lossy — but the header *set* + count + accept-language + cookie/referer
    presence still differ sharply between real browsers and automation libraries
    (python-requests/Go/curl send a tiny, distinctive header set), which is the
    signal we want. Returns ``None`` when there are no client headers.
    """
    if not isinstance(headers, dict) or not headers:
        return None
    names = [str(k).lower() for k in headers.keys() if str(k).lower() not in _PROXY_HEADERS]
    if not names:
        return None
    m = (method or "GET")[:2].lower()
    has_cookie = "c" if "cookie" in names else "n"
    has_referer = "r" if "referer" in names else "n"
    accept_lang = headers.get("accept-language") or ""
    lang = (accept_lang.split(",")[0].split(";")[0].replace("-", "")[:4] or "0000").lower()
    lang = (lang + "0000")[:4]
    # The ordered header-name list, excluding cookie/referer per JA4H convention.
    name_list = [n for n in names if n not in ("cookie", "referer")]
    digest = hashlib.sha256(",".join(name_list).encode("utf-8", "replace")).hexdigest()[:12]
    return f"{m}{len(name_list):02d}{has_cookie}{has_referer}{lang}_{digest}"


def enrich_visits(visits, resolve_asn=True):
    """Add asn, netblock, provider_ua, is_browser, is_automated, ja4h to each visit."""
    for visit in visits:
        ip = visit.get("client_ip")
        ua = visit.get("user_agent") or ""
        visit["netblock"] = netblock(ip)
        if resolve_asn:
            asn, descr = asn_for_ip(ip)
        else:
            asn, descr = visit.get("asn"), visit.get("asn_descr")
        visit["asn"] = asn
        visit["asn_descr"] = descr
        visit["provider_ua"] = known_crawlers.provider_for_ua(ua)
        visit["is_browser"] = known_crawlers.is_browser_ua(ua)
        visit["is_automated"] = known_crawlers.looks_automated(ua)
        visit["ja4h"] = compute_ja4h(visit.get("headers"), visit.get("method"))
    if resolve_asn:
        _save_asn_cache()
    return visits


def _timing_features(timestamps):
    """Inter-arrival stats + a crude burstiness measure from sorted timestamps."""
    ts = sorted(t for t in timestamps if t is not None)
    if len(ts) < 2:
        return {"mean_gap": None, "std_gap": None, "burstiness": None, "span_s": 0.0}
    gaps = [(ts[i] - ts[i - 1]).total_seconds() for i in range(1, len(ts))]
    mean_gap = statistics.fmean(gaps)
    std_gap = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
    # Burstiness B in [-1, 1]: +1 very bursty, 0 Poisson, -1 perfectly regular.
    burst = ((std_gap - mean_gap) / (std_gap + mean_gap)) if (std_gap + mean_gap) else 0.0
    return {
        "mean_gap": round(mean_gap, 3),
        "std_gap": round(std_gap, 3),
        "burstiness": round(burst, 4),
        "span_s": round((ts[-1] - ts[0]).total_seconds(), 1),
    }


def _entropy(counter):
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    h = 0.0
    for n in counter.values():
        p = n / total
        h -= p * math.log2(p)
    return round(h, 4)


def aggregate_endpoints(visits):
    """Collapse enriched visits to one record per client IP (the graph nodes)."""
    from collections import Counter, defaultdict

    groups = defaultdict(list)
    for visit in visits:
        groups[visit.get("client_ip")].append(visit)

    endpoints = {}
    for ip, rows in groups.items():
        if not ip:
            continue
        uas = Counter(r.get("user_agent") or "" for r in rows)
        paths = Counter(r.get("uri") or "" for r in rows)
        sites = Counter(r.get("site") or "" for r in rows)
        hours = Counter(
            (_parse_ts(r.get("ts")).hour if _parse_ts(r.get("ts")) else -1) for r in rows
        )
        ja3s = {r.get("ja3") for r in rows if r.get("ja3")}
        ja4s = {r.get("ja4") for r in rows if r.get("ja4")}
        ja4hs = {r.get("ja4h") for r in rows if r.get("ja4h")}
        tcp_oses = {r.get("tcp_os") for r in rows if r.get("tcp_os") and r.get("tcp_os") != "unknown"}
        ja4ts = {r.get("ja4t") for r in rows if r.get("ja4t")}
        providers_ua = {r.get("provider_ua") for r in rows if r.get("provider_ua")}
        asn = next((r.get("asn") for r in rows if r.get("asn")), None)
        asn_descr = next((r.get("asn_descr") for r in rows if r.get("asn_descr")), None)
        timing = _timing_features([_parse_ts(r.get("ts")) for r in rows])

        endpoints[ip] = {
            "client_ip": ip,
            "asn": asn,
            "asn_descr": asn_descr,
            "netblock": netblock(ip),
            "n_requests": len(rows),
            "user_agents": dict(uas),
            "ua_top": uas.most_common(1)[0][0] if uas else "",
            "n_user_agents": len(uas),
            "sites": sorted(s for s in sites if s),
            "n_sites": len([s for s in sites if s]),
            "n_paths": len([p for p in paths if p]),
            "path_entropy": _entropy(paths),
            "ua_entropy": _entropy(uas),
            "hour_entropy": _entropy(hours),
            "ja3": sorted(ja3s),
            "ja4": sorted(ja4s),
            "ja4h": sorted(h for h in ja4hs if h),
            "tcp_os": sorted(o for o in tcp_oses if o),
            "ja4t": sorted(t for t in ja4ts if t),
            "has_fingerprint": bool(ja3s or ja4s),
            "providers_ua": sorted(providers_ua),
            "is_declared_crawler": bool(providers_ua),
            "is_browser": any(r.get("is_browser") for r in rows),
            "is_automated": any(r.get("is_automated") for r in rows),
            "first_ts": min((str(r.get("ts")) for r in rows if r.get("ts")), default=None),
            "last_ts": max((str(r.get("ts")) for r in rows if r.get("ts")), default=None),
            **timing,
        }
    return endpoints


def attach_browser_fingerprints(endpoints, browser_fps):
    """Fold Layer-1 browser fingerprints onto the per-IP endpoint records.

    The fp.js beacon arrives on a *separate* connection from the page load, so we
    join by client_ip (same physical visitor, same source IP) rather than the
    4-tuple used for TLS/TCP. Adds the device-correlation keys (canvas/webgl/audio/
    font hashes + the composite fp_id) that stitch one machine across IP changes
    and proxy rotation, plus the WebGL renderer, navigator platform, automation
    tells, and behavioral class the consistency engine consumes. Every endpoint
    gets the fields (defaulted) so the graph + GNN can read them uniformly.
    """
    from collections import defaultdict

    groups = defaultdict(list)
    for fp in browser_fps or []:
        if fp.get("client_ip"):
            groups[fp["client_ip"]].append(fp)

    for ip, rec in endpoints.items():
        rec.setdefault("canvas", [])
        rec.setdefault("webgl_fp", [])
        rec.setdefault("audio", [])
        rec.setdefault("font", [])
        rec.setdefault("fpid", [])
        rec.setdefault("webgl_renderers", [])
        rec.setdefault("js_platform", None)
        rec.setdefault("automation_tells", {})
        rec.setdefault("automation_score", 0)
        rec.setdefault("behavior_synthetic", False)
        rec.setdefault("behavior_interacted", False)
        rec.setdefault("has_browser_fingerprint", False)
        rec.setdefault("n_device_keys", 0)

        fps = groups.get(ip)
        if not fps:
            continue

        canvas = {f.get("canvas_hash") for f in fps if f.get("canvas_hash")}
        webgl = {f.get("webgl_hash") for f in fps if f.get("webgl_hash")}
        audio = {f.get("audio_hash") for f in fps if f.get("audio_hash")}
        font = {f.get("font_hash") for f in fps if f.get("font_hash")}
        fpid = {f.get("fp_id") for f in fps if f.get("fp_id")}
        renderers = {f.get("webgl_renderer") for f in fps if f.get("webgl_renderer")}

        platform = None
        max_auto = 0
        merged_tells = {}
        synthetic = interacted = False
        for f in fps:
            nav = f.get("navigator") or {}
            if not platform and nav.get("platform"):
                platform = nav.get("platform")
            auto = f.get("automation") or {}
            try:
                max_auto = max(max_auto, int(auto.get("score") or 0))
            except (TypeError, ValueError):
                pass
            for key, val in auto.items():
                if val is True:
                    merged_tells[key] = True
            beh = f.get("behavior") or {}
            synthetic = synthetic or bool(beh.get("synthetic"))
            interacted = interacted or bool(beh.get("interacted"))

        rec["canvas"] = sorted(canvas)
        rec["webgl_fp"] = sorted(webgl)
        rec["audio"] = sorted(audio)
        rec["font"] = sorted(font)
        rec["fpid"] = sorted(fpid)
        rec["webgl_renderers"] = sorted(r for r in renderers if r)
        rec["js_platform"] = platform
        rec["automation_tells"] = merged_tells
        rec["automation_score"] = max_auto
        rec["behavior_synthetic"] = synthetic
        rec["behavior_interacted"] = interacted
        rec["has_browser_fingerprint"] = True
        rec["n_device_keys"] = len(canvas) + len(webgl) + len(audio) + len(font) + len(fpid)
    return endpoints
