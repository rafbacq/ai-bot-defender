"""Behavioral personas — generative priors for realistic background traffic.

A ``Persona`` is a light, interpretable generative model of one behavioral cohort
(honest declared crawler, ordinary human browser, datacenter automation, …). We
fit personas by **archetype bucketing** of the real ``all_visits`` endpoints
(dependency-light — no sklearn/kmeans): each real endpoint is classified with the
same ``crawler_graph.ingest.known_crawlers`` predicates the detector uses, then we
MLE the per-bucket distributions (UA mix, ASN pool, request volume, timing).

Personas drive the *background* the attacker's cohort is embedded in (so the
cohort-level disguise signals in ``campaigns.py`` have a realistic backdrop) and
are the reference distribution the Phase-0 calibration test matches against. The
attacker's *own* cohort is generated action-by-action by ``traffic_model`` from the
policy, not from a persona.

When there is no / too little real traffic, ``default_personas()`` supplies a
hand-built, plausible set so the machinery is exercisable offline (the calibration
report records ``n_real_endpoints`` so the fidelity claim is honest).
"""

from collections import Counter
from dataclasses import dataclass, field


# Public CIDR /16 prefixes to draw synthetic client IPs from, by flavor. Public &
# routable is required for the TCP-OS contradiction layer to be *active* at all
# (crawler_graph.analysis.consistency.tcp_os_is_trustworthy rejects private IPs).
DATACENTER_PREFIXES = ["104.28", "45.79", "159.65", "167.71", "138.197", "165.227"]
RESIDENTIAL_PREFIXES = ["73.55", "98.42", "71.192", "24.60", "68.100", "174.60"]
CLOUD_PREFIXES = ["34.201", "52.13", "35.180", "13.59", "3.101"]

HUMAN_UAS = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/126.0.0.0 Safari/537.36", "Windows", "Win32"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like "
     "Gecko) Version/17.4 Safari/605.1.15", "Apple", "MacIntel"),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0", "Linux",
     "Linux x86_64"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/125.0.0.0 Edg/125.0.0.0", "Windows", "Win32"),
]

DECLARED_CRAWLERS = [
    ("Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)", "20473", "Linux"),
    ("Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "399358", "Linux"),
    ("Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/bot)", "396982", "Linux"),
    ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "15169", "Linux"),
]

# Providers' *published* IP homes. Honest declared crawlers originate here; an
# attacker wearing a declared UA from anywhere else is an off-range impersonation
# the detector's range-verification catches (known_crawlers.ip_in_declared_ranges).
# The provider names must match crawler_graph.ingest.known_crawlers.provider_for_ua.
PROVIDER_PREFIXES = {
    "OpenAI": "20.15", "Anthropic": "160.79", "Perplexity": "44.221", "Google": "66.249",
}
PROVIDER_CIDRS = {
    "OpenAI": ["20.15.0.0/16"], "Anthropic": ["160.79.0.0/16"],
    "Perplexity": ["44.221.0.0/16"], "Google": ["66.249.0.0/16"],
}


def provider_ranges():
    """Parsed ``{provider: [ip_network,...]}`` for the campaign disguise detector."""
    import ipaddress
    out = {}
    for prov, cidrs in PROVIDER_CIDRS.items():
        nets = []
        for c in cidrs:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                continue
        if nets:
            out[prov] = nets
    return out

PATHS = ["/", "/about", "/history", "/contact", "/people", "/research", "/news"]


@dataclass
class Persona:
    label: str
    kind: str                      # "declared" | "human" | "automation"
    uas: list = field(default_factory=list)          # list[(ua, tcp_os, js_platform)]
    asn_pool: list = field(default_factory=list)
    ip_prefixes: list = field(default_factory=list)
    gap_kind: str = "poisson"      # "poisson" | "regular" | "bursty"
    mean_gap_s: float = 120.0
    req_per_ip_lo: int = 1
    req_per_ip_hi: int = 4
    n_ips_lo: int = 1
    n_ips_hi: int = 4
    runs_js: float = 1.0           # P(the endpoint emits a browser-fp beacon)
    shares_ja4: bool = False       # declared/automation cohorts share a stack fp
    base_rate: float = 1.0

    def draws(self):
        return max(1, round(self.base_rate * 4))


def _archetype(rec):
    if rec.get("providers_ua"):
        return "declared"
    if rec.get("is_automated"):
        return "automation"
    if rec.get("is_browser"):
        return "human"
    return "automation"  # non-browser, non-declared clients look like tooling


def fit_personas(endpoints, min_real=12):
    """Fit personas from real endpoint records. Falls back to defaults when the
    real corpus is too thin (returns ``(personas, n_real)``)."""
    if not endpoints or len(endpoints) < min_real:
        return default_personas(), len(endpoints or {})

    buckets = {"declared": [], "human": [], "automation": []}
    for rec in endpoints.values():
        buckets[_archetype(rec)].append(rec)

    personas = []
    total = sum(len(v) for v in buckets.values()) or 1
    for kind, recs in buckets.items():
        if not recs:
            continue
        uas = Counter()
        asns = Counter()
        volumes = []
        gaps = []
        js = 0
        for r in recs:
            for ua, n in (r.get("user_agents") or {}).items():
                uas[ua] += n
            if r.get("asn"):
                asns[r["asn"]] += 1
            volumes.append(max(1, int(r.get("n_requests", 1))))
            if r.get("mean_gap") is not None:
                gaps.append(float(r["mean_gap"]))
            if r.get("has_browser_fingerprint"):
                js += 1
        vlo = max(1, min(volumes))
        vhi = max(vlo, int(sorted(volumes)[int(0.9 * (len(volumes) - 1))]))
        mean_gap = (sum(gaps) / len(gaps)) if gaps else 120.0
        # Map real UA strings to (ua, tcp_os, platform) triples via the consistency
        # heuristics so synthetic rows carry a self-consistent OS by default.
        from crawler_graph.analysis import consistency as _cons
        ua_triples = []
        for ua, _ in uas.most_common(6):
            os_fam = _cons.os_from_ua(ua) or "Linux"
            plat = {"Windows": "Win32", "Apple": "MacIntel", "Linux": "Linux x86_64"}.get(os_fam)
            ua_triples.append((ua, os_fam, plat))
        personas.append(Persona(
            label=f"real-{kind}",
            kind=kind,
            uas=ua_triples or _default_uas(kind),
            asn_pool=[a for a, _ in asns.most_common(8)] or _default_asns(kind),
            ip_prefixes=_prefixes_for(kind),
            gap_kind="regular" if kind == "declared" else "poisson",
            mean_gap_s=mean_gap,
            req_per_ip_lo=vlo, req_per_ip_hi=vhi,
            runs_js=(js / len(recs)) if recs else (0.0 if kind != "human" else 1.0),
            shares_ja4=(kind == "declared"),
            base_rate=len(recs) / total,
        ))
    return personas, len(endpoints)


def _prefixes_for(kind):
    if kind == "human":
        return RESIDENTIAL_PREFIXES
    if kind == "declared":
        return DATACENTER_PREFIXES
    return CLOUD_PREFIXES


def _default_uas(kind):
    if kind == "human":
        return list(HUMAN_UAS)
    if kind == "declared":
        return [(ua, os_, {"Windows": "Win32", "Apple": "MacIntel", "Linux": "Linux x86_64"}.get(os_))
                for ua, _, os_ in DECLARED_CRAWLERS]
    return [("python-requests/2.31.0", "Linux", None),
            ("Go-http-client/2.0", "Linux", None)]


def _default_asns(kind):
    if kind == "human":
        return ["7018", "7922", "701", "20115"]
    if kind == "declared":
        return [a for _, a, _ in DECLARED_CRAWLERS]
    return ["14061", "16509", "396982", "63949"]


def default_personas():
    """A hand-built, realistic background mix for offline / thin-data runs."""
    return [
        Persona("honest-declared", "declared",
                uas=[(ua, os_, None) for ua, _, os_ in DECLARED_CRAWLERS],
                asn_pool=[a for _, a, _ in DECLARED_CRAWLERS],
                ip_prefixes=DATACENTER_PREFIXES, gap_kind="regular", mean_gap_s=30.0,
                req_per_ip_lo=18, req_per_ip_hi=55, n_ips_lo=4, n_ips_hi=8,
                runs_js=0.0, shares_ja4=True, base_rate=0.30),
        Persona("human-browser", "human",
                uas=list(HUMAN_UAS), asn_pool=_default_asns("human"),
                ip_prefixes=RESIDENTIAL_PREFIXES, gap_kind="bursty", mean_gap_s=240.0,
                req_per_ip_lo=1, req_per_ip_hi=4, n_ips_lo=8, n_ips_hi=16,
                runs_js=1.0, shares_ja4=False, base_rate=0.55),
        Persona("datacenter-automation", "automation",
                uas=_default_uas("automation"), asn_pool=_default_asns("automation"),
                ip_prefixes=CLOUD_PREFIXES, gap_kind="regular", mean_gap_s=60.0,
                req_per_ip_lo=5, req_per_ip_hi=20, n_ips_lo=2, n_ips_hi=5,
                runs_js=0.0, shares_ja4=True, base_rate=0.15),
    ]
