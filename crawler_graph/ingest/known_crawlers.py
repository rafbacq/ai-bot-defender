"""Declared crawler signatures + provider attribution.

Two kinds of ground truth about *honest* crawlers:

1. **User-Agent patterns** — the documented bot UAs (GPTBot, ClaudeBot, …). A
   match attributes the visitor to a provider with no fingerprinting needed.
2. **Published IP ranges** (optional, loaded from ``crawler_ranges.json``) — the
   CIDR blocks providers publish for their crawlers. A visitor that *claims* a
   crawler UA but originates **outside** that provider's declared ranges is the
   classic impersonation / disguise signal.

``is_browser_ua`` marks "looks like a human browser, not a declared bot" — the
population where agentic AI browsers hide, and where TLS/JA fingerprints (not the
UA) do the work.
"""

import ipaddress
import json
import re

# Declared crawler User-Agents -> provider. Checked in order; first match wins.
CRAWLER_UA_PATTERNS = [
    (re.compile(r"GPTBot", re.I), "OpenAI"),
    (re.compile(r"OAI-SearchBot", re.I), "OpenAI"),
    (re.compile(r"ChatGPT-User", re.I), "OpenAI"),
    (re.compile(r"ClaudeBot", re.I), "Anthropic"),
    (re.compile(r"anthropic-ai", re.I), "Anthropic"),
    (re.compile(r"Claude-User|Claude-Web|Claude-SearchBot", re.I), "Anthropic"),
    (re.compile(r"PerplexityBot|Perplexity-User", re.I), "Perplexity"),
    (re.compile(r"Google-Extended", re.I), "Google"),
    (re.compile(r"Googlebot|Storebot-Google|Google-InspectionTool|GoogleOther", re.I), "Google"),
    (re.compile(r"Bingbot|BingPreview|msnbot|adidxbot", re.I), "Microsoft/Bing"),
    (re.compile(r"Applebot", re.I), "Apple"),
    (re.compile(r"Amazonbot", re.I), "Amazon"),
    (re.compile(r"Bytespider", re.I), "ByteDance"),
    (re.compile(r"CCBot", re.I), "CommonCrawl"),
    (re.compile(r"Meta-ExternalAgent|Meta-ExternalFetcher|facebookexternalhit|FacebookBot", re.I), "Meta"),
    (re.compile(r"DuckAssistBot|DuckDuckBot", re.I), "DuckDuckGo"),
    (re.compile(r"YouBot", re.I), "You.com"),
    (re.compile(r"cohere-ai", re.I), "Cohere"),
    (re.compile(r"Diffbot", re.I), "Diffbot"),
    (re.compile(r"Timpibot", re.I), "Timpi"),
    (re.compile(r"omgili|webzio", re.I), "Webz.io"),
]

# A request that looks like a real browser engine *and* carries no declared bot
# UA. Agentic AI browsers (Atlas, Comet, Claude for Chrome, …) live here.
BROWSER_UA_RE = re.compile(r"Mozilla/5\.0.*(Chrome/|Safari/|Firefox/|Edg/|Gecko/)", re.I)

# Hints that a browser-UA visitor is an automation/agent rather than a person.
AGENT_UA_HINTS = re.compile(
    r"(Headless|Electron|PhantomJS|puppeteer|playwright|python-requests|"
    r"Go-http-client|node-fetch|axios|httpx|aiohttp|curl|wget|Java/|okhttp)", re.I)


def provider_for_ua(ua):
    """Return the declared provider for a crawler UA, or ``None``."""
    if not ua:
        return None
    for pattern, provider in CRAWLER_UA_PATTERNS:
        if pattern.search(ua):
            return provider
    return None


def is_declared_crawler(ua):
    return provider_for_ua(ua) is not None


def is_browser_ua(ua):
    """True if the UA looks like a human browser and is not a declared bot."""
    return bool(ua and BROWSER_UA_RE.search(ua) and provider_for_ua(ua) is None)


def looks_automated(ua):
    """True if the UA betrays automation tooling (non-browser client libs)."""
    return bool(ua and AGENT_UA_HINTS.search(ua))


# --- Version-insensitive claimed identity (disguise counting) ---------------
# Browser identities group by ENGINE + OS, not shell brand. The device fp_id
# hashes engine-rendered surfaces (canvas / WebGL / audio / fonts / platform)
# and nothing browser-brand specific, so Chrome and Edge on one Windows machine
# (both Blink on the same GPU) legitimately mint the SAME fp_id — a dual-browser
# user must not read as a disguise. Conversely one fp_id claiming two *engines*
# (Chrome + Firefox) is a real spoof: an actual Firefox would have minted a
# different fp_id, so at least one UA is lying. On iOS every browser is WebKit
# (CriOS/FxiOS/EdgiOS are shells over the system engine), so iOS UAs all map to
# webkit. HeadlessChrome stays its OWN identity: headed -> headless is a
# deliberate change of claimed client, not a brand choice.
_IOS_UA_RE = re.compile(r"iPhone|iPad|iPod|CriOS/|FxiOS/|EdgiOS/", re.I)
_ENGINE_PATTERNS = [
    ("headlesschrome", re.compile(r"\bHeadlessChrome/", re.I)),
    ("gecko", re.compile(r"\bFirefox/", re.I)),
    ("chromium", re.compile(r"\b(Chrome|Chromium|Edg(e|A)?|OPR|Opera|SamsungBrowser)/", re.I)),
    ("webkit", re.compile(r"\bSafari/", re.I)),
]
# First product token of a tool-style UA ("curl/8.18.0" -> "curl").
_TOOL_TOKEN_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)/")


def ua_identity(ua):
    """The version-insensitive identity a User-Agent *claims* (a short string).

    Raw-string UA counting flagged every real visitor whose browser auto-updated
    (``Edg/149`` -> ``Edg/150`` is the same Edge on the same Windows install one
    update later) as a device "wearing multiple identities". Identity rotation —
    the actual disguise signal — is a change of *claimed engine, OS, or client
    kind*, never of version digits or of the shell brand around one engine. So:

      * a declared crawler identifies by its provider   -> ``"bot:Google"``
      * a browser by engine family + OS family          -> ``"chromium:Windows"``
        (Chrome = Edge = Opera on one Windows box; iOS shells all -> webkit)
      * a tool/library by its product token             -> ``"curl"``
      * anything unrecognized by its raw string (conservative: genuinely
        distinct claims still count separately).

    What still counts as separate identities on one device: a second engine
    (chromium vs gecko/webkit), a different claimed OS, headed vs
    ``HeadlessChrome``, browser vs tool, or a declared-bot UA. Version/brand
    rotation within one engine is deliberately NOT flagged at the device layer;
    it still surfaces at the campaign layer (UA counts, TLS/JA4 cohesion)."""
    if not ua:
        return ""
    provider = provider_for_ua(ua)
    if provider:
        return f"bot:{provider}"
    if BROWSER_UA_RE.search(ua):
        if _IOS_UA_RE.search(ua):
            engine = "webkit"
        else:
            engine = next((name for name, pat in _ENGINE_PATTERNS if pat.search(ua)), "browser")
        # Lazy import: analysis.consistency only depends on config, so there is
        # no cycle — but keep the ingest layer import-safe if analysis moves.
        try:
            from ..analysis.consistency import os_from_ua
            os_family = os_from_ua(ua) or "?"
        except Exception:
            os_family = "?"
        return f"{engine}:{os_family}"
    tool = _TOOL_TOKEN_RE.match(ua)
    if tool:
        return tool.group(1).lower()
    return ua.strip().lower()


# --- Published IP-range verification (optional) ----------------------------
_RANGES_CACHE = None


def load_ranges(path):
    """Load ``{provider: [CIDR, ...]}`` from JSON; ``{}`` if absent/invalid.

    Providers publish these (e.g. OpenAI's gptbot.json); drop the merged file at
    ``crawler_graph/crawler_ranges.json`` to enable IP-range verification. The
    file is intentionally optional and not vendored, because the ranges change.
    """
    global _RANGES_CACHE
    if _RANGES_CACHE is not None:
        return _RANGES_CACHE
    networks = {}
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
        for provider, cidrs in raw.items():
            nets = []
            for cidr in cidrs or []:
                try:
                    nets.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    continue
            if nets:
                networks[provider] = nets
    except (OSError, json.JSONDecodeError, AttributeError):
        networks = {}
    _RANGES_CACHE = networks
    return networks


def ip_in_declared_ranges(ip, provider, ranges):
    """True if ``ip`` is inside ``provider``'s declared CIDRs.

    Returns ``None`` (unknown) when we have no published ranges for that provider
    — so callers can distinguish "verified outside" from "can't verify".
    """
    nets = (ranges or {}).get(provider)
    if not nets:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return any(addr in net for net in nets)
