"""Bot-traffic simulation against the *live* honeypot, through the reverse proxy.

Sends real HTTP requests (and fp.js-shaped beacons) for a diverse fleet of
visitors — declared crawlers, real browsers, mobile clients, automation tools,
and a headless/VM bot — each request a normal ``GET /`` carrying the site's
``Host`` header, exactly like a crawler hitting the page. Every UA is suffixed
with a per-run tag so the harness can isolate *its own* traffic in the shared
logs and never depends on or disturbs pre-existing data.

Safe by construction: read-mostly. The only writes are honeypot page views (which
mint canaries — the intended behavior) and fingerprint beacons (benign rows).
No deploys, no DB mutation, no rate-limit pressure (bounded request counts).
"""

from __future__ import annotations

import json
import secrets

import requests

# UA templates. Declared crawlers keep their documented bot token so the system
# attributes them; browsers keep a real engine token; automation keeps its tell.
_PROFILES = [
    # label, ua_template, expected_provider, beacon_flavor
    ("openai",     "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot) {tag}", "OpenAI", None),
    ("anthropic",  "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com) {tag}", "Anthropic", None),
    ("google",     "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html) {tag}", "Google", None),
    ("perplexity", "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/bot) {tag}", "Perplexity", None),
    ("amazon",     "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/amazonbot) {tag}", "Amazon", None),
    ("chrome_win", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 {tag}", None, "clean"),
    ("safari_mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 {tag}", None, "clean"),
    ("firefox_lin","Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0 {tag}", None, "clean"),
    ("iphone",     "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1 {tag}", None, None),
    ("android",    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36 {tag}", None, None),
    ("py_requests","python-requests/2.31.0 {tag}", None, None),
    ("curl",       "curl/8.5.0 {tag}", None, None),
    ("headless_vm","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/123.0 Safari/537.36 {tag}", None, "vm"),
]


def make_tag() -> str:
    """A short, UA-safe per-run marker that matches no crawler/automation pattern."""
    return "AIBDLive" + secrets.token_hex(4)


def _beacon(flavor, label, tag):
    """An fp.js-shaped payload. ``clean`` = a self-consistent real browser;
    ``vm`` = a headless/software-renderer bot with automation + synthetic behavior."""
    base = {
        "v": 1, "phase": "load",
        "fp_id": f"fp_{label}_{tag}", "canvas_hash": f"cv_{label}_{tag}",
        "canvas_winding": True, "webgl_hash": f"wg_{label}_{tag}",
        "webgl_vendor": "Google Inc.", "webgl_shader_ms": 4.2,
        "audio_hash": f"au_{label}_{tag}", "audio_sample": 0.0314,
        "font_hash": f"ft_{label}_{tag}", "fonts": ["Arial", "Calibri"],
        "screen": {"w": 1920, "h": 1080, "dpr": 1},
        "navigator": {"platform": "Win32", "hardwareConcurrency": 8},
    }
    if flavor == "vm":
        base.update({
            "webgl_renderer": "Google SwiftShader",
            "automation": {"score": 3, "webdriver": True, "swRenderer": True},
            "behavior": {"synthetic": True, "interacted": False},
        })
    else:
        base.update({
            "webgl_renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0)",
            "automation": {"score": 0},
            "behavior": {"synthetic": False, "interacted": True},
        })
    return base


def flood(proxy_http, host_header, tag, *, bots=40, timeout=10):
    """Send the bot fleet at the live honeypot through the proxy.

    Returns a summary dict: the tag, per-label UA + counts, the providers we
    declared, and how many page views / beacons were accepted.
    """
    per = max(2, bots // len(_PROFILES))
    session = requests.Session()
    labels: dict[str, dict] = {}
    page_views = 0
    beacons = 0
    providers = set()

    for label, template, provider, flavor in _PROFILES:
        ua = template.format(tag=tag)
        labels[label] = {"ua": ua, "provider": provider, "views": 0, "beacon": bool(flavor)}
        for _ in range(per):
            try:
                resp = session.get(proxy_http + "/", headers={"Host": host_header, "User-Agent": ua},
                                   timeout=timeout)
                if resp.status_code == 200:
                    page_views += 1
                    labels[label]["views"] += 1
            except requests.RequestException:
                pass
        if provider:
            providers.add(provider)
        if flavor:
            try:
                r = session.post(proxy_http + "/__fpbeacon",
                                 headers={"Host": host_header, "User-Agent": ua,
                                          "Content-Type": "application/json"},
                                 data=json.dumps(_beacon(flavor, label, tag)), timeout=timeout)
                if r.status_code in (200, 204):
                    beacons += 1
            except requests.RequestException:
                pass

    return {
        "tag": tag,
        "labels": labels,
        "providers": sorted(providers),
        "page_views": page_views,
        "beacons": beacons,
        "n_uas": len(labels),
        "vm_ua": labels["headless_vm"]["ua"],
        "clean_ua": labels["chrome_win"]["ua"],
    }
