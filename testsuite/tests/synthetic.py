"""Synthetic crawler/visitor traffic for the AI Bot Defender test suite.

``bot_population`` builds a large, *labeled* mix of the populations the system is
designed to tell apart, in the exact row shapes the real ingest layer consumes:

  * ``visits``       — rows like ``all_visits`` (the proxy request log).
  * ``handshakes``   — rows like ``tls_handshakes`` (Zeek JA4, joined by 4-tuple).
  * ``browser_fps``  — rows like ``browser_fingerprints`` (the fp.js beacon).
  * ``tcp_fps``      — rows like ``tcp_fingerprints`` (the SYN OS inference).
  * ``labels``       — ground truth: population name -> set of client IPs.

Populations (each is a feature the suite must verify end to end):
  declared_*  — honest self-declaring crawlers (GPTBot/ClaudeBot/…): one ASN,
                declared UA, systematic volume -> must attribute, must NOT flag.
  humans      — varied real browsers, UNIQUE device fingerprints, self-consistent
                across UA/JS/TCP layers, scattered ASNs -> must NEVER flag.
  stealth     — a disguised fleet: browser UA across MANY ASNs sharing ONE JA4 at
                crawl volume, and a Linux SYN under a Windows UA -> disguise +
                cross-layer contradiction. (Scales with ``scale`` for stress.)
  agentic     — agentic-browser population: shared JA4, casual volume, fully
                self-consistent -> agentic, NOT disguise.
  rotator     — ONE physical machine (shared canvas + fp_id) hopping ASNs -> must
                stitch into ONE campaign via the device fingerprint.
  vm          — headless/VM cohort (SwiftShader renderer, synthetic behavior) ->
                vm_cohort.

Every routable population uses **public** source IPs on purpose: the consistency
engine only trusts the TCP/IP OS layer for public clients (behind a local NAT the
SYN is the proxy's), so a Windows-UA-vs-Linux-SYN contradiction is only asserted
for publicly-routed crawlers — which is what real crawlers are.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

GPTBOT_UA = "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"
CLAUDEBOT_UA = "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"
GOOGLE_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
PERPLEXITY_UA = "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/bot)"
AMAZON_UA = "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/amazonbot)"

CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
SAFARI_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
FIREFOX_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"
STEALTH_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
AGENTIC_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
HEADLESS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/123.0 Safari/537.36"
# A distinct Chrome build string so the rotator's ONLY tie between its IPs is the
# shared device fingerprint, not an exact-UA hub it happens to share with humans.
ROTATOR_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.7 Safari/537.36"


def bot_population(scale: int = 1, seed: int = 7, site: str = "site-001"):
    """Return ``(visits, handshakes, browser_fps, tcp_fps, labels)``.

    ``scale`` multiplies the disguised stealth fleet (the stress dimension) and is
    floored at 1; ``seed`` makes the whole mix reproducible.
    """
    scale = max(1, int(scale))
    rng = random.Random(seed)
    base = datetime(2026, 6, 1, tzinfo=timezone.utc)
    visits: list[dict] = []
    handshakes: list[dict] = []
    browser_fps: list[dict] = []
    tcp_fps: list[dict] = []
    labels: dict[str, set] = {}
    counters = {"port": 20000}
    fp_seen: set[str] = set()

    def add(ip, ua, ja4, n, asn, *, tcp_os=None, canvas=None, webgl=None, fp_id=None,
            webgl_renderer=None, font=None, platform=None, automation_score=0,
            behavior_synthetic=False, span_seconds=86400):
        for _ in range(n):
            counters["port"] += 1
            port = counters["port"]
            ts = base + timedelta(seconds=rng.randint(0, span_seconds))
            visits.append({
                "id": len(visits) + 1,
                "ts": ts.isoformat(),
                "site": site,
                "client_ip": ip,
                "client_port": port,
                "user_agent": ua,
                "method": "GET",
                "uri": rng.choice(["/", "/about", "/history", "/geography", "/contact"]),
                "headers": {"accept-language": "en-US,en;q=0.9", "accept": "text/html"},
                "asn": asn,
            })
            if ja4:
                handshakes.append({
                    "ts": ts.isoformat(), "src_ip": ip, "src_port": port,
                    "ja3": None, "ja4": ja4, "sni": f"{site}.dukecodeplus.example",
                })
            if tcp_os:
                tcp_fps.append({
                    "ts": ts.isoformat(), "src_ip": ip, "src_port": port,
                    "ttl": None, "win_size": None, "win_scale": None, "mss": None,
                    "os_guess": tcp_os, "ja4t": "synthetic",
                })
        if (canvas or webgl or fp_id or webgl_renderer or font) and ip not in fp_seen:
            fp_seen.add(ip)
            browser_fps.append({
                "ts": (base + timedelta(seconds=rng.randint(0, span_seconds))).isoformat(),
                "site": site, "client_ip": ip, "client_port": counters["port"] + 1,
                "user_agent": ua, "phase": "load", "fp_id": fp_id,
                "canvas_hash": canvas, "webgl_hash": webgl, "webgl_vendor": None,
                "webgl_renderer": webgl_renderer, "audio_hash": None, "font_hash": font,
                "navigator": {"platform": platform} if platform else {},
                "automation": {"score": automation_score} if automation_score else {},
                "behavior": {"synthetic": behavior_synthetic, "interacted": not behavior_synthetic},
            })

    # 1) Declared crawlers — honest, self-declaring. Each is one ASN, many IPs,
    #    systematic volume, public addresses. Two big ones (OpenAI/Anthropic) give
    #    the GNN >=2 labeled classes; a few smaller ones broaden attribution.
    openai_ips = [f"45.10.5.{i}" for i in range(10)]
    for ip in openai_ips:
        add(ip, GPTBOT_UA, "t13d1516h2_GPTBOTSTACK_aaa", rng.randint(20, 40), "20473", tcp_os="Linux")
    labels["declared_openai"] = set(openai_ips)

    anthropic_ips = [f"160.79.10.{i}" for i in range(8)]
    for ip in anthropic_ips:
        add(ip, CLAUDEBOT_UA, "t13d1516h2_CLAUDESTACK_bbb", rng.randint(18, 36), "399358", tcp_os="Linux")
    labels["declared_anthropic"] = set(anthropic_ips)

    google_ips = [f"66.249.66.{i}" for i in range(5)]
    for ip in google_ips:
        add(ip, GOOGLE_UA, "t13d1516h2_GOOGLESTACK_ccc", rng.randint(15, 30), "15169", tcp_os="Linux")
    labels["declared_google"] = set(google_ips)

    perplexity_ips = [f"23.20.4.{i}" for i in range(4)]
    for ip in perplexity_ips:
        add(ip, PERPLEXITY_UA, "t13d1516h2_PPLXSTACK_ddd", rng.randint(12, 24), "14618", tcp_os="Linux")
    labels["declared_perplexity"] = set(perplexity_ips)

    amazon_ips = [f"52.94.7.{i}" for i in range(4)]
    for ip in amazon_ips:
        add(ip, AMAZON_UA, "t13d1516h2_AMZNSTACK_eee", rng.randint(12, 24), "16509", tcp_os="Linux")
    labels["declared_amazon"] = set(amazon_ips)

    # 2) Human browsers — varied UAs, UNIQUE device fingerprints, fully consistent
    #    across UA/JS/TCP layers, low volume, scattered ASNs. Must never be flagged.
    humans = [(CHROME_WIN, "Windows", "Win32"), (SAFARI_MAC, "Apple", "MacIntel"),
              (FIREFOX_LINUX, "Linux", "Linux x86_64")]
    human_ips = []
    for i in range(30):
        ua, tcp_os, platform = humans[i % len(humans)]
        ip = f"73.55.{rng.randint(1, 250)}.{rng.randint(1, 250)}"
        human_ips.append(ip)
        add(ip, ua, f"t13d_unique_{i}", rng.randint(1, 4), f"70{rng.randint(10, 99)}",
            tcp_os=tcp_os, canvas=f"canvas_human_{i}", fp_id=f"fp_human_{i}", platform=platform)
    labels["humans"] = set(human_ips)

    # 3) Disguised stealth fleet — the headline detection target. Windows browser
    #    UA + Win32 platform across MANY ASNs, ONE shared JA4, systematic volume;
    #    the SYN says Linux, contradicting the claimed OS. Scales for stress.
    stealth_ja4 = "t13d1517h2_STEALTHSTACK_zzz"
    stealth_n = 14 * scale
    stealth_ips = []
    for i in range(stealth_n):
        ip = f"104.{20 + (i % 40)}.{1 + (i // 250)}.{1 + (i % 250)}"
        stealth_ips.append(ip)
        add(ip, STEALTH_UA, stealth_ja4, rng.randint(10, 16), f"AS-PROXY-{i % 11}",
            tcp_os="Linux", canvas=f"canvas_stealth_{i}", fp_id=f"fp_stealth_{i}", platform="Win32")
    labels["stealth"] = set(stealth_ips)

    # 4) Agentic browser — shared JA4, many ASNs, CASUAL volume, self-consistent
    #    (Apple UA + MacIntel + Apple SYN, unique device fp). Agentic, not disguise.
    agentic_ja4 = "t13d1518h2_AGENTBROWSER_yyy"
    agentic_ips = []
    for i in range(20):
        ip = f"98.{20 + i}.{rng.randint(1, 250)}.{rng.randint(1, 250)}"
        agentic_ips.append(ip)
        add(ip, AGENTIC_UA, agentic_ja4, rng.randint(1, 3), f"AS-RES-{10 + i}",
            tcp_os="Apple", canvas=f"canvas_agentic_{i}", fp_id=f"fp_agentic_{i}", platform="MacIntel")
    labels["agentic"] = set(agentic_ips)

    # 5) Proxy rotator — ONE machine (shared canvas + fp_id) hopping ASNs. The only
    #    tie between the IPs is the Layer-1 device fingerprint -> ONE campaign.
    rotator_ips = [f"5.5.{i}.{i}" for i in range(6)]
    for i, ip in enumerate(rotator_ips):
        add(ip, ROTATOR_UA, None, rng.randint(3, 5), f"AS-VPN-{i}", tcp_os="Windows",
            canvas="canvas_SHARED_DEVICE", fp_id="fp_SHARED_DEVICE", platform="Win32")
    labels["rotator"] = set(rotator_ips)

    # 6) VM / headless cohort — SwiftShader renderer (software raster), shared font
    #    so they cluster, automation tells + synthetic behavior. vm_cohort.
    vm_ips = [f"6.6.6.{i}" for i in range(6)]
    for i, ip in enumerate(vm_ips):
        add(ip, HEADLESS_UA, None, rng.randint(4, 6), "AS-CLOUD-1", tcp_os="Linux",
            canvas=f"canvas_vm_{i}", fp_id=f"fp_vm_{i}", font="font_VM_SHARED",
            webgl_renderer="Google SwiftShader", platform="Win32",
            automation_score=2, behavior_synthetic=True)
    labels["vm"] = set(vm_ips)

    return visits, handshakes, browser_fps, tcp_fps, labels
