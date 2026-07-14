"""Paths, logdb access details, and tunables for the crawler-graph package.

Everything is env-overridable so the package behaves the same whether it is run
as a host CLI (talking to the proxy stack via ``docker compose exec``) or inside
the app container (direct psycopg2 connection to ``logdb`` over ``proxy_net``).
"""

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = Path(os.environ.get("PROJECT_ROOT", PACKAGE_DIR.parent))
OUTPUT_DIR = PACKAGE_DIR / "output"
PROXY_COMPOSE = PROJECT_ROOT / "docker-compose.proxy.yml"

# --- logdb (central all_visits + tls_handshakes) ---------------------------
# Matches docker-compose.proxy.yml. When LOGDB_HOST is set (e.g. inside the app
# container, where "logdb" resolves over proxy_net) a direct psycopg2 connection
# is used; otherwise we shell `docker compose exec logdb psql` exactly like
# app/services/request_log.py, which is the portable host path.
LOGDB_SERVICE = "logdb"
LOGDB_USER = os.environ.get("LOGDB_USER", "logger")
LOGDB_NAME = os.environ.get("LOGDB_NAME", "site_logs")
LOGDB_PASS = os.environ.get("LOGDB_PASS", "logger")
LOGDB_HOST = os.environ.get("LOGDB_HOST")  # None -> docker-exec path
LOGDB_PORT = int(os.environ.get("LOGDB_PORT", "5432"))

# --- Analysis window / size guards -----------------------------------------
MAX_VISITS = int(os.environ.get("INTEL_MAX_VISITS", "50000"))
SINCE_HOURS = int(os.environ.get("INTEL_SINCE_HOURS", "0"))  # 0 = no lower bound

# --- Graph edge weights -----------------------------------------------------
# How strongly a *shared* attribute implies "same actor". A shared JA4 is a
# strong signal (same client stack); a shared ASN is weak (millions of unrelated
# hosts share one). Community detection uses these as edge weights.
#
# The device-fingerprint hubs (canvas/webgl/audio/font/fpid) are the Layer-1
# correlation keys from the reference doc: a shared canvas/WebGL/audio hash means
# the SAME physical machine even across IP changes, cleared cookies, and proxy
# rotation — so they are weighted as strongly as a TLS fingerprint. ``ja4h`` is
# the HTTP-header signature (weaker, like a shared exact UA).
EDGE_WEIGHTS = {
    "ja": float(os.environ.get("INTEL_W_JA", "5.0")),       # shared JA3/JA4 hash
    "ua": float(os.environ.get("INTEL_W_UA", "3.0")),       # shared exact User-Agent
    "net": float(os.environ.get("INTEL_W_NET", "3.0")),     # shared /24 (or v6 /64)
    "asn": float(os.environ.get("INTEL_W_ASN", "1.0")),     # shared ASN
    "canvas": float(os.environ.get("INTEL_W_CANVAS", "6.0")),  # shared canvas hash (device)
    "webglfp": float(os.environ.get("INTEL_W_WEBGL", "6.0")),  # shared WebGL hash (device)
    "audio": float(os.environ.get("INTEL_W_AUDIO", "5.0")),    # shared AudioContext hash
    "font": float(os.environ.get("INTEL_W_FONT", "3.0")),      # shared installed-font set
    "fpid": float(os.environ.get("INTEL_W_FPID", "7.0")),      # composite device id (strongest)
    "ja4h": float(os.environ.get("INTEL_W_JA4H", "3.0")),      # shared HTTP-header signature
}
# Drop attribute hubs that connect more than this many endpoints (e.g. a giant
# shared ASN) to keep communities meaningful; 0 disables the cap.
ATTR_HUB_CAP = int(os.environ.get("INTEL_ATTR_HUB_CAP", "400"))

# A high-confidence Jaccard-style cohesion threshold used when flagging disguise.
DISGUISE_MIN_SHARE = float(os.environ.get("INTEL_DISGUISE_MIN_SHARE", "0.5"))
# Mean requests-per-IP above which a cohort reads as *systematic crawling*
# (vs. casual browsing). Separates a stealth crawler (high volume, rotating IPs,
# shared fingerprint) from an agentic-browser population (low volume per user).
SYSTEMATIC_MIN_REQ_PER_IP = float(os.environ.get("INTEL_SYSTEMATIC_MIN_REQ_PER_IP", "8"))

# --- Cross-layer consistency (Layer-1/2/3 contradiction engine) -------------
# WebGL/renderer strings that indicate a virtual display adapter or software
# rasterizer (VM / container / headless / cloud GPU). Per the reference doc,
# fingerprints landing in these cohorts get treated as higher-risk regardless of
# other signal quality. Matched case-insensitively as substrings.
#
# Deliberately narrow to keep false positives off real users: the removed markers
# "software" / "gallium" / "virgl" / "google angle (google, vulkan" all appear in
# legitimate Chrome-on-Linux / Android ANGLE-Vulkan and Mesa renderer strings.
# Genuine software rasterizers are still caught by the specific names below AND by
# the fp.js swRenderer tell (SwiftShader|llvmpipe|Software|Microsoft Basic
# Render|Mesa OffScreen), so nothing real is lost.
VM_RENDERER_MARKERS = [
    "swiftshader", "llvmpipe", "microsoft basic render", "mesa offscreen",
    "angle (software", "vmware", "virtualbox", "vbox", "parallels", "qemu",
    "apple paravirtual", "nvidia grid", "tesla t4", "tesla v100", "tesla m60",
    "amd radeon (tm) instinct",
]
# Automation-tell weighting (fixes "AUTO from a single weak tell"). A STRONG tell
# is on its own conclusive (a real user never trips it); WEAK tells are each
# individually true for legitimate privacy browsers / VMs / in-app WebViews, so we
# require at least WEAK_AUTOMATION_MIN of them before calling a visitor automated.
STRONG_AUTOMATION_TELLS = {"webdriver", "cdc", "headlessua", "tostringtampered"}
WEAK_AUTOMATION_MIN = int(os.environ.get("INTEL_WEAK_AUTOMATION_MIN", "2"))

# --- Identity-rotation / disguise detection ---------------------------------
# A single physical device (same fp_id / canvas / audio hash) that presents under
# multiple User-Agents or from multiple /24 netblocks is wearing more than one
# identity — the disguise signal. (In the local Docker build every visitor shares
# the userland-proxy hop, so netblocks collapse to one and the operator's own
# browser is never flagged; a real rotating crawler spans several.)
DISGUISE_MIN_UAS = int(os.environ.get("INTEL_DISGUISE_MIN_UAS", "2"))
DISGUISE_MIN_NETBLOCKS = int(os.environ.get("INTEL_DISGUISE_MIN_NETBLOCKS", "2"))
# Campaign-level device stitching (one fingerprint dominating a multi-ASN cohort)
# only reads as disguise when the cohort ALSO behaves like infrastructure —
# crawl-volume requests, automation tells, or an ASN footprint beyond what one
# person plausibly roams (home + work + cellular ~= 3). A commuting phone is a
# single stitched device on 2-3 ASNs at casual volume and must not be flagged.
DISGUISE_DEVICE_MIN_ASNS = int(os.environ.get("INTEL_DISGUISE_DEVICE_MIN_ASNS", "4"))
# Score weights for each kind of cross-layer contradiction (higher = stronger
# bot/disguise signal). The OS contradiction (claimed UA OS vs the TCP/IP kernel
# inference) is the spoof-resistant headline signal.
CONSISTENCY_WEIGHTS = {
    "os_ua_vs_tcp": int(os.environ.get("INTEL_C_OS_TCP", "3")),
    "os_js_vs_tcp": int(os.environ.get("INTEL_C_OS_JS_TCP", "3")),
    "os_ua_vs_js": int(os.environ.get("INTEL_C_OS_UA_JS", "2")),
    "vm_cohort": int(os.environ.get("INTEL_C_VM", "2")),
    "automation": int(os.environ.get("INTEL_C_AUTO", "2")),
    "synthetic_behavior": int(os.environ.get("INTEL_C_SYNTH", "1")),
    "browser_no_js": int(os.environ.get("INTEL_C_NOJS", "1")),
}
# An endpoint with a total contradiction score at/above this reads as a
# cross-layer inconsistency (the doc's "internal contradiction" bot signal).
INCONSISTENCY_FLAG_SCORE = int(os.environ.get("INTEL_INCONSISTENCY_SCORE", "3"))
# Trust the SYN-derived OS even from private/loopback client addresses. OFF by
# default because the local build NATs every visitor through the Docker userland
# proxy, so the captured SYN is the proxy host's kernel (every client reads
# "Linux") — flagging a real Windows/macOS browser as an OS spoof. Set to 1 only
# for a genuine same-LAN / source-preserving-DNAT deployment where the client SYN
# reaches the capture intact. See crawler_graph/README.md.
TRUST_TCP_FROM_PRIVATE = bool(int(os.environ.get("INTEL_TRUST_PRIVATE_TCP", "0")))

# --- Persisted artifacts ----------------------------------------------------
ASN_CACHE = OUTPUT_DIR / "asn_cache.json"
CAMPAIGNS_JSON = OUTPUT_DIR / "campaigns.json"
GRAPH_VIZ = OUTPUT_DIR / "campaigns.png"
GRAPH_VIZ_HTML = OUTPUT_DIR / "campaigns_graph.html"  # interactive graph (hover + colors)
GNN_MODEL = OUTPUT_DIR / "gnn_model.pt"
GNN_PREDS = OUTPUT_DIR / "gnn_predictions.json"
CRAWLER_RANGES = PACKAGE_DIR / "crawler_ranges.json"  # optional published CIDRs


def ensure_output_dir():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR
