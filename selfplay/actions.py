"""The attacker's factored (MultiDiscrete) action space.

Each of the four factors maps to concrete inputs of the production detector's
feature vector (``crawler_graph.ml.features.FEATURE_NAMES``) and, crucially, to the
*cost-to-evade ladder* encoded in ``crawler_graph.analysis.consistency`` +
``graphing.campaigns``. The ``stack`` factor is the heart of it: each preset is a
rung on that ladder — cheaper rungs trip a specific contradiction; defeating it
costs real infrastructure (``infra_cost``), which is what the learned agent must
trade against harvest under the detection budget.

An action is a 4-tuple of ints ``(identity, timing, fetch, stack)``.
"""

from dataclasses import dataclass

# ---- factor 0: identity rotation ------------------------------------------
IDENTITY = ["keep", "rotate_ua", "rotate_asn", "rotate_both"]

# ---- factor 1: timing (speed x pattern) -----------------------------------
SPEEDS = {"fast": 4.0, "human": 60.0, "slow": 600.0}      # mean inter-arrival seconds
PATTERNS = ["regular", "poisson", "bursty"]
TIMING = [(s, p) for s in SPEEDS for p in PATTERNS]        # 9 combos

# ---- factor 2: which links to follow --------------------------------------
FETCH = ["high_value", "low_value", "take_bait"]


# ---- factor 3: client-stack posture (the cost-to-evade ladder) ------------
@dataclass(frozen=True)
class StackPreset:
    name: str
    ua_kind: str            # "browser" | "declared" | "automation"
    claim_os: str           # "Windows" | "Apple" | "Linux" — OS the UA/platform claims
    runs_js: bool           # emit a browser-fp beacon (fp.js)
    strong_tell: bool       # trips a STRONG automation tell (webdriver/cdc/...)
    vm_renderer: bool       # WebGL renderer is a software/VM adapter
    tcp_matches_claim: bool # the client kernel (SYN) matches the claimed OS
    ip_flavor: str          # "datacenter" | "residential" | "cloud"
    synthetic_timing: bool  # behavioral biometrics look synthetically humanized
    infra_cost: float       # relative $ / effort the attacker pays for this rung
    rung: int               # position on the ladder (0 = cheapest)


# Ordered cheapest -> most expensive. Comments name the signal each rung *trips*
# (from consistency.score_endpoint / campaigns._summarize) that the next rung fixes.
STACK_PRESETS = [
    StackPreset("declared_ua",      "declared",   "Linux",   False, False, False, True,  "datacenter",  False, 0.00, 0),
    #  ^ honest-looking bot UA; attributed (and range_violation if outside ranges)
    StackPreset("nonjs_scraper",    "browser",    "Windows", False, False, False, False, "datacenter",  False, 0.05, 1),
    #  ^ browser UA, never runs JS -> browser_no_js contradiction
    StackPreset("headless_js",      "browser",    "Windows", True,  True,  True,  False, "datacenter",  False, 0.20, 2),
    #  ^ runs JS but leaks webdriver/cdc + software renderer -> automation + vm_cohort
    StackPreset("stealth_patched",  "browser",    "Windows", True,  False, True,  False, "datacenter",  True,  0.45, 3),
    #  ^ tells patched, but VM WebGL + datacenter kernel != Windows + regular timing
    StackPreset("real_gpu_dc",      "browser",    "Windows", True,  False, False, False, "datacenter",  False, 0.65, 4),
    #  ^ real GPU/browser fp, but datacenter SYN says Linux vs claimed Windows -> os_ua_vs_tcp
    StackPreset("resi_consistent",  "browser",    "Windows", True,  False, False, True,  "residential", False, 1.00, 5),
    #  ^ real browser on residential IP whose kernel matches the claim: fully consistent (priciest)
]

ACTION_DIMS = [len(IDENTITY), len(TIMING), len(FETCH), len(STACK_PRESETS)]


def decode(action):
    """Decode a 4-tuple of ints into a semantic dict the traffic model consumes."""
    a = [int(x) for x in action]
    ident = IDENTITY[a[0] % len(IDENTITY)]
    speed_name, pattern = TIMING[a[1] % len(TIMING)]
    fetch = FETCH[a[2] % len(FETCH)]
    stack = STACK_PRESETS[a[3] % len(STACK_PRESETS)]
    return {
        "identity": ident,
        "rotate_ua": ident in ("rotate_ua", "rotate_both"),
        "rotate_asn": ident in ("rotate_asn", "rotate_both"),
        "speed_name": speed_name,
        "mean_gap_s": SPEEDS[speed_name],
        "pattern": pattern,
        "fetch": fetch,
        "take_bait": fetch == "take_bait",
        "content_value": {"high_value": 1.0, "low_value": 0.25, "take_bait": 0.1}[fetch],
        "stack": stack,
    }
