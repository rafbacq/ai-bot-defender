"""Honeypot canary tokens + visitor identification (the core detection mechanism).

The honeypot's whole premise: every unique visitor — keyed by
``(User-Agent, ASN)`` — is served a *stable, unique* set of fabricated canary
tokens, and every visit is logged with a full breakdown of who the visitor is.
If those canaries later surface in an LLM's output, a specific scraper ingested
the page.

This module exercises the two real, importable halves of that mechanism:

  * the **canary generators** — the exact Faker expressions in
    ``website/varLists/scraper<N>.txt``, evaluated the way ``server.py:gen_vars``
    evaluates them (with a Faker that has the project's edu/food providers), and
  * the **visitor identifier** — ``website/user_agent_info.parse_user_agent``,
    the real parser ``server.py`` uses to record each visit.

The per-visitor assignment state machine (stable-per-key, unique-across-keys,
"Null" when generation is off) is ``server.py:update_page``'s documented
contract; ``server.py`` itself isn't import-safe (it opens a Postgres connection
at import), so we drive that contract through a faithful in-memory model that
calls the *real* generators + identifier. A live-stack integration check of the
literal ``server.py`` is left to the opt-in ``integration`` tier.
"""

from __future__ import annotations

import glob
import os

import pytest


# --- Real canary generator, mirroring server.py:gen_vars -------------------
def _make_faker():
    from faker import Faker
    import faker_edu
    from faker_food import FoodProvider

    fake = Faker("en_US")
    fake.add_provider(faker_edu.Provider)
    fake.add_provider(FoodProvider)
    return fake


def _varlist_lines(repo_root, version):
    path = repo_root / "website" / "varLists" / f"scraper{version}.txt"
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()][:10]


def _gen_set(fake, lines):
    """Evaluate one varList into a 10-tuple of canary strings (as server.py does)."""
    return tuple(str(eval(expr, {"fake": fake})) for expr in lines)


def _versions(repo_root):
    out = []
    for path in glob.glob(str(repo_root / "website" / "varLists" / "scraper*.txt")):
        stem = os.path.basename(path)[len("scraper"):-len(".txt")]
        if stem.isdigit():
            out.append(int(stem))
    return sorted(out)


def test_every_scraper_varlist_yields_ten_nonempty_canaries(repo_root):
    """Each scraper flavor's varList evaluates to 10 non-empty canary values."""
    versions = _versions(repo_root)
    assert versions, "expected at least one scraper varList"
    fake = _make_faker()
    for version in versions:
        lines = _varlist_lines(repo_root, version)
        assert len(lines) >= 10, f"scraper{version}.txt must define >=10 canary generators"
        values = _gen_set(fake, lines)
        assert len(values) == 10
        for i, value in enumerate(values, 1):
            assert value and value.strip() and value != "Null", \
                f"scraper{version} var{i} produced an empty canary from {lines[i - 1]!r}"


def test_canary_sets_are_high_entropy_across_many_visitors(repo_root):
    """Generating canary sets for many visitors yields almost-entirely-unique sets,
    so distinct scrapers receive distinguishable tokens (the keying premise)."""
    fake = _make_faker()
    lines = _varlist_lines(repo_root, 1)
    sets = [_gen_set(fake, lines) for _ in range(400)]
    unique = set(sets)
    # Real Faker variety should keep full-set collisions rare.
    assert len(unique) >= 0.97 * len(sets), f"only {len(unique)}/{len(sets)} canary sets were unique"
    # Per-slot variety: no single slot collapses to one constant value.
    for slot in range(10):
        distinct = {s[slot] for s in sets}
        assert len(distinct) > 1, f"canary slot {slot + 1} produced a constant value"


def test_user_agent_parser_identifies_browsers_bots_and_mobile(website_on_path):
    """The real visitor identifier extracts browser/OS/device class from diverse UAs."""
    from user_agent_info import parse_user_agent

    cases = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36":
            {"browser_family": "Chrome", "os_family": "Windows", "is_pc": True, "is_mobile": False},
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15":
            {"browser_family": "Safari", "os_family": "Mac OS X", "is_pc": True, "is_mobile": False},
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1":
            {"os_family": "iOS", "is_mobile": True, "is_pc": False},
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36":
            {"os_family": "Android", "is_mobile": True},
    }
    for ua, expected in cases.items():
        info = parse_user_agent(ua, session_id=None)
        for key, want in expected.items():
            assert info[key] == want, f"{key}={info[key]!r} (wanted {want!r}) for UA {ua[:40]!r}"

    # A non-browser scraper UA still parses without error (identity recorded, even
    # if the UA library doesn't classify it as a known browser).
    bot = parse_user_agent("Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)", None)
    assert bot["is_mobile"] is False and bot["is_pc"] is False

    # A null UA degrades to all-None instead of raising (server.py relies on this).
    blank = parse_user_agent(None, None)
    assert blank["browser_family"] is None and blank["os_family"] is None


# --- Faithful model of server.py:update_page's documented contract ---------
class HoneypotModel:
    """In-memory model of the honeypot's per-visitor canary assignment.

    Mirrors ``server.py:update_page``: every request is appended to a visit log
    with its parsed identity; a NEW ``(user_agent, asn)`` gets a freshly generated,
    de-duplicated canary set (when generation is on) while a returning visitor
    reuses its stored set and bumps ``view_count``; with generation off, every
    visitor is served ``"Null"`` and nothing is stored.
    """

    def __init__(self, fake, lines, parse_ua, genmode=True):
        self._fake = fake
        self._lines = lines
        self._parse_ua = parse_ua
        self._genmode = genmode
        self.agents = {}          # (user_agent, asn) -> {"vars": (...), "view_count": int}
        self.visits = []          # append-only identity log
        self._seen_sets = set()

    def _fresh_set(self):
        for _ in range(50):
            values = _gen_set(self._fake, self._lines)
            if values not in self._seen_sets:
                self._seen_sets.add(values)
                return values
        return values  # extremely unlikely; accept a dup rather than loop forever

    def visit(self, user_agent, asn):
        info = self._parse_ua(user_agent, session_id=None)
        self.visits.append({"user_agent": user_agent, "asn": asn,
                            "browser_family": info["browser_family"],
                            "os_family": info["os_family"], "is_pc": info["is_pc"]})
        if not self._genmode:
            return tuple(["Null"] * 10)
        key = (user_agent, asn)
        entry = self.agents.get(key)
        if entry is None:
            entry = {"vars": self._fresh_set(), "view_count": 0}
            self.agents[key] = entry
        entry["view_count"] += 1
        return entry["vars"]


def _diverse_visitors():
    """A varied fleet of (user_agent, asn) visitors for the simulation."""
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
        "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
        "python-requests/2.31.0",
    ]
    asns = ["20473", "399358", "7018", "AS-PROXY-1"]
    return [(ua, asn) for ua in uas for asn in asns]


def test_each_visitor_is_logged_with_full_identity(website_on_path, repo_root):
    """Every simulated request is logged with the parsed who-are-they breakdown."""
    from user_agent_info import parse_user_agent

    model = HoneypotModel(_make_faker(), _varlist_lines(repo_root, 1), parse_user_agent)
    visitors = _diverse_visitors()
    for ua, asn in visitors:
        model.visit(ua, asn)

    assert len(model.visits) == len(visitors)
    # Identity is recorded for every visit (browser bots may classify as None family,
    # but a known browser visit must carry a resolved family + OS).
    chrome_visits = [v for v in model.visits if "Chrome/126" in v["user_agent"]]
    assert chrome_visits and all(v["browser_family"] == "Chrome" for v in chrome_visits)
    assert all(v["os_family"] == "Windows" for v in chrome_visits)


def test_canaries_are_stable_per_visitor_and_unique_across_visitors(website_on_path, repo_root):
    """Same (UA, ASN) always gets the same canary set (and bumps view_count);
    distinct visitors get distinct sets — the honeypot's stability+uniqueness law."""
    from user_agent_info import parse_user_agent

    model = HoneypotModel(_make_faker(), _varlist_lines(repo_root, 1), parse_user_agent)
    visitors = _diverse_visitors()

    first = {key: model.visit(*key) for key in visitors}
    # Revisit every visitor three more times.
    for _ in range(3):
        for key in visitors:
            assert model.visit(*key) == first[key], f"canary set changed for {key}"

    # view_count reflects all four visits per unique key.
    assert all(entry["view_count"] == 4 for entry in model.agents.values())
    # Distinct (UA, ASN) visitors received distinct canary sets.
    assert len(set(first.values())) == len(visitors)
    # A new ASN for an already-seen UA is a NEW visitor with a NEW set.
    chrome = visitors[0][0]
    assert model.visit(chrome, "99999") != first[(chrome, visitors[0][1])]


def test_generation_off_serves_null_and_stores_nothing(website_on_path, repo_root):
    """With generation disabled, every visitor is served all-"Null" and no canary
    rows are minted (the ``server.py nogen`` mode)."""
    from user_agent_info import parse_user_agent

    model = HoneypotModel(_make_faker(), _varlist_lines(repo_root, 1), parse_user_agent, genmode=False)
    for ua, asn in _diverse_visitors():
        assert model.visit(ua, asn) == tuple(["Null"] * 10)
    assert model.agents == {}, "no canary sets should be stored when generation is off"
    assert len(model.visits) == len(_diverse_visitors()), "visits are still logged in nogen mode"
