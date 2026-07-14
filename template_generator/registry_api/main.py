"""
Central Registry API for AI Bot Defender template deduplication.

Provides a black-box interface: callers learn only yes/no — never the full list.

Endpoints:
  POST /claim-title     Atomically reserve a unique title for a category.
  POST /check          Check title / SHA-256 / SimHash collision (returns yes/no).
  POST /register       Atomically check then register a template.
  POST /admin/keys     Create a new per-institution API key (admin only).
  GET  /health         Liveness probe.

Auth:
  Regular endpoints: X-API-Key header (per-institution key issued via /admin/keys).
  Admin endpoint:    X-Admin-Key header (REGISTRY_ADMIN_KEY env var).

Environment variables:
  REGISTRY_DB_PATH    Path to SQLite database file (default: ./registry.db).
  REGISTRY_ADMIN_KEY  Admin key for /admin/keys (default: change-me-admin-key).
  SIMHASH_THRESHOLD   Hamming-distance threshold for near-duplicate detection (default: 38).
  DDG_ENABLED         Set to "0" to disable DuckDuckGo checks (default: "1").
  DDG_TIMEOUT         Seconds to wait per DuckDuckGo request (default: 5).

Run:
  uvicorn main:app --host 0.0.0.0 --port 8000
"""
import hashlib
import json
import os
import random
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

from faker import Faker
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

_fake = Faker("en_US")

REGISTRY_DB = os.environ.get("REGISTRY_DB_PATH", "./registry.db")
ADMIN_KEY = os.environ.get("REGISTRY_ADMIN_KEY", "change-me-admin-key")
SIMHASH_THRESHOLD = int(os.environ.get("SIMHASH_THRESHOLD", "38"))
SIMHASH_BITS = 64
# Set to "0" to disable DuckDuckGo checks (useful for offline testing).
DDG_ENABLED = os.environ.get("DDG_ENABLED", "1") == "1"
DDG_TIMEOUT = int(os.environ.get("DDG_TIMEOUT", "5"))  # seconds per request

app = FastAPI(title="Template Registry API", docs_url=None, redoc_url=None)


# ---------------------------------------------------------------------------
# SimHash  (stdlib only — no extra deps; must match client implementation)
# ---------------------------------------------------------------------------

def _simhash_text(text: str) -> int:
    """Compute a 64-bit SimHash fingerprint from normalized text using 3-word shingles."""
    tokens = re.findall(r"\w+", text.lower())
    shingles = [" ".join(tokens[i : i + 3]) for i in range(len(tokens) - 2)] or tokens
    v = [0] * SIMHASH_BITS
    for shingle in shingles:
        h = int(hashlib.md5(shingle.encode()).hexdigest(), 16)
        for i in range(SIMHASH_BITS):
            v[i] += 1 if (h >> i) & 1 else -1
    fp = 0
    for i in range(SIMHASH_BITS):
        if v[i] > 0:
            fp |= 1 << i
    return fp


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

@contextmanager
def get_db():
    conn = sqlite3.connect(REGISTRY_DB)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _init_db() -> None:
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS templates (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                institution_id TEXT    NOT NULL,
                category       TEXT    NOT NULL,
                title          TEXT    NOT NULL UNIQUE,
                content_hash   TEXT    NOT NULL UNIQUE,
                simhash        INTEGER,
                registered_at  TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS claimed_titles (
                title          TEXT PRIMARY KEY,
                category       TEXT NOT NULL,
                institution_id TEXT NOT NULL,
                claimed_at     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                key            TEXT PRIMARY KEY,
                institution_id TEXT NOT NULL UNIQUE,
                created_at     TEXT NOT NULL
            );
        """)


# ---------------------------------------------------------------------------
# Server-side title generation (mirrors make_static_title in generate_templates.py)
# ---------------------------------------------------------------------------

_CATEGORY_LABEL = {
    "towns": "town", "tourist_locations": "location", "biography": "person",
    "artists": "artist", "movies": "film", "books": "book",
    "historical_figures": "figure", "animals": "species", "political_figures": "figure",
    "universities": "institution", "companies": "company", "languages": "language",
    "cuisine": "dish", "scientists_inventors": "figure", "clothing": "garment",
    "medicine": "condition", "sports_teams": "team", "folklore": "legend",
    "video_games": "game", "religion": "religion",
}


def _generate_title(category: str) -> str:
    """Generate a Faker-based title for the given category — identical logic to
    make_static_title() in generate_templates.py so both sides produce the same
    style of names."""
    label = _CATEGORY_LABEL.get(category, "town")
    if label in ("person", "artist", "figure"):
        return _fake.first_name() + " " + _fake.last_name()
    elif label == "town":
        return _fake.last_name() + random.choice(["ville", "field", "burg", "ton", "ford", " Creek", " Falls"])
    elif label == "location":
        return _fake.last_name() + random.choice([" Pass", " Point", " Cape", " Ridge", " Bay"])
    elif label == "institution":
        return _fake.last_name() + random.choice([" University", " College", " Institute"])
    elif label == "company":
        return _fake.last_name() + random.choice([" Industries", " Partners", " Group", " Corp"])
    elif label == "team":
        return "the " + _fake.city() + " " + random.choice(["Rangers", "Sentinels", "Hawks", "Wolves", "Eagles"])
    elif label == "species":
        return random.choice(["Greater", "Lesser", "Eastern", "Northern"]) + " " + _fake.last_name() + random.choice(["wren", "fin", "cap", "hawk"])
    elif label == "film":
        return random.choice(["The", "A"]) + " " + _fake.last_name() + random.choice([" Shore", " Road", " Hour", " Glass"])
    elif label == "book":
        return "The " + _fake.last_name() + random.choice([" Garden", " Map", " Letter", " Door"])
    elif label == "game":
        return _fake.last_name() + random.choice([" Chronicles", " Protocol", " Veil", " Archive"])
    elif label == "language":
        return _fake.last_name()[:5].capitalize() + random.choice(["ian", "ic", "ese", "ish"])
    elif label == "dish":
        return _fake.last_name() + random.choice([" Stew", " Cake", " Bread", " Soup"])
    elif label == "garment":
        return "the " + _fake.last_name() + random.choice([" Wrap", " Shawl", " Robe", " Cloak"])
    elif label == "condition":
        return _fake.last_name() + random.choice([" Syndrome", " Fever", " Disease", " Disorder"])
    elif label == "legend":
        return "the " + _fake.last_name() + random.choice([" of the Vale", " Wanderer", " of Ashfen"])
    elif label == "religion":
        return _fake.last_name() + random.choice(["ism", "anism", "ism", " Faith"])
    else:
        return _fake.last_name() + "ville"


# ---------------------------------------------------------------------------
# Name blending — portmanteau generator
# ---------------------------------------------------------------------------

def _blend_names(a: str, b: str) -> str:
    """Merge two strings into a portmanteau.

    Takes the first ~60% of 'a' and the last ~40% of 'b', joined and
    capitalised. Both inputs should be single words (no spaces).

    Examples:
        "Harrison" + "Vega"    → "Harrivega"
        "Maple"    + "Thornton" → "Maplerton"
        "Johnson"  + "Cruz"    → "Johnsuz"
    """
    a = a.strip().split()[0]  # use only first word if multi-word
    b = b.strip().split()[-1]  # use only last word if multi-word
    split_a = max(2, int(len(a) * 0.6))
    keep_b = max(2, int(len(b) * 0.4))
    return (a[:split_a] + b[-keep_b:]).capitalize()


def _blend_title(category: str) -> str:
    """Generate a blended (portmanteau) title for the given category.

    Uses two independent Faker surnames as the raw material for blending,
    then attaches the appropriate category suffix. The result sounds
    plausible but is statistically near-impossible to find on the internet.
    """
    label = _CATEGORY_LABEL.get(category, "town")

    def blend() -> str:
        return _blend_names(_fake.last_name(), _fake.last_name())

    if label in ("person", "artist", "figure"):
        # Blend for last name; keep a real first name so it reads naturally.
        return _fake.first_name() + " " + blend()
    elif label == "town":
        return blend() + random.choice(["ville", "field", "burg", "ton", "ford", " Creek", " Falls"])
    elif label == "location":
        return blend() + random.choice([" Pass", " Point", " Cape", " Ridge", " Bay"])
    elif label == "institution":
        return blend() + random.choice([" University", " College", " Institute"])
    elif label == "company":
        return blend() + random.choice([" Industries", " Partners", " Group", " Corp"])
    elif label == "team":
        # Blend the city name component.
        city_blend = _blend_names(_fake.last_name(), _fake.last_name())
        return "the " + city_blend + " " + random.choice(["Rangers", "Sentinels", "Hawks", "Wolves", "Eagles"])
    elif label == "species":
        return random.choice(["Greater", "Lesser", "Eastern", "Northern"]) + " " + blend() + random.choice(["wren", "fin", "cap", "hawk"])
    elif label == "film":
        return random.choice(["The", "A"]) + " " + blend() + random.choice([" Shore", " Road", " Hour", " Glass"])
    elif label == "book":
        return "The " + blend() + random.choice([" Garden", " Map", " Letter", " Door"])
    elif label == "game":
        return blend() + random.choice([" Chronicles", " Protocol", " Veil", " Archive"])
    elif label == "language":
        return blend()[:5].capitalize() + random.choice(["ian", "ic", "ese", "ish"])
    elif label == "dish":
        return blend() + random.choice([" Stew", " Cake", " Bread", " Soup"])
    elif label == "garment":
        return "the " + blend() + random.choice([" Wrap", " Shawl", " Robe", " Cloak"])
    elif label == "condition":
        return blend() + random.choice([" Syndrome", " Fever", " Disease", " Disorder"])
    elif label == "legend":
        return "the " + blend() + random.choice([" of the Vale", " Wanderer", " of Ashfen"])
    elif label == "religion":
        return blend() + random.choice(["ism", "anism", " Faith"])
    else:
        return blend() + "ville"


# ---------------------------------------------------------------------------
# DuckDuckGo existence check
# ---------------------------------------------------------------------------

def _ddg_exists(title: str) -> bool:
    """Return True if DuckDuckGo's Instant Answer API returns any content for
    the quoted title, meaning something with that name likely exists online.

    Uses an exact-phrase search ("<title>") so partial matches are ignored.
    Returns False (safe to use) on any network error so a DDG outage never
    blocks generation.
    """
    if not DDG_ENABLED:
        return False
    import urllib.request
    import urllib.parse
    query = f'"{title}"'
    url = (
        "https://api.duckduckgo.com/?q="
        + urllib.parse.quote(query)
        + "&format=json&no_html=1&skip_disambig=1"
    )
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (registry-api dedup check)"}
        )
        with urllib.request.urlopen(req, timeout=DDG_TIMEOUT) as resp:
            data = json.loads(resp.read())
        # Any of these fields being non-empty means DDG found something.
        has_abstract = bool(data.get("AbstractText", "").strip())
        has_results = bool(data.get("Results", []))
        has_topics = bool(data.get("RelatedTopics", []))
        found = has_abstract or has_results or has_topics
        if found:
            print(f"[ddg] '{title}' found online — will substitute", flush=True)
        return found
    except Exception as exc:
        print(f"[ddg] check failed for '{title}': {exc} — treating as not found", flush=True)
        return False


# ---------------------------------------------------------------------------
# Combined pipeline: blend → DDG verify → claim
# ---------------------------------------------------------------------------

def _find_verified_title(category: str, suggested: str) -> str:
    """Return a title that is:
      1. Not taken in the registry (claimed or registered).
      2. Not found on the internet via DuckDuckGo.

    Tries the suggested title first. If it fails either check, generates
    blended alternatives. Falls back to plain Faker if blending somehow
    exhausts itself (astronomically unlikely).
    """
    candidates = [suggested] + [_blend_title(category) for _ in range(50)]
    for candidate in candidates:
        if not _ddg_exists(candidate):
            return candidate  # DB uniqueness checked by caller inside the transaction
    # Absolute fallback: blended name + short UUID hex suffix
    import uuid
    return _blend_title(category) + f" ({uuid.uuid4().hex[:6]})"


def _is_title_taken(conn, title: str) -> bool:
    """True if the title exists in either claimed_titles or templates."""
    row = conn.execute(
        "SELECT 1 FROM claimed_titles WHERE title = ? "
        "UNION SELECT 1 FROM templates WHERE title = ? LIMIT 1",
        (title, title),
    ).fetchone()
    return row is not None


_init_db()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _require_api_key(x_api_key: str = Header(...)) -> str:
    with get_db() as conn:
        row = conn.execute(
            "SELECT institution_id FROM api_keys WHERE key = ?", (x_api_key,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return row["institution_id"]


def _require_admin_key(x_admin_key: str = Header(...)) -> None:
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class ClaimTitleRequest(BaseModel):
    category: str
    suggested_title: str  # client's preferred title (model-generated); server uses it if free


class CheckRequest(BaseModel):
    title: str
    content_hash: str
    simhash: Optional[int] = None


class RegisterRequest(BaseModel):
    category: str
    title: str
    content_hash: str
    simhash: Optional[int] = None


class CreateKeyRequest(BaseModel):
    institution_id: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/claim-title")
def claim_title(req: ClaimTitleRequest, institution_id: str = Depends(_require_api_key)):
    """
    Atomically reserve a unique title for a category.

    The client sends its preferred (model-generated) title. The server uses it
    if it is free; otherwise generates Faker-based alternatives until one is
    available. Returns the reserved title — guaranteed unique across all
    institutions at the moment of reservation.

    Titles are held in claimed_titles until /register promotes them to templates.
    This prevents races between institutions generating simultaneously.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build a prioritised list of candidates:
    #   1. The model's suggestion (checked first — preferred if unique and not online)
    #   2. Up to 200 blended titles generated on demand
    # DDG check happens outside the DB transaction (network call; can be slow).
    # DB uniqueness check happens inside the transaction (atomic).
    suggested = req.suggested_title.strip()

    def _iter_candidates():
        # Try the suggestion first, then an unlimited stream of blended titles.
        yield suggested
        while True:
            yield _blend_title(req.category)

    candidate = None
    was_suggestion = False
    for raw_candidate in _iter_candidates():
        if _ddg_exists(raw_candidate):
            print(f"[claim-title] '{raw_candidate}' exists online, trying next", flush=True)
            continue
        # DDG says it's not online — now atomically check + claim in the DB.
        with get_db() as conn:
            if not _is_title_taken(conn, raw_candidate):
                conn.execute(
                    "INSERT INTO claimed_titles (title, category, institution_id, claimed_at) "
                    "VALUES (?, ?, ?, ?)",
                    (raw_candidate, req.category, institution_id, now),
                )
                candidate = raw_candidate
                was_suggestion = (raw_candidate == suggested)
                break
            # Title passed DDG but is already in the registry — keep iterating.

    return {"title": candidate, "was_suggestion": was_suggestion}


@app.post("/check")
def check(req: CheckRequest, _institution_id: str = Depends(_require_api_key)):
    """
    Returns {"collision": bool, "similarity_warning": bool}.

    collision=True         → title or SHA-256 already registered; caller must retry.
    similarity_warning=True → content is a near-duplicate (SimHash distance ≤ threshold);
                              caller should retry to generate more distinct content.
    The response never reveals which entry triggered the match.
    """
    with get_db() as conn:
        # 1. Exact title or hash match.
        row = conn.execute(
            "SELECT id FROM templates WHERE title = ? OR content_hash = ?",
            (req.title, req.content_hash),
        ).fetchone()
        if row:
            return {"collision": True, "similarity_warning": False}

        # 2. SimHash fuzzy match.
        if req.simhash is not None:
            rows = conn.execute(
                "SELECT simhash FROM templates WHERE simhash IS NOT NULL"
            ).fetchall()
            for r in rows:
                if _hamming(req.simhash, r["simhash"]) <= SIMHASH_THRESHOLD:
                    return {"collision": False, "similarity_warning": True}

    return {"collision": False, "similarity_warning": False}


@app.post("/register")
def register(req: RegisterRequest, institution_id: str = Depends(_require_api_key)):
    """
    Atomically check and register a template.

    Returns {"ok": true} on success, 409 Conflict if a collision is detected
    between the /check call and this write (race condition guard).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_db() as conn:
        row = conn.execute(
            "SELECT id FROM templates WHERE title = ? OR content_hash = ?",
            (req.title, req.content_hash),
        ).fetchone()
        if row:
            raise HTTPException(status_code=409, detail="collision")
        conn.execute(
            """
            INSERT INTO templates
                (institution_id, category, title, content_hash, simhash, registered_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (institution_id, req.category, req.title, req.content_hash, req.simhash, now),
        )
        # Remove from claimed_titles now that it is fully registered.
        conn.execute("DELETE FROM claimed_titles WHERE title = ?", (req.title,))
    return {"ok": True}


@app.post("/admin/keys")
def create_key(
    req: CreateKeyRequest,
    _: None = Depends(_require_admin_key),
):
    """
    Issue a new API key for an institution (admin only).

    Returns the generated key — store it securely; it cannot be retrieved again.
    """
    key = secrets.token_hex(32)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO api_keys (key, institution_id, created_at) VALUES (?, ?, ?)",
                (key, req.institution_id, now),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=409,
                detail=f"Institution '{req.institution_id}' already has an API key",
            )
    return {"institution_id": req.institution_id, "api_key": key}
