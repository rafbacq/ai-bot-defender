"""Configuration for the LLM querying pipeline.

Everything here is overridable per-run by the orchestrator (see ``pipeline.py``)
and falls back to sensible, offline-safe defaults so the package imports and
runs without any API keys configured.
"""

import os
from pathlib import Path

# --- Paths ----------------------------------------------------------------
PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = Path(os.environ.get("PROJECT_ROOT", PACKAGE_DIR.parent))

# Best-effort .env loading for host/CLI *and* container runs.
#
# The app container is started with the API-key vars pre-declared (e.g.
# `OPENROUTER_API_KEY: ${OPENROUTER_API_KEY:-}` in docker-compose.app.yml). When the
# host shell doesn't export them, compose injects an *empty* value that is still
# "present" in os.environ — and python-dotenv's default load_dotenv(override=False)
# refuses to replace an already-present var, so a key sitting in querying/.env would
# be silently ignored (this is exactly the "API key is not set" failure in the UI).
# So we load the .env files ourselves and fill in any var that is unset *or empty*,
# while still letting a genuinely-set shell value take precedence over the file.
# Optional: if python-dotenv isn't installed, env vars must come from the shell.
try:
    from dotenv import dotenv_values

    for _env_path in (PACKAGE_DIR / ".env", PROJECT_ROOT / ".env"):
        if not _env_path.is_file():
            continue
        for _key, _value in dotenv_values(_env_path).items():
            if _value and not os.environ.get(_key):
                os.environ[_key] = _value
except Exception:
    pass
RUNS_DIR = PACKAGE_DIR / "runs"            # persisted query-run JSON files
SAMPLE_GROUND_TRUTH = PACKAGE_DIR / "jeniffer.csv"  # bundled demo dataset

# --- Querying behaviour ----------------------------------------------------
# How many of the generated retrieval questions to actually send per run.
MAX_PROBES = int(os.environ.get("QUERY_MAX_PROBES", 3))
# A best-match Jaccard score at or above this counts as a confirmed leak.
HIGH_RISK_THRESHOLD = float(os.environ.get("QUERY_HIGH_RISK_THRESHOLD", 0.3))

# --- Providers -------------------------------------------------------------
# Target-model provider: "mock" (offline demo), "openrouter", or "anthropic".
TARGET_PROVIDER = os.environ.get("QUERY_TARGET_PROVIDER", "mock")
# Extractor provider: "mock", "openai" (OpenAI-compatible), or "anthropic".
EXTRACTOR_PROVIDER = os.environ.get("QUERY_EXTRACTOR_PROVIDER", "mock")

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = os.environ.get(
    "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"
)
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
# Default to the latest, most capable Claude model for AI features.
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-fable-5")

# OpenAI-compatible extractor endpoint (the original used a Duke-internal one).
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
EXTRACTOR_MODEL = os.environ.get("QUERY_EXTRACTOR_MODEL", "gpt-4.1")

# --- Training-data provenance / membership inference (Direction 6b) --------
PROVENANCE_DIR = PACKAGE_DIR / "provenance"     # persisted provenance reports
# Membership-inference backend: "mock" (offline), "hf" (local logits), "openai".
MEMBERSHIP_BACKEND = os.environ.get("QUERY_MEMBERSHIP_BACKEND", "mock")
MEMBERSHIP_MODEL = os.environ.get("QUERY_MEMBERSHIP_MODEL", "gpt2")
MEMBERSHIP_K = float(os.environ.get("QUERY_MEMBERSHIP_K", "0.2"))    # Min-K% fraction
MEMBERSHIP_ALPHA = float(os.environ.get("QUERY_MEMBERSHIP_ALPHA", "0.01"))  # p-value cutoff

# Default set of target models offered in the UI. The "mock/*" entries always
# work offline; the others require the matching provider + API key.
DEFAULT_TARGET_MODELS = [
    "mock/scraper-sim",
    "mock/honest-llm",
    # OpenRouter rotates which models are offered on the free tier, and each free
    # endpoint is independently and *transiently* rate-limited (429) when congested —
    # so the choice here is a moving target. gpt-oss-120b was fully serving at the time
    # of writing; if it starts failing, swap in another live free slug (the run error
    # now reports the real reason) or add credit to remove free-tier rate limits.
    "openrouter/openai/gpt-oss-120b:free",
    "anthropic/claude-fable-5",
]
