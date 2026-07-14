"""Internal OpenAI client for the framework's own processing steps.

Attribute generation, schema generation, and content extraction all run
through this client (GPT-4.1: these components expect structured,
deterministic outputs). It is separate from the *target* models being
evaluated — those go through LiteLLM (``llm_client_litellm``).

Key: ``OPENAI_API_KEY_INTERNAL``. Optional base URL: ``OPENAI_API_BASE_INTERNAL``
(Azure / Duke-hosted / other OpenAI-compatible deployments).

Integration change vs. the branch: the client is created lazily via
``get_client()`` instead of at import time, and returns ``None`` when the key
(or the ``openai`` package) is absent — callers then use their deterministic
offline fallbacks, so importing this package never requires a key.
"""

import os

# The model id the internal steps use ("GPT 4.1" on the branch — not a valid
# API id; a real call would 400).
INTERNAL_MODEL = os.environ.get("OPENAI_MODEL_INTERNAL", "gpt-4.1")

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # dotenv is a convenience, not a requirement
    pass

_client = None
_client_tried = False


def internal_key():
    return os.environ.get("OPENAI_API_KEY_INTERNAL", "")


def get_client():
    """Return the internal OpenAI client, or ``None`` when unavailable."""
    global _client, _client_tried
    if _client_tried:
        return _client
    _client_tried = True

    api_key = internal_key()
    if not api_key:
        return None
    try:
        from openai import OpenAI
    except ImportError:
        return None

    kwargs = {"api_key": api_key}
    base_url = os.environ.get("OPENAI_API_BASE_INTERNAL")
    if base_url:
        kwargs["base_url"] = base_url
    _client = OpenAI(**kwargs)
    return _client
