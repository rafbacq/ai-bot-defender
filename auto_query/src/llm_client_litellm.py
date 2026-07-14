"""Query the target models — LiteLLM for real providers, simulators for mock/*.

LiteLLM standardizes the API call across providers, and
``web_search_options`` asks search-enabled models to actually retrieve; any
LiteLLM provider works by exporting its standard API-key env var and adding a
line to ``config/models.py``.

Integration changes vs. the branch:

- ``mock/scraper-sim`` / ``mock/honest-llm`` ids are answered by a
  deterministic offline simulator (ported from ``querying.llm_client``) so the
  engine demos end to end with no keys. The leak candidates ride in via the
  optional ``context`` argument.
- ``litellm`` is imported lazily (only when a real model is queried) so the
  offline path never needs it installed.
- ``drop_params`` is enabled so providers that don't support
  ``web_search_options`` get the plain request instead of a hard error.
- provider failures are **classified** (``classify_error``): an invalid key,
  exhausted credits/quota, a rate limit, a retired model id, and a network
  problem each map to a distinct ``error_kind`` + a human-readable message and
  a "what to do" hint, which the dashboard surfaces per model.
- the project ``.env`` is re-read (``refresh_env``) before every real query,
  so keys saved while the app is running are picked up with no restart.
"""

import random

from auto_query.config.models import provider_of, refresh_env

# Ordered (kind, keywords, hint) — first match wins, so the most specific
# buckets come first. Keywords are matched case-insensitively against the
# exception's type name + message. Quota comes before rate-limit on purpose:
# OpenAI reports "insufficient_quota" through a RateLimitError (429), and
# "out of credits" is the answer the user actually needs.
_ERROR_BUCKETS = [
    ("quota",
     ["insufficient_quota", "insufficient credits", "exceeded your current quota",
      "budgetexceeded", "billing", "credit balance", "purchase credits",
      "payment required", "402"],
     "The account is out of credits/quota — add billing credit, then re-run."),
    ("auth",
     ["authenticationerror", "permissiondenied", "invalid api key", "incorrect api key",
      "invalid x-api-key", "unauthorized", "authentication", "401", "403",
      "api key not valid", "no api key"],
     "The API key is missing or invalid — set or re-save it under Provider API keys."),
    ("rate_limit",
     ["ratelimiterror", "rate limit", "rate_limit", "too many requests", "429",
      "overloaded"],
     "The provider rate-limited this request — wait a moment and re-run."),
    ("model_not_found",
     ["notfounderror", "model_not_found", "does not exist", "unknown model",
      "invalid model", "404"],
     "The model id may be retired or renamed — update auto_query/config/models.py."),
    ("network",
     ["apiconnectionerror", "timeout", "timed out", "connection", "unreachable",
      "temporarily unavailable", "serviceunavailable", "503"],
     "Could not reach the provider — check connectivity and retry."),
]


def classify_error(exc):
    """Map a provider exception to ``(kind, hint)`` for user-facing reporting.

    Works on LiteLLM's OpenAI-style exception types (AuthenticationError,
    RateLimitError, ...) but falls back to message keywords, so raw provider
    errors classify too. Unrecognized errors return ``("provider_error", ...)``.
    """
    haystack = f"{type(exc).__name__} {exc}".lower()
    for kind, keywords, hint in _ERROR_BUCKETS:
        if any(keyword in haystack for keyword in keywords):
            return kind, hint
    return ("provider_error",
            "The provider returned an unexpected error — see the detail and retry.")

# Short human labels for each error kind (shared by the UI).
ERROR_KIND_LABELS = {
    "auth": "API key problem",
    "quota": "Out of credits",
    "rate_limit": "Rate limited",
    "model_not_found": "Model unavailable",
    "network": "Network error",
    "provider_error": "Provider error",
}


def _mock_answer(model, user_prompt, context):
    """Deterministic offline answer for a ``mock/*`` model (no network)."""
    subject = (context or {}).get("subject", "the subject")
    leak = list((context or {}).get("leak_candidates", []))

    if model.endswith("honest-llm") or "honest" in model:
        return (
            f"I do not have verified, specific records about {subject}. "
            "I can only share general, publicly-known context, and I will not "
            "fabricate names, locations, affiliations, or identifiers. "
            "If you need authoritative details, consult primary sources."
        )

    # scraper-sim (default): simulate regurgitating ingested page content.
    rng = random.Random(f"{model}|{user_prompt}")
    rng.shuffle(leak)
    revealed = [str(v) for v in leak if v and str(v).strip().lower() != "null"][:8]
    bullets = "\n".join(f"- {value}" for value in revealed)
    return (
        f"Here is the documented information I can associate with {subject}:\n\n"
        f"{bullets}\n\n"
        f"These details appear across institutional profiles and related records "
        f"connected to {subject}."
    )


def query_model(model, role_prompt, user_prompt, context=None):
   # Queries a single model.
    try:
        if model.startswith("mock/"):
            return {
                "question":
                    user_prompt,
                "answer":
                    _mock_answer(model, user_prompt, context),
            }

        # Pick up keys saved to the project .env since the process started.
        refresh_env()

        import litellm
        from litellm import completion  # standardizes api calls

        # Not every provider accepts web_search_options; drop it (and any other
        # unsupported param) rather than failing the whole model.
        litellm.drop_params = True

        response = completion(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": role_prompt
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
             web_search_options={
                    "search_context_size":
                        "high"
    }
        )

        answer = response.choices[0].message.content #removes fluff and gives back only what i care about

        return {
            "question":
                user_prompt,
            "answer":
                answer

        }

    except Exception as e:

        print()
        print(
            f"[ERROR] {model}"
        )

        print(e)

        kind, hint = classify_error(e)
        label = ERROR_KIND_LABELS.get(kind, "Provider error")

        return {

            "question":
                user_prompt,

            "answer":
                "",

            # Human-readable first line (what happened + which provider),
            # with the classification + raw detail alongside for the UI.
            "error":
                f"{label} ({provider_of(model)}): {hint}",

            "error_kind":
                kind,

            "error_detail":
                str(e)[:500],

        }


def query_models(models, role_prompt, user_prompt, context=None):
    """
    Query every model in MODELS and returns a dictionary of model and its response
    """
    results = {}
    for model_name, model in models.items():

        print()
        print(f"[QUERYING] {model_name}")

        results[model_name] = query_model(model, role_prompt, user_prompt, context=context)

    return results
