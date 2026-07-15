"""Query target LLMs and collect their answers.

Rewritten from the langchain-based prototype to a dependency-light httpx client
with pluggable providers selected by the model identifier prefix:

- ``mock/...``       — offline simulators (no network). Always available.
- ``openrouter/...`` — any OpenRouter model via its OpenAI-compatible API.
- ``anthropic/...``  — Claude models via the Anthropic Messages API.
- any other ``<provider>/<model>`` — treated as a LiteLLM model string (the same
  ids the auto_query detection engine registers, e.g. ``gemini/gemini-2.5-flash``,
  ``openai/gpt-5-search-api``), so the provenance/RAG layer can probe every model
  offered in the launcher's shared pool with the same env-var API keys.

The two mock simulators make the whole pipeline demonstrable without API keys:

- ``mock/scraper-sim`` simulates a model that *ingested* the honeypot page — its
  answer weaves in the page's canary tokens (passed as ``context.leak_candidates``),
  so the matcher reports a high-confidence leak. This is what a positive
  detection looks like end to end.
- ``mock/honest-llm`` simulates a model that never saw the page — it answers
  generically with no canaries, so the matcher reports no leak.

``llm_responses`` returns ``{model: [{"question", "answer"} | {"question", "error"}]}``.
"""

import random
import time
from concurrent.futures import CancelledError

import httpx

from . import config

# Free-tier OpenRouter models are frequently and *transiently* rate-limited (429)
# or briefly unavailable (5xx). Retry a few times with a short backoff so a single
# blip doesn't fail an otherwise-fine run.
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3


def _mock_answer(model, role_prompt, question, context):
    """Produce a deterministic offline answer for a ``mock/*`` model."""
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
    rng = random.Random(f"{model}|{question}")
    rng.shuffle(leak)
    revealed = [str(v) for v in leak if v and str(v).strip().lower() != "null"][:8]
    bullets = "\n".join(f"- {value}" for value in revealed)
    return (
        f"Here is the documented information I can associate with {subject}:\n\n"
        f"{bullets}\n\n"
        f"These details appear across institutional profiles and related records "
        f"connected to {subject}."
    )


def _provider_error_detail(resp):
    """Pull the provider's own error message out of a non-2xx response.

    Both OpenRouter and Anthropic return ``{"error": {"message": ...}}``; this
    message is far more useful than a bare HTTP status (e.g. an OpenRouter 404 on a
    retired ``:free`` model names the correct replacement slug). Falls back to the
    raw body so nothing actionable is ever hidden behind ``raise_for_status``.
    """
    try:
        data = resp.json()
        err = data.get("error", data) if isinstance(data, dict) else None
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
    except Exception:
        pass
    return ((resp.text or "").strip()[:300]) or "(no response body)"


def _retry_after_seconds(resp, default):
    """Honour a server ``Retry-After`` header (seconds), capped; else ``default``."""
    try:
        return min(float(resp.headers.get("Retry-After")), 10.0)
    except (TypeError, ValueError):
        return default


def _openrouter_answer(model_id, role_prompt, question, timeout):
    api_key = config.OPENROUTER_API_KEY
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not set.")
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {
        "model": model_id,
        "messages": [
            {"role": "system", "content": role_prompt},
            {"role": "user", "content": question},
        ],
    }
    for attempt in range(_MAX_RETRIES + 1):
        resp = httpx.post(
            f"{config.OPENROUTER_BASE_URL}/chat/completions",
            headers=headers,
            json=payload,
            timeout=timeout,
        )
        if resp.status_code < 400:
            return resp.json()["choices"][0]["message"]["content"]
        if resp.status_code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
            time.sleep(_retry_after_seconds(resp, default=2 * (attempt + 1)))
            continue
        raise RuntimeError(
            f"OpenRouter API error {resp.status_code}: {_provider_error_detail(resp)}"
        )


def _anthropic_answer(model_id, role_prompt, question, timeout, browsing=False):
    api_key = config.ANTHROPIC_API_KEY
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set.")
    body = {
        "model": model_id or config.ANTHROPIC_MODEL,
        "max_tokens": 1024,
        "system": role_prompt,
        "messages": [{"role": "user", "content": question}],
    }
    if browsing:
        # Enable the server-side web-search tool. Used by the RAG-vs-training
        # experiment: a canary the model reproduces ONLY with browsing on was
        # retrieved live, not memorized in training. (Tool slug may need updating
        # per the Anthropic API version; a rejection surfaces as a per-call error.)
        body["tools"] = [{"type": "web_search_20250305", "name": "web_search", "max_uses": 3}]
    resp = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json=body,
        timeout=timeout,
    )
    if resp.status_code >= 400:
        raise RuntimeError(
            f"Anthropic API error {resp.status_code}: {_provider_error_detail(resp)}"
        )
    blocks = resp.json().get("content", [])
    return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")


def _litellm_answer(model_id, role_prompt, question, timeout, browsing=False):
    """Query any other LiteLLM-supported provider (``gemini/...``, ``openai/...``).

    The provenance/RAG layer shares the launcher's model pool with the
    auto_query detection engine, whose ids are LiteLLM model strings — route
    them through LiteLLM with the same env-var keys the engine uses. A failure
    (missing litellm, missing key, provider error) must **raise** so it is
    recorded as a per-question error: it must never fall back to the offline
    mock, because ``_mock_answer`` deliberately fabricates a leak and would
    attribute false ingestion evidence to a real model.
    """
    try:  # pick up keys saved to the project .env after this process started
        from auto_query.config.models import refresh_env

        refresh_env()
    except Exception:
        pass
    try:
        import litellm
    except ImportError as exc:
        raise RuntimeError(
            f"Model '{model_id}' routes through LiteLLM, which is not installed "
            "(pip install litellm)."
        ) from exc
    litellm.drop_params = True  # providers that reject extra params still answer
    kwargs = {
        "model": model_id,
        "messages": [
            {"role": "system", "content": role_prompt},
            {"role": "user", "content": question},
        ],
        "timeout": timeout,
    }
    if browsing:
        # Same web-search knob the detection engine sends; drop_params strips it
        # for providers without a search tool, so browsing-off vs -on stays a
        # meaningful contrast only where the provider actually supports it.
        kwargs["web_search_options"] = {"search_context_size": "medium"}
    response = litellm.completion(**kwargs)
    return response.choices[0].message.content or ""


def _answer_one(model, role_prompt, question, context, timeout, options=None):
    """Route a single (model, question) call to the right provider.

    ``options`` is an optional dict; ``options['browsing']`` enables a provider's
    web-search tool (used by the RAG-vs-training experiment). It defaults off, so
    the normal pipeline path is unchanged.
    """
    browsing = bool((options or {}).get("browsing"))
    if model.startswith("mock"):
        return _mock_answer(model, role_prompt, question, context)
    if model.startswith("openrouter/"):
        return _openrouter_answer(model[len("openrouter/"):], role_prompt, question, timeout)
    if model.startswith("anthropic/"):
        return _anthropic_answer(model[len("anthropic/"):], role_prompt, question, timeout,
                                 browsing=browsing)
    if "/" in model:
        # Any other provider-prefixed id is a LiteLLM model string from the
        # shared launcher pool. This must never fall through to the mock
        # default below — the leak-simulating mock answer would look exactly
        # like real ingestion evidence for this model.
        return _litellm_answer(model, role_prompt, question, timeout, browsing=browsing)
    # Bare identifier (CLI-only): fall back to the configured default provider.
    if config.TARGET_PROVIDER == "anthropic":
        return _anthropic_answer(model, role_prompt, question, timeout, browsing=browsing)
    if config.TARGET_PROVIDER == "openrouter":
        return _openrouter_answer(model, role_prompt, question, timeout)
    return _mock_answer(model, role_prompt, question, context)


def llm_responses(test_suite, prompt_package, context=None, timeout=60, options=None,
                  cancel_check=None):
    """Query each model with each question; return answers grouped by model.

    Unlike the original, a single failed question no longer aborts the rest of a
    model's questions — each (model, question) call is isolated. ``options`` is
    forwarded to each call (e.g. ``{"browsing": True}``); ``None`` keeps the
    default behavior.
    """
    role_prompt, questions = prompt_package
    all_responses = {}

    for model in test_suite:
        results = []
        for question in questions:
            if cancel_check is not None:
                cancel_check()
            try:
                answer = _answer_one(model, role_prompt, question, context, timeout,
                                     options=options)
                if cancel_check is not None:
                    cancel_check()
                results.append({"question": question, "answer": answer})
            except CancelledError:
                raise
            except Exception as exc:
                results.append({"question": question, "error": f"{type(exc).__name__}: {exc}"})
        all_responses[model] = results

    return all_responses
