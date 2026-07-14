"""Normalize a target model's free-text answer into structured fields.

A second LLM (the "extractor") turns the unstructured target answer into lists
of people, locations, organizations, works, and unique phrases — the shape the
matcher compares against the honeypot's canary tokens.

Provider is selected by ``config.EXTRACTOR_PROVIDER``:

- ``mock``      — offline heuristic extraction (parses bullet lines / segments).
- ``openai``    — any OpenAI-compatible chat endpoint (the original used a
  Duke-internal one via ``OPENAI_API_BASE``).
- ``anthropic`` — Claude via the Messages API.

Returns a dict whose list-valued fields are what ``matcher`` scores. Always
returns lists (not semicolon strings) so evidence is never silently dropped.
"""

import json
import re
import sys

import httpx

from . import config

CATEGORIES = ["people", "locations", "organizations", "works", "unique_phrases"]

_EXTRACT_INSTRUCTION = (
    "Extract concrete, verbatim entities from the text below. "
    "Return ONLY a JSON object with these keys, each a list of strings: "
    "people, locations, organizations, works, unique_phrases. "
    "Copy values exactly as written; do not paraphrase, summarize, or invent. "
    "Use empty lists where nothing applies.\n\nTEXT:\n"
)


def _mock_extract(answer):
    """Heuristic offline extraction: recover bullet items and segmented values."""
    values = []
    for line in answer.splitlines():
        line = line.strip()
        match = re.match(r"^[-*•]\s+(.*)$", line)
        if match:
            values.append(match.group(1).strip())
    # Also split obvious comma/semicolon lists inside any non-bullet prose lines.
    if not values:
        for chunk in re.split(r"[;\n]", answer):
            chunk = chunk.strip()
            if chunk and len(chunk) <= 80:
                values.append(chunk)
    values = [v for v in dict.fromkeys(values) if v]
    result = {key: [] for key in CATEGORIES}
    result["unique_phrases"] = values
    return result


def _llm_extract_json(answer):
    """Call a real extractor LLM and parse its JSON object response."""
    prompt = _EXTRACT_INSTRUCTION + answer

    if config.EXTRACTOR_PROVIDER == "anthropic":
        if not config.ANTHROPIC_API_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY is not set.")
        resp = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": config.ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": config.ANTHROPIC_MODEL,
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=60,
        )
        resp.raise_for_status()
        blocks = resp.json().get("content", [])
        raw = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    else:  # openai-compatible
        if not config.OPENAI_API_KEY:
            raise RuntimeError("OPENAI_API_KEY is not set.")
        resp = httpx.post(
            f"{config.OPENAI_API_BASE}/chat/completions",
            headers={"Authorization": f"Bearer {config.OPENAI_API_KEY}"},
            json={
                "model": config.EXTRACTOR_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
            },
            timeout=60,
        )
        resp.raise_for_status()
        raw = resp.json()["choices"][0]["message"]["content"]

    match = re.search(r"\{.*\}", raw, re.DOTALL)
    data = json.loads(match.group(0) if match else raw)
    return {key: list(data.get(key) or []) for key in CATEGORIES}


def extract_info(aibot_response):
    """Turn one target-model answer into structured, list-valued fields."""
    if not aibot_response or not aibot_response.strip():
        return {key: [] for key in CATEGORIES}

    if config.EXTRACTOR_PROVIDER == "mock":
        return _mock_extract(aibot_response)

    try:
        return _llm_extract_json(aibot_response)
    except Exception as exc:
        print(f"extractor: extraction failed ({exc}); falling back to heuristic.", file=sys.stderr)
        return _mock_extract(aibot_response)
