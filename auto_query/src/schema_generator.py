"""Generate an extraction schema from a site's Faker template.

For each faker expression the schema records the semantic category and exact
format of the values it produces; the content extractor uses those
descriptions to spot canary-shaped strings in a model's answer. Runs on the
internal GPT-4.1 client; falls back to a deterministic per-expression
description derived from the faker provider names when no
``OPENAI_API_KEY_INTERNAL`` is configured.
"""

import json
import re

from auto_query.src.openai_client import INTERNAL_MODEL, get_client

# Faker provider -> human description, for the offline schema. Ordered:
# first match wins within an expression's parts.
_FAKER_DESCRIPTIONS = [
    ("institution_name", "the name of a university or educational institution"),
    ("first_name_female", "a feminine first name"),
    ("first_name_male", "a masculine first name"),
    ("first_name", "a first name"),
    ("last_name", "a family name / surname"),
    ("name", "a person's full name"),
    ("city", "a city or town name"),
    ("country", "a country name"),
    ("state", "a state or region name"),
    ("street_address", "a street address"),
    ("company", "a company or organization name"),
    ("job", "a job title"),
    ("year", "a four-digit year"),
    ("date", "a date"),
    ("dish", "the name of a food dish"),
    ("ingredient", "a food ingredient"),
    ("fruit", "a fruit name"),
    ("word", "a single word"),
    ("catch_phrase", "a short phrase"),
]


def _describe_expression(expression):
    """Deterministic description of one faker expression (offline fallback)."""
    parts = []
    for provider, description in _FAKER_DESCRIPTIONS:
        if provider in expression and description not in parts:
            parts.append(description)
    if not parts:
        return "a short generated text value"
    joined = " combined with ".join(parts)
    if "+" in expression or "," in expression:
        return f"{joined} (a single combined string, exactly as written)"
    return joined


def _heuristic_schema(template_text):
    """No-key fallback: one schema entry per non-empty faker template line."""
    variables = []
    for line in (template_text or "").splitlines():
        expression = line.strip()
        if not expression:
            continue
        variables.append({
            "expression": expression,
            "description": _describe_expression(expression),
        })
    return {"variables": variables}


def generate_schema(template_text):

    client = get_client()
    if client is None:
        return _heuristic_schema(template_text)

    prompt = f"""
Analyze the following Faker template.

For each expression:

1. Infer the semantic category of information.

2. Describe the exact format the expression is going to be in eg  hyphenated, capital letters

Return JSON only.

Format:

{{
    "variables": [
        {{
            "expression": "...",
            "description": "..."
        }}
    ]
}}

Template:

{template_text}
"""

    response = client.responses.create(model=INTERNAL_MODEL, input=prompt)

    # --- RAILBLOCKS START ---
    # Extract text from the response safely
    raw_text = getattr(response, 'output_text', '') or ''
    raw_text = raw_text.strip()

    if not raw_text:
        print("[ERROR] The model returned an empty response for the faker template.")
        return _heuristic_schema(template_text)

    # Strip out markdown backticks if the model wrapped the JSON block
    cleaned_text = re.sub(r"^```json\s*|\s*```$", "", raw_text, flags=re.IGNORECASE).strip()

    try:
        schema = json.loads(cleaned_text)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse JSON from response. Raw response was:\n{raw_text}")
        print(f"Decoder Error details: {e}")
        # Fall back to the deterministic per-expression schema
        return _heuristic_schema(template_text)
    # --- RAILBLOCKS END ---

    return schema
