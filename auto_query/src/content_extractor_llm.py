"""Extract likely canary values from a target model's answer.

Uses the schema descriptions generated from the site's faker template to
identify candidate synthetic values inside a model response. Runs on the
internal GPT-4.1 client; falls back to a deterministic bullet/segment
heuristic (the proven ``querying.extractor`` approach) when no
``OPENAI_API_KEY_INTERNAL`` is configured.

Returns a sorted list of normalized (trimmed, lowercased) candidate strings —
the evidence shape ``matcher_v4`` consumes.
"""

import json
import re

from auto_query.src.openai_client import INTERNAL_MODEL, get_client


def _heuristic_extract(response_text):
    """No-key fallback: recover bullet items, else short segmented values."""
    values = []
    for line in response_text.splitlines():
        line = line.strip()
        match = re.match(r"^[-*•]\s+(.*)$", line)
        if match:
            values.append(match.group(1).strip())
    # Also split obvious comma/semicolon lists inside any non-bullet prose lines.
    if not values:
        for chunk in re.split(r"[;\n]", response_text):
            chunk = chunk.strip()
            if chunk and len(chunk) <= 80:
                values.append(chunk)
    return sorted({value.lower() for value in values if value})


def extract_content_llm(
    response_text,
    schema
):
    """
    Uses the schema descriptions generated
    from scraperX.txt to identify likely
    canary values in a model response.
    """

    if not response_text or not response_text.strip():
        return []

    client = get_client()
    if client is None:
        return _heuristic_extract(response_text)

    descriptions = [

        variable["description"]

        for variable

        in schema["variables"]

    ]

    prompt = f"""
You are helping identify synthetic values
inside a model response.

The following descriptions explain the
types of values that may have been generated:

{json.dumps(descriptions, indent=2)}

Model Response:

{response_text}

Task:

Identify every substring that plausibly
matches one of the described value types.

Rules:

- Extract exact strings.
- Do not summarize.
- Do not explain.
- Do not infer values not present.
- Return JSON only.

Format:

{{
    "candidates": [
        "value1",
        "value2",
        "value3"
    ]
}}
"""

    response = client.responses.create(
        model=INTERNAL_MODEL,
        input=prompt
    )

    try:

        output = json.loads(
            response.output_text
        )

        candidates = output.get(
        "candidates",
        []
    )

# ------------------------
# normalize + deduplicate
# ------------------------

        cleaned_candidates = sorted(

            {

                str(x)
                .strip()
                .lower()

                for x in candidates

                if x is not None
                and str(x).strip()

            }

        )

        return cleaned_candidates


    except Exception as e:

        print(
            f"Failed to parse extractor output: {e}"
        )

        return _heuristic_extract(response_text)
