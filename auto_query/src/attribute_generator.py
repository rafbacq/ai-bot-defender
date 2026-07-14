"""Infer the attribute categories missing from the template's masked contexts.

Looks at text statements containing missing information (like "was born in
_____") and infers the categories or attributes of data that are missing
(e.g., birthplace, employer). Runs on the internal GPT-4.1 client; falls back
to a deterministic keyword heuristic when no ``OPENAI_API_KEY_INTERNAL`` is
configured so the prompt pipeline works offline.
"""

import json

from auto_query.src.openai_client import INTERNAL_MODEL, get_client


def build_attribute_prompt(relationships):  # prompt that we are going to send to llm
    relationship_text = "\n".join(f"- {r}"
         for r in relationships
    )
    return f"""
The following statements contain missing information.

Statements:

{relationship_text}

Your task is to identify what categories of information
appear to be missing.
Return only attribute names.
Examples: parent, birthplace, childhood, location, residence, founder, organization,
merger, partner, institution, employee count, contact email, work title,publication title,
employer, education, patent, location, role, date

Rules:
- Return attribute names only.
- Do not return values.
- Do not explain.
- Do not infer specific names.
- Do not generate biographies.
- Generalize the missing information categories.

Return JSON:
[
  "attribute1",
  "attribute2"
]
"""


# Offline heuristic: masked-context keyword -> attribute category. Ordered so
# the resulting attribute list is deterministic.
_CONTEXT_ATTRIBUTE_HINTS = [
    (("born", "birth"), "birthplace"),
    (("grew up", "childhood", "raised"), "childhood location"),
    (("married", "spouse", "partner", "wife", "husband"), "partner"),
    (("parents", "mother", "father", "daughter of", "son of"), "parent"),
    (("university", "college", "institute", "school", "studied",
      "education", "campus", "degree"), "institution"),
    (("works", "worked", "employed", "employer", "career", "company"), "employer"),
    (("founded", "founder", "established"), "founder"),
    (("lives", "resides", "residence", "moved to", "based in"), "residence"),
    (("wrote", "published", "book", "work", "exhibition", "painting",
      "title"), "notable works"),
    (("award", "prize", "honor"), "award"),
    (("year", "date", "in 1", "in 2"), "date"),
    (("city", "town", "village", "location"), "location"),
    (("name",), "name"),
]

_DEFAULT_ATTRIBUTES = [
    "name", "birthplace", "location", "institution",
    "organization", "partner", "notable works", "date",
]


def _heuristic_attributes(relationships):
    """Deterministic no-key fallback: keyword-scan the masked contexts."""
    contexts = []
    for item in relationships:
        if isinstance(item, dict):
            contexts.append(str(item.get("context", "")).lower())
        else:
            contexts.append(str(item).lower())
    blob = " ".join(contexts)

    attributes = []
    for keywords, attribute in _CONTEXT_ATTRIBUTE_HINTS:
        if any(keyword in blob for keyword in keywords):
            attributes.append(attribute)
    return attributes or list(_DEFAULT_ATTRIBUTES)


def generate_attributes(relationships):
    """
    Looks at text statements containing missing information (like "was born in _____")
    and infers the categories or attributes of data that are missing (e.g., birthplace, employer)
    """

    client = get_client()
    if client is None:
        return _heuristic_attributes(relationships)

    prompt = build_attribute_prompt(relationships)

    try:
        response = client.responses.create(model=INTERNAL_MODEL, input=prompt)
        text = response.output_text.strip()

        try:

            attributes = json.loads(text)

            if isinstance(attributes, list):
                return attributes

        except Exception:
            pass

        lines = [line.strip() for line in text.split("\n") if line.strip()]  # returning each on a new line

        return lines

    except Exception as e:
        print(
            f"Attribute generation failed: {e}"
        )
        return _heuristic_attributes(relationships)
