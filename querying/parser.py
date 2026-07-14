"""Scrape an HTML page and derive a structured ``website_record``.

Refactored from the original prototype to be location-independent and robust:

- A single HTTP request (the original made two), with an optional ``host_header``
  so a local honeypot served by the nginx reverse proxy can be reached at
  ``http://127.0.0.1/`` while still carrying its real ``Host``.
- spaCy named-entity recognition is used when available, but the module degrades
  gracefully to a lightweight heading/title heuristic when spaCy (or its English
  model) is not installed — so the pipeline still runs on a minimal environment.
- Entity-list keys are plural (``organizations``, ``works`` …) to match what the
  extractor and matcher expect.
"""

import re
import sys

import requests
from bs4 import BeautifulSoup

# spaCy is optional. Loading the model is expensive, so do it lazily and cache.
_NLP = None
_SPACY_TRIED = False


def _get_nlp():
    """Return a loaded spaCy pipeline, or ``None`` if spaCy is unavailable."""
    global _NLP, _SPACY_TRIED
    if _SPACY_TRIED:
        return _NLP
    _SPACY_TRIED = True
    try:
        import spacy

        _NLP = spacy.load("en_core_web_sm")
    except Exception:
        _NLP = None
    return _NLP


def parser(target_url, host_header=None, verify=True, timeout=10):
    """Fetch ``target_url`` and return a structured record of its content.

    ``host_header`` overrides the ``Host`` header (used to reach a honeypot via
    the local reverse proxy). ``verify=False`` accepts the proxy's self-signed
    TLS cert. Returns ``{}`` on a failed fetch.
    """
    headers = {"User-Agent": "AIBotDefender-Probe/1.0"}
    if host_header:
        headers["Host"] = host_header
    try:
        response = requests.get(
            target_url, headers=headers, timeout=timeout, verify=verify
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"parser: error fetching {target_url}: {exc}", file=sys.stderr)
        return {}

    soup = BeautifulSoup(response.text, "html.parser")

    text = clean_text(soup)
    record = get_variables(text)
    record["main_idea"] = get_main_idea(soup) or _title_subject(soup)
    record["top_anchors"] = get_headings(soup)
    return record


def _title_subject(soup):
    """Heuristic subject from <title>/<h1> when NER is unavailable.

    The honeypot pages title themselves like "About Jennifer Balef"; strip the
    leading "About"/"Profile of" boilerplate to recover the subject name.
    """
    title = soup.title.text.strip() if soup.title else ""
    h1 = soup.find("h1")
    candidate = (h1.get_text().strip() if h1 else "") or title
    candidate = re.sub(
        r"^(about|profile of|biography of|the)\s+", "", candidate, flags=re.I
    ).strip()
    return candidate or None


def get_main_idea(soup):
    """Return the most salient PERSON/ORG/LOC from the title + first heading."""
    nlp = _get_nlp()
    if nlp is None:
        return None

    title_text = soup.title.text if soup.title else ""
    h1_tag = soup.find("h1")
    h1_text = h1_tag.text if h1_tag else ""
    doc = nlp(f"{title_text} {h1_text}")

    found = {"PERSON": None, "ORG": None, "LOC": None}
    for ent in doc.ents:
        if ent.label_ == "PERSON":
            found["PERSON"] = ent.text.strip()
        elif ent.label_ == "ORG":
            found["ORG"] = ent.text.strip()
        elif ent.label_ in ("GPE", "LOC"):
            found["LOC"] = ent.text.strip()
    return found["PERSON"] or found["ORG"] or found["LOC"]


def clean_text(soup):
    """Strip script/style and collapse the page into one whitespace-normalized string."""
    for tag in soup(["script", "style"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ", strip=True).split())


def get_headings(soup):
    """Return non-empty h1–h6 text in document order."""
    headings = []
    for heading in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
        text = heading.get_text().strip()
        if text:
            headings.append(text)
    return headings


def get_variables(text):
    """Extract entity lists from page text.

    Uses spaCy NER when available; otherwise returns empty entity lists (the
    pipeline still works from ``main_idea`` + ``top_anchors`` alone).
    Keys are plural to match the extractor/matcher contract.
    """
    empty = {
        "people": [],
        "cities": [],
        "locations": [],
        "institutions": [],
        "organizations": [],
        "works": [],
        "unique_phrases": [],
    }
    nlp = _get_nlp()
    if nlp is None or not text:
        return empty

    doc = nlp(text)
    buckets = {key: [] for key in empty}
    for ent in doc.ents:
        value = ent.text.strip()
        if ent.label_ in ("CARDINAL", "DATE", "TIME", "PERCENT", "QUANTITY"):
            continue
        if len(value) <= 2:
            continue
        if ent.label_ == "PERSON":
            buckets["people"].append(value)
        elif ent.label_ == "ORG":
            buckets["organizations"].append(value)
        elif ent.label_ == "GPE":
            buckets["cities"].append(value)
        elif ent.label_ == "LOC":
            buckets["locations"].append(value)
        elif ent.label_ in ("PRODUCT", "EVENT", "WORK_OF_ART"):
            buckets["works"].append(value)
        elif ent.label_ == "FAC":
            buckets["institutions"].append(value)
        else:
            buckets["unique_phrases"].append(value)

    # Deduplicate while preserving first-seen order (stable output).
    return {key: list(dict.fromkeys(values)) for key, values in buckets.items()}
