"""Parse honeypot HTML into a structured website record.

Takes the HTML of a page (rendered or template), scrapes it for the main idea,
anchors and variables, and returns a dictionary to make prompt generation
easier and more targeted.

Integration change vs. the branch: spaCy is optional. The branch called
``spacy.load("en_core_web_sm")`` unconditionally (twice per parse); here the
pipeline is loaded lazily once and, when spaCy or its model is unavailable, the
subject falls back to a title/heading heuristic (mirroring ``querying.parser``)
so the record always carries a ``main_idea`` key — ``generate_probes`` needs it.
"""

import re

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


def parser(html):
    """
    Takes the HTML of a webpage, scrapes the page for the main idea, anchors of
    the page and variables and returns a dictionary to make prompt generation
    easier and more targeted.
    """

    soup = BeautifulSoup(html, "html.parser")

    main_idea = get_main_idea(soup)
    headings = get_headings(soup)
    text = clean_text(soup)
    website_record = get_variables(text)
    # Always present (possibly None): downstream prompt generation keys on it.
    website_record["main_idea"] = main_idea or _title_subject(soup)
    if headings != []:
        website_record["top_anchors"] = headings
    return website_record


def _title_subject(soup):
    """Heuristic subject from <title>/<h1> when NER is unavailable or silent.

    The honeypot pages title themselves like "About Jennifer Balef"; strip the
    leading "About"/"Profile of" boilerplate to recover the subject name.
    Unrendered template placeholders ({{ var1 }}) are never a usable subject.
    """
    title = soup.title.text.strip() if soup.title else ""
    h1_tag = soup.find("h1")
    candidate = (h1_tag.get_text().strip() if h1_tag else "") or title
    candidate = re.sub(
        r"^(about|profile of|biography of|the)\s+", "", candidate, flags=re.I
    ).strip()
    if "{{" in candidate:
        return None
    return candidate or None


def get_main_idea(soup):
    # Info from title and first heading
    nlp = _get_nlp()
    if nlp is None:
        return None

    if soup.title:
        title_text = soup.title.text
    else:
        title_text = ""
    h1_tag = soup.find("h1")
    h1_text = h1_tag.text if h1_tag else ""

    header_text = f"{title_text} {h1_text}"
    doc = nlp(header_text)

    found_person = None
    found_org = None
    found_location = None

    for ent in doc.ents:
        if ent.label_ == "PERSON":
            found_person = ent.text.strip()
        elif ent.label_ == "ORG":
            found_org = ent.text.strip()
        elif ent.label_ in ["GPE", "LOC"]:
            found_location = ent.text.strip()

    if found_person:
        return found_person
    elif found_org:
        return found_org
    elif found_location:
        return found_location

    return None  # no clear entity


def clean_text(soup):
    for tag in soup(["script", "style"]):  # --> remove tags
        tag.decompose()
    clean_text = soup.get_text(separator=" ", strip=True)
    clean_text = " ".join(clean_text.split())  # --> join into one strip of text
    return clean_text


def get_headings(soup):

    # finds every h1, h2, h3, h4, h5, and h6 tag in order of appearance
    all_headings = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])

    cleaned_headings = []

    for heading in all_headings:
        text = heading.get_text().strip()  # removes blank pages
        if text:
            cleaned_headings.append(text)

    return cleaned_headings


def get_variables(text):
    ##Natural language processor to tag all the names, cities, location, institution
    empty = {
        "people": [],
        "city": [],
        "location": [],
        "institution": [],
        "organization": [],
        "work": [],
        "unique_phrase": [],
    }
    nlp = _get_nlp()
    if nlp is None or not text:
        return empty

    doc = nlp(text)

    people = []
    locations = []
    cities = []
    institutions = []
    works = []
    unique_phrases = []
    organizations = []

    all_entities = []

    for ent in doc.ents:
        clean_text = ent.text.strip()

        # Skip generic numbers/dates
        if ent.label_ in ["CARDINAL", "DATE", "TIME", "PERCENT", "QUANTITY"]:
            continue
        if len(clean_text) <= 2:  # -->assumption that counter doesn't have something meaningful things
            continue

        all_entities.append(clean_text)  # everything into a map

        if ent.label_ == "PERSON":
            people.append(ent.text)
        elif ent.label_ == "ORG":
            organizations.append(ent.text)
        elif ent.label_ == "GPE":
            # cities, countries, states
            cities.append(ent.text)
        elif ent.label_ == "LOC":
            # non-political locations (mountains, rivers, etc.)
            locations.append(ent.text)
        elif ent.label_ == "PRODUCT" or ent.label_ == "EVENT" or ent.label_ == "WORK_OF_ART":
            works.append(ent.text)

        elif ent.label_ == "FAC":  # Facilities (e.g., universities, research labs)
            institutions.append(ent.text)
        else:
            # For other entity types or custom phrases, you can add logic here
            unique_phrases.append(ent.text)

    return {
        ##return a dictionary with type of variable mapped back to its instance in the html webpage
        "people": list(set(people)),
        "city": list(set(cities)),
        "location": list(set(locations)),
        "institution": list(set(institutions)),
        "organization": list(set(organizations)),
        "work": list(set(set(works))),
        "unique_phrase": list(set(unique_phrases)),
    }
