#!/usr/bin/env python3
"""
Generate honeypot HTML templates from the fine-tuned Qwen3 model.

Pipeline (per template):
  1. Load base Qwen3-1.7B + the trained LoRA adapter (from train.py) -- OR, with
     --reprocess, skip the model entirely and rebuild templates from the saved
     raw_<i>.txt model outputs (no torch / GPU / internet required).
  2. Prompt the model once PER SECTION (Overview / History / Geography /
     Demographics) so the page is multi-section prose, the way a real
     Wikipedia-style article is built, not a single paragraph.
  3. Turn the model's prose into a canary-slotted page:
       a. Strip all numbers. Every [[NUM]] placeholder and every leaked literal
          number / coordinate / mojibake artifact is removed entirely. Numbers
          never appear in generated templates -- only noun canary slots are used.
       b. Type-aware slot mapping. Each [[NAME]] is classified by its surrounding
          words into place / person / org and routed to one of the 10 noun slots
          whose Faker expression matches that type, so the grammar reads. The
          town's own name stays {{ var1 }} throughout (title / h1 / footer).
       c. Density trimming. Cap placeholders per section (--max-section-placeholders)
          so each section reads like prose, not a list of substitutions.
  4. Wrap everything in an HTML page with fixed subheadings (Overview, History,
     Geography, Demographics, Notable Landmarks) but all non-structural text --
     footer pattern, meta description, page tagline -- generated fresh per template
     by the model so no two pages share hardcoded copy.

Outputs to template_generator/generated_templates/:
    scraper_gen_<i>.html   -- the deployable template
    scraper_gen_<i>.txt    -- its varList: one faker expression per {{ varN }} slot,
                              same format as website/varLists/scraper1.txt
    raw_<i>.txt            -- the raw per-section model output (for inspection;
                              the input that --reprocess reads back)

Variable slots (always exactly 10, all nouns, all Faker-renderable, and
category-specific so they read naturally and use appropriate anchor words):
    See CATEGORY_SLOT_DEFINITIONS below for per-category details.

Use --base-only to sample from the un-fine-tuned model with few-shot examples.
Use --reprocess to rebuild .html/.txt from existing raw_<i>.txt without loading
the model.
"""
import argparse
import hashlib
import json
import os
import random
import re
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_ADAPTER = HERE / "models" / "Qwen3-1.7B-lora"

# SimHash parameters — must match registry_api/main.py
SIMHASH_BITS = 64
SIMHASH_THRESHOLD = 38  # Hamming-distance limit for near-duplicate detection (~60% of 64 bits)
DEFAULT_DATA = HERE / "data" / "sft.jsonl"
DEFAULT_OUT = HERE / "generated_templates"

PLACEHOLDER_RULE = (
    "Use [[NAME]] for every proper name: people, places, organisations, titles, brands, species, institutions, works, teams, movements, and traditions. "
    "Do NOT include numbers, dates, years, ages, counts, measurements, coordinates, rankings, populations, statistics, percentages, decades, centuries, timelines, or temporal references. "
    "Rewrite sentences to avoid those details entirely. "
    "Write 8-12 natural encyclopaedia sentences across two or three paragraphs, with each paragraph being 3-4 sentences long. "
    "Every sentence must begin with a clear subject and express a complete thought — never start a sentence with a bare verb like 'was', 'were', 'is', or 'are' without a subject. "
    "Each sentence must flow naturally from the previous one — vary sentence length and structure so the prose reads like something a knowledgeable human wrote, not a list of facts. "
    "Do NOT include section headers of any kind (such as 'Taxonomy and naming', 'References', 'External links', 'See also', 'Further reading', 'Notes', 'Sources', 'The following', or any Wikipedia-style heading). "
    "Do NOT include reference lists, Wikipedia markup, citations, brackets, bullet lists, or any fragment that is not a complete grammatical sentence."
)

ANCHORED_PROSE_RULE = (
    "Do NOT use [[NAME]] for canary slots. Use ONLY the required [[VARn]] phrases listed below. "
    "You may refer to the {subject_label} by a plain descriptive phrase without any bracket placeholder. "
    "Do NOT include numbers, dates, years, ages, counts, measurements, coordinates, rankings, "
    "populations, statistics, percentages, decades, centuries, timelines, or temporal references. "
    "Write 12-16 natural encyclopaedia sentences across three paragraphs, with each paragraph being 3-4 sentences long. "
    "Most sentences should be purely descriptive background prose WITHOUT any [[VARn]] token — "
    "only the sentences that contain the required phrases below should have [[VARn]] tokens. "
    "Every sentence must begin with a clear subject and express a complete thought — never start a sentence with a bare verb like 'was', 'were', 'is', or 'are' without a subject. "
    "Each sentence must flow naturally from the previous one — vary sentence length and structure so the prose reads like something a knowledgeable human wrote, not a list of facts. "
    "Do NOT include section headers of any kind (such as 'Taxonomy and naming', 'References', 'External links', 'See also', 'Further reading', 'Notes', 'Sources', 'The following', or any Wikipedia-style heading). "
    "Do NOT include reference lists, Wikipedia markup, citations, brackets, bullet lists, or any fragment that is not a complete grammatical sentence."
)

# ---------------------------------------------------------------------------
# Category definitions.
# has_landmarks: True  -> page gets a 4th "Notable Landmarks" / contextual
#                         section after the 3 main sections.
#               False -> 3 sections only; no landmark section.
#
# landmark_section_name: what to call the 4th section for this category
#   (only used when has_landmarks=True).
# ---------------------------------------------------------------------------
CATEGORIES = {
    "tourist_locations": {
        "subject": "fictional tourist location or landmark",
        "sections": ["history", "description", "significance"],
        "headings": {"history": "History", "description": "Description", "significance": "Significance"},
        "subject_slot_label": "location",
        "has_landmarks": True,
        "landmark_section_name": "Nearby Attractions",
        "landmark_prompt": "a viewing platform, visitor centre, or historic structure near the site",
    },
    "biography": {
        "subject": "fictional person",
        "sections": ["early_life", "career", "legacy"],
        "headings": {"early_life": "Early Life", "career": "Career", "legacy": "Legacy"},
        "subject_slot_label": "person",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "towns": {
        "subject": "fictional U.S. town or small city",
        "sections": ["history", "culture", "economy"],
        "headings": {"history": "History", "culture": "Culture", "economy": "Economy"},
        "subject_slot_label": "town",
        "has_landmarks": True,
        "landmark_section_name": "Notable Landmarks",
        "landmark_prompt": "a historic bridge, an old mill, a town hall, a pioneer cemetery, or a community theatre",
    },
    "artists": {
        "subject": "fictional visual artist",
        "sections": ["early_life", "style", "legacy"],
        "headings": {"early_life": "Early Life", "style": "Style", "legacy": "Legacy"},
        "subject_slot_label": "artist",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "movies": {
        "subject": "fictional film",
        "sections": ["plot", "production", "reception"],
        "headings": {"plot": "Plot", "production": "Production", "reception": "Reception"},
        "subject_slot_label": "film",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "books": {
        "subject": "fictional novel",
        "sections": ["plot", "themes", "reception"],
        "headings": {"plot": "Plot", "themes": "Themes", "reception": "Reception"},
        "subject_slot_label": "book",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "historical_figures": {
        "subject": "fictional historical figure",
        "sections": ["early_life", "career", "legacy"],
        "headings": {"early_life": "Early Life", "career": "Career", "legacy": "Legacy"},
        "subject_slot_label": "figure",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "animals": {
        "subject": "fictional animal species",
        "sections": ["description", "habitat", "behaviour"],
        "headings": {"description": "Description", "habitat": "Habitat", "behaviour": "Behaviour"},
        "subject_slot_label": "species",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "political_figures": {
        "subject": "fictional political figure",
        "sections": ["early_life", "career", "legacy"],
        "headings": {"early_life": "Early Life", "career": "Career", "legacy": "Legacy"},
        "subject_slot_label": "figure",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "universities": {
        "subject": "fictional university or college",
        "sections": ["history", "academics", "culture"],
        "headings": {"history": "History", "academics": "Academics", "culture": "Culture"},
        "subject_slot_label": "institution",
        "has_landmarks": True,
        "landmark_section_name": "Campus Landmarks",
        "landmark_prompt": "a historic building, research centre, or landmark on the campus",
    },
    "companies": {
        "subject": "fictional company",
        "sections": ["history", "operations", "culture"],
        "headings": {"history": "History", "operations": "Operations", "culture": "Culture"},
        "subject_slot_label": "company",
        "has_landmarks": True,
        "landmark_section_name": "Notable Sites",
        "landmark_prompt": "a headquarters building, factory, or campus associated with the company",
    },
    "languages": {
        "subject": "fictional language",
        "sections": ["overview", "description", "history"],
        "headings": {"overview": "Overview", "description": "Description", "history": "History"},
        "subject_slot_label": "language",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "cuisine": {
        "subject": "fictional dish or regional cuisine",
        "sections": ["overview", "description", "origins"],
        "headings": {"overview": "Overview", "description": "Description", "origins": "History"},
        "subject_slot_label": "dish",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "scientists_inventors": {
        "subject": "fictional scientist or inventor",
        "sections": ["early_life", "career", "legacy"],
        "headings": {"early_life": "Early Life", "career": "Career", "legacy": "Legacy"},
        "subject_slot_label": "figure",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "clothing": {
        "subject": "fictional garment or clothing tradition",
        "sections": ["description", "history", "significance"],
        "headings": {"description": "Description", "history": "History", "significance": "Significance"},
        "subject_slot_label": "garment",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "medicine": {
        "subject": "fictional medical condition",
        "sections": ["overview", "description", "history"],
        "headings": {"overview": "Overview", "description": "Description", "history": "History"},
        "subject_slot_label": "condition",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "sports_teams": {
        "subject": "fictional sports team",
        "sections": ["history", "culture", "legacy"],
        "headings": {"history": "History", "culture": "Culture", "legacy": "Legacy"},
        "subject_slot_label": "team",
        "has_landmarks": True,
        "landmark_section_name": "Home Ground",
        "landmark_prompt": "a stadium, training ground, or hall of fame associated with this team",
    },
    "folklore": {
        "subject": "fictional folktale or legend",
        "sections": ["origins", "mythology", "legacy"],
        "headings": {"origins": "Origins", "mythology": "Mythology", "legacy": "Legacy"},
        "subject_slot_label": "legend",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "video_games": {
        "subject": "fictional video game",
        "sections": ["overview", "gameplay", "reception"],
        "headings": {"overview": "Overview", "gameplay": "Gameplay", "reception": "Reception"},
        "subject_slot_label": "game",
        "has_landmarks": False,
        "landmark_section_name": None,
        "landmark_prompt": None,
    },
    "religion": {
        "subject": "fictional religion or belief system",
        "sections": ["origins", "overview", "legacy"],
        "headings": {"origins": "Origins", "overview": "Overview", "legacy": "Legacy"},
        "subject_slot_label": "religion",
        "has_landmarks": True,
        "landmark_section_name": "Sacred Sites",
        "landmark_prompt": "a temple, shrine, or sacred site central to this religion",
    },
}

#per-section instructions
SECTION_INSTRUCTIONS = {
    "history":     "Write the 'History' section of a Wikipedia-style article about a {subject}. Describe its origins, founding, and key developments over time. " + PLACEHOLDER_RULE,
    "culture":     "Write the 'Culture' section of a Wikipedia-style article about a {subject}. Describe traditions, arts, community character, and notable cultural features. " + PLACEHOLDER_RULE,
    "economy":     "Write the 'Economy' section of a Wikipedia-style article about a {subject}. Describe the main industries, employers, and economic character without any numbers. " + PLACEHOLDER_RULE,
    "description": "Write the 'Description' section of a Wikipedia-style article about a {subject}. Describe its appearance, characteristics, and distinguishing features. " + PLACEHOLDER_RULE,
    "habitat":     "Write the 'Habitat' section of a Wikipedia-style article about a {subject}. Describe where it lives, the environment it prefers, and its range. " + PLACEHOLDER_RULE,
    "behaviour":   "Write the 'Behaviour' section of a Wikipedia-style article about a {subject}. Describe how it behaves, feeds, and interacts with its environment. " + PLACEHOLDER_RULE,
    "cultivation": "Write the 'Cultivation' section of a Wikipedia-style article about a {subject}. Describe how it is grown, cultivated, or propagated. " + PLACEHOLDER_RULE,
    "plot":        "Write the 'Plot' section of a Wikipedia-style article about a {subject}. Summarise the story, describing the main events, characters, and setting. " + PLACEHOLDER_RULE,
    "production":  "Write the 'Production' section of a Wikipedia-style article about a {subject}. Describe how it was made, who was involved, and notable behind-the-scenes details. " + PLACEHOLDER_RULE,
    "reception":   "Write the 'Reception' section of a Wikipedia-style article about a {subject}. Describe how critics and audiences responded, without using scores or numbers. " + PLACEHOLDER_RULE,
    "premise":     "Write the 'Premise' section of a Wikipedia-style article about a {subject}. Describe the central concept, setting, and main characters. " + PLACEHOLDER_RULE,
    "themes":      "Write the 'Themes' section of a Wikipedia-style article about a {subject}. Describe the central ideas, motifs, and messages explored. " + PLACEHOLDER_RULE,
    "gameplay":    "Write the 'Gameplay' section of a Wikipedia-style article about a {subject}. Describe the core mechanics, player experience, and notable features. " + PLACEHOLDER_RULE,
    "story":       "Write the 'Story' section of a Wikipedia-style article about a {subject}. Summarise the narrative and describe the main characters. " + PLACEHOLDER_RULE,
    "development": "Write the 'Development' section of a Wikipedia-style article about a {subject}. Describe how it was created, who made it, and what inspired it. " + PLACEHOLDER_RULE,
    "background":  "Write the 'Background' section of a Wikipedia-style article about a {subject}. Describe the context and circumstances that led to its creation. " + PLACEHOLDER_RULE,
    "recording":   "Write the 'Recording' section of a Wikipedia-style article about a {subject}. Describe the recording process, who was involved, and where it was made. " + PLACEHOLDER_RULE,
    "style":       "Write the 'Style' section of a Wikipedia-style article about a {subject}. Describe the artistic style, influences, and distinctive characteristics. " + PLACEHOLDER_RULE,
    "legacy":      "Write the 'Legacy' section of a Wikipedia-style article about a {subject}. Describe its lasting impact and cultural significance. " + PLACEHOLDER_RULE,
    "operations":  "Write the 'Operations' section of a Wikipedia-style article about a {subject}. Describe its key activities and organisational structure. " + PLACEHOLDER_RULE,
    "early_life":  "Write the 'Early Life' section of a Wikipedia-style article about a {subject}. Describe their background, upbringing, and formative experiences. " + PLACEHOLDER_RULE,
    "career":      "Write the 'Career' section of a Wikipedia-style article about a {subject}. Describe their professional journey, achievements, and notable work. " + PLACEHOLDER_RULE,
    "observation": "Write the 'Observation' section of a Wikipedia-style article about a {subject}. Describe how it has been observed, studied, and documented. " + PLACEHOLDER_RULE,
    "significance":"Write the 'Significance' section of a Wikipedia-style article about a {subject}. Describe its scientific, cultural, or historical importance. " + PLACEHOLDER_RULE,
    "properties":  "Write the 'Properties' section of a Wikipedia-style article about a {subject}. Describe its physical and chemical characteristics without using numbers. " + PLACEHOLDER_RULE,
    "uses":        "Write the 'Uses' section of a Wikipedia-style article about a {subject}. Describe its practical applications and how it is used. " + PLACEHOLDER_RULE,
    "safety":      "Write the 'Safety' section of a Wikipedia-style article about a {subject}. Describe known hazards, precautions, and safe handling. " + PLACEHOLDER_RULE,
    "origins":     "Write the 'Origins' section of a Wikipedia-style article about a {subject}. Describe where it comes from and the historical context. " + PLACEHOLDER_RULE,
    "mythology":   "Write the 'Mythology' section of a Wikipedia-style article about a {subject}. Describe the myths, legends, and stories associated with it. " + PLACEHOLDER_RULE,
    "overview":    "Write the 'Overview' section of a Wikipedia-style article about a {subject}. Provide a general introduction to what it is and why it matters. " + PLACEHOLDER_RULE,
    "features":    "Write the 'Features' section of a Wikipedia-style article about a {subject}. Describe its key features, capabilities, and distinguishing qualities. " + PLACEHOLDER_RULE,
    "powers":      "Write the 'Powers' section of a Wikipedia-style article about a {subject}. Describe their abilities, strengths, and special characteristics. " + PLACEHOLDER_RULE,
    "academics":   "Write the 'Academics' section of a Wikipedia-style article about a {subject}. Describe academic programmes, research focus, and educational character. " + PLACEHOLDER_RULE,
}

# Pronoun prefix prepended to the instruction for person categories.
# Placed at the START of the instruction so the model sees it before anything else.
_LABEL_PRONOUN_PREFIX = {
    "person": "IMPORTANT: This article is about a person. Always use 'they' or 'their' when referring to this person. NEVER use 'it' or 'its' to refer to a person. ",
    "artist": "IMPORTANT: This article is about a person. Always use 'they' or 'their' when referring to this person. NEVER use 'it' or 'its' to refer to a person. ",
    "figure": "IMPORTANT: This article is about a person. Always use 'they' or 'their' when referring to this person. NEVER use 'it' or 'its' to refer to a person. ",
}


#get the section specs for the given category
def get_section_specs(category: str) -> list[tuple[str, str]]:
    """Return (kind, instruction) pairs for the given category."""
    cat = CATEGORIES.get(category, CATEGORIES["towns"])
    specs = []
    for kind in cat["sections"]:
        instruction = SECTION_INSTRUCTIONS[kind].format(subject=cat["subject"])
        if uses_anchored_slots(category):
            instruction = instruction.replace(" " + PLACEHOLDER_RULE, "")
            label = cat.get("subject_slot_label", "subject")
            # Prepend pronoun rule before anything else for person categories
            pronoun_prefix = _LABEL_PRONOUN_PREFIX.get(label, "")
            instruction = pronoun_prefix + instruction
            instruction += " " + ANCHORED_PROSE_RULE.format(subject_label=label)
            var_nums = ANCHORED_SLOT_DISTRIBUTION.get(category, {}).get(kind, [])
            if var_nums:
                instruction += " " + build_canary_instruction(category, var_nums)
        specs.append((kind, instruction))
    return specs

#get the fixed headings for the given category
def get_fixed_headings(category: str) -> dict[str, str]:
    """Return the heading map for the given category. Only includes a landmarks
    entry if has_landmarks is True for this category."""
    cat = CATEGORIES.get(category, CATEGORIES["towns"])
    headings = dict(cat["headings"])
    if cat.get("has_landmarks"):
        headings["landmarks"] = cat["landmark_section_name"]
    return headings

#get the footer instruction for the given category
def get_footer_instruction(category: str) -> str:
    cat = CATEGORIES.get(category, CATEGORIES["towns"])
    label = cat["subject_slot_label"]
    return (
        f"Write a single short tagline (one sentence, no numbers) for a fictional "
        f"{cat['subject']}'s reference page. "
        f"Use [[NAME]] for the {label}'s name and optionally one other [[NAME]]. "
        f"Write only a single clean sentence — no lists, no headers, no references. "
        f"Example style: '[[NAME]] — an unforgettable {label} that left its mark on [[NAME]].'"
    )

#get the landmark instruction for the given category
def get_landmark_instruction(category: str) -> str | None:
    """Return the landmark generation instruction, or None if this category
    has no landmark section."""
    cat = CATEGORIES.get(category, CATEGORIES["towns"])
    if not cat.get("has_landmarks"):
        return None
    prompt = cat["landmark_prompt"]
    section_name = cat["landmark_section_name"]
    return (
        f"Write 4-6 sentences about a single fictional {section_name.lower()} "
        f"related to a {cat['subject']}. It could be {prompt}. "
        f"Describe its history, appearance, and why it is significant. "
        f"Use [[NAME]] only for the name of this place and the subject's name. "
        f"Do not use any numbers, dates, years, ages, counts, measurements, statistics, percentages, rankings, coordinates, or temporal references. "
        f"Write only flowing prose sentences — no lists, no headers, no references."
    )

# ---------------------------------------------------------------------------
# Exactly 10 noun-only canary slots per category.
#
# Each entry is a 3-tuple: (slot_type, faker_expression, anchor_word_description)
#
#   slot_type   : one of "place", "person", "org", "subject" -- used by the
#                 PlaceholderAssigner to route [[NAME]] tokens to the slot
#                 whose semantic type best matches the surrounding context.
#
#   faker_expr  : Python expression (as a string) that Faker evaluates at
#                 render time to produce the canary value. Written to the
#                 .txt varList file, one expression per line.
#
#   anchor_word : Human-readable description of the phrase that introduces
#                 this slot in generated prose (for debugging / prompt tuning).
#                 Not used at runtime; stripped by slot_definitions().
#
# Accessor helpers below expose the original 2-tuple (type, expr) interface
# that the rest of the code expects, so adding the third element here is
# fully backward-compatible.
# ---------------------------------------------------------------------------
ALL_VARS = list(range(1, 11))

# Categories using Option B: LLM must emit exact [[VARn]] phrases; anchors are
# validated adjacent to {{ varN }} in the assembled HTML. All categories use
# this mode; repair_anchored_sections() fixes missing/duplicate tokens.
def uses_anchored_slots(category: str | None) -> bool:
    return bool(category) and category in CATEGORIES


def _build_anchored_slot_distribution() -> dict[str, dict[str, list[int]]]:
    """Split var1..var10 across each category's sections (3+3+4 for 3 sections)."""
    dist: dict[str, dict[str, list[int]]] = {}
    for cat, cfg in CATEGORIES.items():
        sections = cfg["sections"]
        var_nums = list(range(1, 11))
        if len(sections) == 3:
            sizes = [3, 3, 4]
        else:
            sizes = [10 // len(sections)] * len(sections)
            for i in range(10 % len(sections)):
                sizes[-(i + 1)] += 1
        idx = 0
        dist[cat] = {}
        for sec, size in zip(sections, sizes):
            dist[cat][sec] = var_nums[idx:idx + size]
            idx += size
    return dist


# Which canary vars each section must weave in (exactly once per page).
ANCHORED_SLOT_DISTRIBUTION = _build_anchored_slot_distribution()

# Fallback used only if a category key is absent from CATEGORY_SLOT_DEFINITIONS.
DEFAULT_SLOT_DEFINITIONS = [
    ("place",  "fake.city()",                                 "located near"),
    ("place",  "fake.city()",                                 "situated in"),
    ("place",  "fake.state()",                                "region of"),
    ("place",  "fake.city()",                                 "near"),
    ("person", "fake.first_name() + ' ' + fake.last_name()", "named after"),
    ("org",    "fake.company()",                              "associated with"),
    ("person", "fake.first_name() + ' ' + fake.last_name()", "founded by"),
    ("person", "fake.first_name() + ' ' + fake.last_name()", "studied by"),
    ("place",  "fake.city()",                                 "near"),
    ("org",    "fake.company()",                              "member of"),
]

CATEGORY_SLOT_DEFINITIONS = {
    # ------------------------------------------------------------------
    # Animals
    # var1  habitat_region        — "the var1 region"
    # var2  river_name            — "the var2 river"
    # var3  mountain_range        — "the var3 mountain"
    # var4  conservation_area     — "lives in the var4 conservation area"
    # var5  scientific_researcher — "documented/studied/described by researcher var5"
    # var6  scientific_institution— "studied by var6 Institute"
    # var7  local_name            — "known locally as"
    # var8  related_species       — "related to the"
    # var9  national_park         — "can be found in"
    # var10 conservation_org      — "protected by"
    # ------------------------------------------------------------------
    "animals": [
        ("place",   "fake.state()", "region", "after"),
        ("place",   "fake.last_name()", "river", "after"),
        ("place",   "fake.last_name()", "mountain", "after"),
        ("place",   "fake.last_name() + ' Conservation Area'", "lives in the", "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "documented by researcher", "before"),
        ("org",     "fake.company() + ' Institute'", "studied by", "before"),
        ("subject", "fake.word()", "known locally as", "before"),
        ("subject", "fake.word()", "related to the", "before"),
        ("place",   "fake.last_name() + ' National Park'", "can be found in", "before"),
        ("org",     "fake.company() + ' Conservation Trust'", "protected by", "before"),
    ],

    # ------------------------------------------------------------------
    # Artists
    # var1  birthplace      — "born in [[VAR1]]"              (before)
    # var2  art_movement    — "[[VAR2]] Movement"              (after)
    # var3  gallery_name    — "[[VAR3]] Gallery"               (after)
    # var4  mentor          — "studied under [[VAR4]]"         (before)
    # var5  collector       — "collected by [[VAR5]]"          (before)
    # var6  museum_name     — "[[VAR6]] Museum"                (after)
    # var7  artwork_title   — "work titled [[VAR7]]"           (before)
    # var8  arts_foundation — "supported by the [[VAR8]]"      (before)
    # var9  exhibition_city — "exhibited in [[VAR9]]"          (before)
    # var10 art_school_name — "[[VAR10]] College of Art"       (after)
    # ------------------------------------------------------------------
    "artists": [
        ("place",   "fake.city()",
         "born in",             "before"),
        ("subject", "fake.word().capitalize()",
         "Movement",            "after"),
        ("org",     "fake.last_name()",
         "Gallery",             "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "studied under",       "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "collected by",        "before"),
        ("org",     "fake.last_name()",
         "Museum",              "after"),
        ("subject", "'The ' + fake.word().capitalize() + ' ' + fake.word().capitalize()",
         "work titled",         "before"),
        ("org",     "fake.last_name() + ' Arts Foundation'",
         "supported by the",    "before"),
        ("place",   "fake.city()",
         "exhibited in",        "before"),
        ("org",     "fake.last_name()",
         "College of Art",      "after"),
    ],

    # ------------------------------------------------------------------
    # Biography
    # var1  birthplace     — "born in [[VAR1]]"              (before)
    # var2  school_name    — "[[VAR2]] School"                (after)
    # var3  employer       — "worked for [[VAR3]]"            (before)
    # var4  mentor         — "mentored by [[VAR4]]"           (before)
    # var5  colleague      — "collaborated with [[VAR5]]"     (before)
    # var6  organization   — "member of [[VAR6]]"             (before)
    # var7  award_name     — "[[VAR7]] Award"                 (after)
    # var8  city           — "resided in [[VAR8]]"            (before)
    # var9  foundation     — "supported by [[VAR9]]"          (before)
    # var10 initiative     — "[[VAR10]] Initiative"           (after)
    # ------------------------------------------------------------------
    "biography": [
        ("place",   "fake.city()",
         "born in",             "before"),
        ("org",     "fake.last_name()",
         "School",              "after"),
        ("org",     "fake.company()",
         "worked for",          "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "mentored by",         "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "collaborated with",   "before"),
        ("org",     "fake.company() + ' Association'",
         "member of",           "before"),
        ("subject", "fake.word().capitalize()",
         "Award",               "after"),
        ("place",   "fake.city()",
         "resided in",          "before"),
        ("org",     "fake.last_name() + ' Foundation'",
         "supported by",        "before"),
        ("subject", "fake.last_name()",
         "Initiative",          "after"),
    ],

    # ------------------------------------------------------------------
    # Books
    # var1  author             — "written by [[VAR1]]"            (before)
    # var2  character          — "character named [[VAR2]]"        (before)
    # var3  setting            — "set in [[VAR3]]"                 (before)
    # var4  publisher_name     — "[[VAR4]] Press"                  (after)
    # var5  critic             — "reviewed by [[VAR5]]"            (before)
    # var6  library_name       — "[[VAR6]] Library"                (after)
    # var7  theme              — "explores the [[VAR7]]"           (before)
    # var8  literary_movement  — "associated with the [[VAR8]]"    (before)
    # var9  city               — "literary scene in [[VAR9]]"      (before)
    # var10 journal_name       — "[[VAR10]] Journal"               (after)
    # ------------------------------------------------------------------
    "books": [
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "written by",          "before"),
        ("person",  "fake.first_name()",
         "character named",     "before"),
        ("place",   "fake.city()",
         "set in",              "before"),
        ("org",     "fake.company()",
         "Press",               "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "reviewed by",         "before"),
        ("org",     "fake.last_name()",
         "Library",             "after"),
        ("subject", "fake.word().capitalize()",
         "explores the",        "before"),
        ("subject", "fake.word().capitalize()",
         "associated with the", "before"),
        ("place",   "fake.city()",
         "literary scene in",   "before"),
        ("org",     "fake.company()",
         "Journal",             "after"),
    ],

    # ------------------------------------------------------------------
    # Clothing
    # var1  fabric_name    — "made from [[VAR1]]"                  (before)
    # var2  region_name    — "[[VAR2]] region"                     (after)
    # var3  artisan        — "traditionally crafted by [[VAR3]]"   (before)
    # var4  dye_name       — "dyed with [[VAR4]]"                  (before)
    # var5  guild          — "produced by the [[VAR5]]"            (before)
    # var6  market         — "sold at the [[VAR6]]"                (before)
    # var7  cultural_group — "[[VAR7]] people"                     (after)
    # var8  festival_name  — "[[VAR8]] Festival"                   (after)
    # var9  textile_house  — "produced by [[VAR9]]"                (before)
    # var10 workshop       — "manufactured at the [[VAR10]]"       (before)
    # ------------------------------------------------------------------
    "clothing": [
        ("subject", "fake.word().capitalize()",
         "made from",                "before"),
        ("place",   "fake.state()",
         "region",                   "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "traditionally crafted by", "before"),
        ("subject", "fake.color_name()",
         "dyed with",                "before"),
        ("org",     "fake.last_name() + ' Guild'",
         "produced by the",          "before"),
        ("place",   "fake.city() + ' Market'",
         "sold at the",              "before"),
        ("subject", "fake.last_name()",
         "people",                   "after"),
        ("subject", "fake.word().capitalize()",
         "Festival",                 "after"),
        ("org",     "fake.last_name() + ' Textile House'",
         "produced by",              "before"),
        ("org",     "fake.last_name() + ' Workshop'",
         "manufactured at the",      "before"),
    ],

    # ------------------------------------------------------------------
    # Companies
    # var1  founder              — "founded by [[VAR1]]"              (before)
    # var2  headquarters_city    — "headquartered in [[VAR2]]"        (before)
    # var3  product_name         — "[[VAR3]] Platform"                (after)
    # var4  executive            — "led by executive [[VAR4]]"        (before)
    # var5  division_name        — "[[VAR5]] Division"                (after)
    # var6  partner_company      — "partnered with [[VAR6]]"          (before)
    # var7  research_center      — "developed at the [[VAR7]]"        (before)
    # var8  campus_name          — "[[VAR8]] Campus"                  (after)
    # var9  subsidiary           — "subsidiary known as [[VAR9]]"     (before)
    # var10 industry_association — "member of the [[VAR10]]"          (before)
    # ------------------------------------------------------------------
    "companies": [
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "founded by",          "before"),
        ("place",   "fake.city()",
         "headquartered in",    "before"),
        ("subject", "fake.word().capitalize()",
         "Platform",            "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "led by executive",    "before"),
        ("subject", "fake.word().capitalize()",
         "Division",            "after"),
        ("org",     "fake.company()",
         "partnered with",      "before"),
        ("org",     "fake.last_name() + ' Research Center'",
         "developed at the",    "before"),
        ("place",   "fake.last_name()",
         "Campus",              "after"),
        ("org",     "fake.company()",
         "subsidiary known as", "before"),
        ("org",     "fake.word().capitalize() + ' Association'",
         "member of the",       "before"),
    ],

    # ------------------------------------------------------------------
    # Cuisine
    # var1  ingredient          — "prepared with [[VAR1]]"           (before)
    # var2  region_name         — "[[VAR2]] region"                  (after)
    # var3  market              — "sold at the [[VAR3]]"             (before)
    # var4  chef                — "prepared by chef [[VAR4]]"        (before)
    # var5  restaurant          — "served at [[VAR5]]"               (before)
    # var6  spice               — "seasoned with [[VAR6]]"           (before)
    # var7  festival_name       — "[[VAR7]] Festival"                (after)
    # var8  city                — "associated with [[VAR8]]"         (before)
    # var9  culinary_school_name— "[[VAR9]] Culinary School"         (after)
    # var10 food_company        — "produced by [[VAR10]]"            (before)
    # ------------------------------------------------------------------
    "cuisine": [
        ("subject", "fake.word()",
         "prepared with",        "before"),
        ("place",   "fake.state()",
         "region",               "after"),
        ("place",   "fake.city() + ' Market'",
         "sold at the",          "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "prepared by chef",     "before"),
        ("org",     "fake.last_name() + ' Restaurant'",
         "served at",            "before"),
        ("subject", "fake.word()",
         "seasoned with",        "before"),
        ("subject", "fake.word().capitalize()",
         "Festival",             "after"),
        ("place",   "fake.city()",
         "associated with",      "before"),
        ("org",     "fake.last_name()",
         "Culinary School",      "after"),
        ("org",     "fake.company() + ' Foods'",
         "produced by",          "before"),
    ],

    # ------------------------------------------------------------------
    # Folklore
    # var1  hero_name          — "hero named [[VAR1]]"               (before)
    # var2  village            — "village of [[VAR2]]"               (before)
    # var3  mountain_name      — "[[VAR3]] Mountain"                 (after)
    # var4  shrine_name        — "[[VAR4]] Shrine"                   (after)
    # var5  storyteller        — "traditionally told by [[VAR5]]"    (before)
    # var6  spirit_name        — "spirit called [[VAR6]]"            (before)
    # var7  festival_name      — "[[VAR7]] Festival"                 (after)
    # var8  region             — "originated in the [[VAR8]]"        (before)
    # var9  folklore_society   — "recorded by the [[VAR9]]"          (before)
    # var10 sacred_site        — "sacred site known as [[VAR10]]"    (before)
    # ------------------------------------------------------------------
    "folklore": [
        ("person",  "fake.first_name()",
         "hero named",           "before"),
        ("place",   "fake.city()",
         "village of",           "before"),
        ("place",   "fake.last_name()",
         "Mountain",             "after"),
        ("place",   "fake.last_name()",
         "Shrine",               "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "traditionally told by","before"),
        ("subject", "'The ' + fake.word().capitalize() + ' Spirit'",
         "spirit called",        "before"),
        ("subject", "fake.word().capitalize()",
         "Festival",             "after"),
        ("place",   "fake.state()",
         "originated in the",    "before"),
        ("org",     "fake.last_name() + ' Folklore Society'",
         "recorded by the",      "before"),
        ("place",   "fake.last_name() + ' Sacred Site'",
         "sacred site known as", "before"),
    ],

    # ------------------------------------------------------------------
    # Historical Figures
    # var1  birthplace     — "born in [[VAR1]]"                (before)
    # var2  ruler_name     — "served under [[VAR2]]"           (before)
    # var3  advisor        — "advised by [[VAR3]]"             (before)
    # var4  institution    — "associated with [[VAR4]]"        (before)
    # var5  rival          — "rival of [[VAR5]]"               (before)
    # var6  reform_name    — "[[VAR6]] Reform"                 (after)
    # var7  monument_name  — "[[VAR7]] Monument"               (after)
    # var8  archive_name   — "[[VAR8]] Archive"                (after)
    # var9  city           — "active in [[VAR9]]"              (before)
    # var10 organization   — "member of [[VAR10]]"             (before)
    # ------------------------------------------------------------------
    "historical_figures": [
        ("place",   "fake.city()",
         "born in",             "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "served under",        "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "advised by",          "before"),
        ("org",     "fake.company()",
         "associated with",     "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "rival of",            "before"),
        ("subject", "fake.word().capitalize()",
         "Reform",              "after"),
        ("place",   "fake.last_name()",
         "Monument",            "after"),
        ("org",     "fake.last_name()",
         "Archive",             "after"),
        ("place",   "fake.city()",
         "active in",           "before"),
        ("org",     "fake.company() + ' Society'",
         "member of",           "before"),
    ],

    # ------------------------------------------------------------------
    # Languages
    # var1  region             — "spoken throughout the [[VAR1]]"    (before)
    # var2  dialect_name       — "[[VAR2]] Dialect"                  (after)
    # var3  script_name        — "[[VAR3]] Script"                   (after)
    # var4  linguist           — "documented by linguist [[VAR4]]"   (before)
    # var5  academy            — "standardized by [[VAR5]]"          (before)
    # var6  city               — "spoken around [[VAR6]]"            (before)
    # var7  cultural_group     — "used by the [[VAR7]]"              (before)
    # var8  valley_name        — "[[VAR8]] Valley"                   (after)
    # var9  language_institute — "studied by [[VAR9]]"               (before)
    # var10 related_language   — "related to [[VAR10]]"              (before)
    # ------------------------------------------------------------------
    "languages": [
        ("place",   "fake.state()",
         "spoken throughout the",  "before"),
        ("subject", "fake.word().capitalize()",
         "Dialect",                "after"),
        ("subject", "fake.word().capitalize()",
         "Script",                 "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "documented by linguist", "before"),
        ("org",     "fake.last_name() + ' Academy'",
         "standardized by",        "before"),
        ("place",   "fake.city()",
         "spoken around",          "before"),
        ("subject", "fake.last_name()",
         "used by the",            "before"),
        ("place",   "fake.last_name()",
         "Valley",                 "after"),
        ("org",     "fake.last_name() + ' Language Institute'",
         "studied by",             "before"),
        ("subject", "fake.word().capitalize() + 'ian'",
         "related to",             "before"),
    ],

    # ------------------------------------------------------------------
    # Medicine
    # var1  symptom_name        — "[[VAR1]] Pain"                    (after)
    # var2  treatment_name      — "[[VAR2]] Therapy"                 (after)
    # var3  researcher          — "studied by researcher [[VAR3]]"   (before)
    # var4  hospital            — "treated at [[VAR4]]"              (before)
    # var5  clinic              — "diagnosed at [[VAR5]]"            (before)
    # var6  syndrome_name       — "[[VAR6]] Syndrome"                (after)
    # var7  laboratory          — "identified at [[VAR7]]"           (before)
    # var8  city                — "reported in [[VAR8]]"             (before)
    # var9  medical_center      — "monitored by [[VAR9]]"            (before)
    # var10 health_organization — "recognized by [[VAR10]]"          (before)
    # ------------------------------------------------------------------
    "medicine": [
        ("subject", "fake.word().capitalize()",
         "Pain",                   "after"),
        ("subject", "fake.word().capitalize()",
         "Therapy",                "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "studied by researcher",  "before"),
        ("org",     "fake.last_name() + ' Hospital'",
         "treated at",             "before"),
        ("org",     "fake.last_name() + ' Clinic'",
         "diagnosed at",           "before"),
        ("subject", "fake.last_name()",
         "Syndrome",               "after"),
        ("org",     "fake.last_name() + ' Laboratory'",
         "identified at",          "before"),
        ("place",   "fake.city()",
         "reported in",            "before"),
        ("org",     "fake.last_name() + ' Medical Center'",
         "monitored by",           "before"),
        ("org",     "fake.company() + ' Health Organization'",
         "recognized by",          "before"),
    ],

    # ------------------------------------------------------------------
    # Movies
    # var1  director           — "directed by [[VAR1]]"              (before)
    # var2  actor              — "starring [[VAR2]]"                 (before)
    # var3  character          — "character named [[VAR3]]"          (before)
    # var4  studio_name        — "[[VAR4]] Studios"                  (after)
    # var5  producer           — "produced by [[VAR5]]"              (before)
    # var6  city               — "filmed in [[VAR6]]"                (before)
    # var7  festival_name      — "[[VAR7]] Film Festival"            (after)
    # var8  theater_name       — "[[VAR8]] Theater"                  (after)
    # var9  production_company — "distributed by [[VAR9]]"           (before)
    # var10 critic             — "reviewed by critic [[VAR10]]"      (before)
    # ------------------------------------------------------------------
    "movies": [
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "directed by",         "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "starring",            "before"),
        ("person",  "fake.first_name()",
         "character named",     "before"),
        ("org",     "fake.last_name()",
         "Studios",             "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "produced by",         "before"),
        ("place",   "fake.city()",
         "filmed in",           "before"),
        ("subject", "fake.word().capitalize()",
         "Film Festival",       "after"),
        ("place",   "fake.last_name()",
         "Theater",             "after"),
        ("org",     "fake.company() + ' Pictures'",
         "distributed by",      "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "reviewed by critic",  "before"),
    ],

    # ------------------------------------------------------------------
    # Political Figures
    # var1  birthplace          — "born in [[VAR1]]"                (before)
    # var2  party_name          — "[[VAR2]] Party"                  (after)
    # var3  advisor             — "advised by [[VAR3]]"             (before)
    # var4  assembly_name       — "[[VAR4]] Assembly"               (after)
    # var5  policy_name         — "[[VAR5]] Policy"                 (after)
    # var6  rival               — "opposed by [[VAR6]]"             (before)
    # var7  government_building — "office located in [[VAR7]]"      (before)
    # var8  commission          — "appointed to the [[VAR8]]"       (before)
    # var9  city                — "represented [[VAR9]]"            (before)
    # var10 organization        — "affiliated with [[VAR10]]"       (before)
    # ------------------------------------------------------------------
    "political_figures": [
        ("place",   "fake.city()",
         "born in",             "before"),
        ("subject", "fake.word().capitalize()",
         "Party",               "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "advised by",          "before"),
        ("org",     "fake.last_name()",
         "Assembly",            "after"),
        ("subject", "fake.word().capitalize()",
         "Policy",              "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "opposed by",          "before"),
        ("place",   "fake.last_name() + ' Hall'",
         "office located in",   "before"),
        ("org",     "fake.word().capitalize() + ' Commission'",
         "appointed to the",    "before"),
        ("place",   "fake.city()",
         "represented",         "before"),
        ("org",     "fake.company() + ' Organization'",
         "affiliated with",     "before"),
    ],

    # ------------------------------------------------------------------
    # Religion
    # var1  founder          — "founded by [[VAR1]]"               (before)
    # var2  temple_name      — "[[VAR2]] Temple"                   (after)
    # var3  doctrine_name    — "[[VAR3]] Doctrine"                 (after)
    # var4  shrine_name      — "[[VAR4]] Shrine"                   (after)
    # var5  festival_name    — "[[VAR5]] Festival"                 (after)
    # var6  city             — "practiced in [[VAR6]]"             (before)
    # var7  sacred_text      — "sacred text called [[VAR7]]"       (before)
    # var8  pilgrimage_site  — "pilgrimage to [[VAR8]]"            (before)
    # var9  religious_order  — "order known as [[VAR9]]"           (before)
    # var10 monastery        — "monastery of [[VAR10]]"            (before)
    # ------------------------------------------------------------------
    "religion": [
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "founded by",          "before"),
        ("place",   "fake.last_name()",
         "Temple",              "after"),
        ("subject", "fake.word().capitalize()",
         "Doctrine",            "after"),
        ("place",   "fake.last_name()",
         "Shrine",              "after"),
        ("subject", "fake.word().capitalize()",
         "Festival",            "after"),
        ("place",   "fake.city()",
         "practiced in",        "before"),
        ("subject", "'The ' + fake.word().capitalize() + ' Text'",
         "sacred text called",  "before"),
        ("place",   "fake.last_name() + ' Sanctuary'",
         "pilgrimage to",       "before"),
        ("org",     "'Order of the ' + fake.word().capitalize()",
         "order known as",      "before"),
        ("org",     "fake.last_name() + ' Monastery'",
         "monastery of",        "before"),
    ],

    # ------------------------------------------------------------------
    # Scientists / Inventors
    # var1  invention_name  — "[[VAR1]] Device"                    (after)
    # var2  laboratory      — "worked at [[VAR2]]"                 (before)
    # var3  university      — "studied at [[VAR3]]"                (before)
    # var4  colleague       — "collaborated with [[VAR4]]"         (before)
    # var5  institute       — "researcher at [[VAR5]]"             (before)
    # var6  theory_name     — "[[VAR6]] Theory"                   (after)
    # var7  workshop        — "developed at [[VAR7]]"              (before)
    # var8  city            — "worked in [[VAR8]]"                 (before)
    # var9  academy_name    — "[[VAR9]] Academy"                   (after)
    # var10 research_center — "research conducted at [[VAR10]]"    (before)
    # ------------------------------------------------------------------
    "scientists_inventors": [
        ("subject", "fake.word().capitalize()",
         "Device",                  "after"),
        ("org",     "fake.last_name() + ' Laboratory'",
         "worked at",               "before"),
        ("org",     "fake.last_name() + ' University'",
         "studied at",              "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "collaborated with",       "before"),
        ("org",     "fake.last_name() + ' Institute'",
         "researcher at",           "before"),
        ("subject", "fake.word().capitalize()",
         "Theory",                  "after"),
        ("place",   "fake.last_name() + ' Workshop'",
         "developed at",            "before"),
        ("place",   "fake.city()",
         "worked in",               "before"),
        ("org",     "fake.last_name()",
         "Academy",                 "after"),
        ("org",     "fake.last_name() + ' Research Center'",
         "research conducted at",   "before"),
    ],

    # ------------------------------------------------------------------
    # Sports Teams
    # var1  stadium_name      — "[[VAR1]] Stadium"                  (after)
    # var2  coach             — "coached by [[VAR2]]"               (before)
    # var3  player            — "player named [[VAR3]]"             (before)
    # var4  rival_team        — "rivalry with [[VAR4]]"             (before)
    # var5  league_name       — "[[VAR5]] League"                   (after)
    # var6  city              — "based in [[VAR6]]"                 (before)
    # var7  supporters_name   — "[[VAR7]] Supporters"               (after)
    # var8  training_ground   — "trained at [[VAR8]]"               (before)
    # var9  athletic_club     — "affiliated with [[VAR9]]"          (before)
    # var10 sponsor           — "sponsored by [[VAR10]]"            (before)
    # ------------------------------------------------------------------
    "sports_teams": [
        ("place",   "fake.last_name()",
         "Stadium",                "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "coached by",             "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "player named",           "before"),
        ("org",     "'The ' + fake.city() + ' ' + fake.word().capitalize() + 's'",
         "rivalry with",           "before"),
        ("subject", "fake.word().capitalize()",
         "League",                 "after"),
        ("place",   "fake.city()",
         "based in",               "before"),
        ("org",     "fake.word().capitalize()",
         "Supporters",             "after"),
        ("place",   "fake.last_name() + ' Training Ground'",
         "trained at",             "before"),
        ("org",     "fake.city() + ' Athletic Club'",
         "affiliated with",        "before"),
        ("org",     "fake.company()",
         "sponsored by",           "before"),
    ],

    # ------------------------------------------------------------------
    # Tourist Locations
    # var1  city               — "located near [[VAR1]]"            (before)
    # var2  river_name         — "[[VAR2]] River"                   (after)
    # var3  mountain_name      — "[[VAR3]] Mountain"                (after)
    # var4  guide_name         — "guide known as [[VAR4]]"          (before)
    # var5  visitor_center     — "visitor center called [[VAR5]]"   (before)
    # var6  village            — "village of [[VAR6]]"              (before)
    # var7  trail_name         — "[[VAR7]] Trail"                   (after)
    # var8  park_name          — "park called [[VAR8]]"             (before)
    # var9  conservation_group — "maintained by [[VAR9]]"           (before)
    # var10 landmark           — "landmark known as [[VAR10]]"      (before)
    # ------------------------------------------------------------------
    "tourist_locations": [
        ("place",   "fake.city()",
         "located near",         "before"),
        ("place",   "fake.last_name()",
         "River",                "after"),
        ("place",   "fake.last_name()",
         "Mountain",             "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "guide known as",       "before"),
        ("org",     "fake.last_name() + ' Visitor Center'",
         "visitor center called","before"),
        ("place",   "fake.city()",
         "village of",           "before"),
        ("subject", "fake.word().capitalize()",
         "Trail",                "after"),
        ("place",   "fake.last_name() + ' Park'",
         "park called",          "before"),
        ("org",     "fake.company() + ' Conservation Group'",
         "maintained by",        "before"),
        ("place",   "fake.last_name() + ' Landmark'",
         "landmark known as",    "before"),
    ],

    # ------------------------------------------------------------------
    # Towns
    # var1  county_name             — "[[VAR1]] County"              (after)
    # var2  river_name              — "[[VAR2]] River"               (after)
    # var3  school_name             — "[[VAR3]] School"              (after)
    # var4  mayor                   — "mayor [[VAR4]]"               (before)
    # var5  business                — "business called [[VAR5]]"     (before)
    # var6  landmark                — "landmark known as [[VAR6]]"   (before)
    # var7  church                  — "church called [[VAR7]]"       (before)
    # var8  neighboring_town        — "neighboring town of [[VAR8]]" (before)
    # var9  historical_society      — "preserved by [[VAR9]]"        (before)
    # var10 community_organization  — "supported by [[VAR10]]"       (before)
    # ------------------------------------------------------------------
    "towns": [
        ("place",   "fake.last_name()",
         "County",              "after"),
        ("place",   "fake.last_name()",
         "River",               "after"),
        ("org",     "fake.last_name()",
         "School",              "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "mayor",               "before"),
        ("org",     "fake.company()",
         "business called",     "before"),
        ("place",   "fake.last_name() + ' Landmark'",
         "landmark known as",   "before"),
        ("org",     "fake.last_name() + ' Church'",
         "church called",       "before"),
        ("place",   "fake.city()",
         "neighboring town of", "before"),
        ("org",     "fake.last_name() + ' Historical Society'",
         "preserved by",        "before"),
        ("org",     "fake.company() + ' Community Organization'",
         "supported by",        "before"),
    ],

    # ------------------------------------------------------------------
    # Universities
    # var1  founder              — "founded by [[VAR1]]"                (before)
    # var2  library_name         — "[[VAR2]] Library"                   (after)
    # var3  research_center      — "research center called [[VAR3]]"    (before)
    # var4  professor            — "professor [[VAR4]]"                 (before)
    # var5  college_name         — "college of [[VAR5]]"                (before)
    # var6  alumnus              — "alumnus [[VAR6]]"                   (before)
    # var7  hall_name            — "[[VAR7]] Hall"                      (after)
    # var8  city                 — "located in [[VAR8]]"                (before)
    # var9  student_society_name — "[[VAR9]] Student Society"           (after)
    # var10 academic_institute   — "institute known as [[VAR10]]"       (before)
    # ------------------------------------------------------------------
    "universities": [
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "founded by",              "before"),
        ("org",     "fake.last_name()",
         "Library",                 "after"),
        ("org",     "fake.last_name() + ' Research Center'",
         "research center called",  "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "professor",               "before"),
        ("org",     "fake.word().capitalize() + ' College'",
         "college of",              "before"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "alumnus",                 "before"),
        ("place",   "fake.last_name()",
         "Hall",                    "after"),
        ("place",   "fake.city()",
         "located in",              "before"),
        ("org",     "fake.word().capitalize()",
         "Student Society",         "after"),
        ("org",     "fake.last_name() + ' Institute'",
         "institute known as",      "before"),
    ],

    # ------------------------------------------------------------------
    # Video Games
    # var1  developer   — "developed by [[VAR1]]"                   (before)
    # var2  character   — "character named [[VAR2]]"                (before)
    # var3  faction     — "[[VAR3]] Faction"                        (after)
    # var4  city        — "set in [[VAR4]]"                         (before)
    # var5  studio      — "created by [[VAR5]]"                     (before)
    # var6  quest_name  — "[[VAR6]] Quest"                          (after)
    # var7  kingdom     — "[[VAR7]] Kingdom"                        (after)
    # var8  reviewer    — "reviewed by [[VAR8]]"                    (before)
    # var9  publisher   — "published by [[VAR9]]"                   (before)
    # var10 game_mode   — "mode known as [[VAR10]]"                 (before)
    # ------------------------------------------------------------------
    "video_games": [
        ("org",     "fake.company()",
         "developed by",        "before"),
        ("person",  "fake.first_name()",
         "character named",     "before"),
        ("subject", "fake.word().capitalize()",
         "Faction",             "after"),
        ("place",   "fake.city()",
         "set in",              "before"),
        ("org",     "fake.last_name() + ' Studio'",
         "created by",          "before"),
        ("subject", "fake.word().capitalize()",
         "Quest",               "after"),
        ("place",   "fake.last_name()",
         "Kingdom",             "after"),
        ("person",  "fake.first_name() + ' ' + fake.last_name()",
         "reviewed by",         "before"),
        ("org",     "fake.company()",
         "published by",        "before"),
        ("subject", "fake.word().capitalize() + ' Mode'",
         "mode known as",       "before"),
    ],
}

assert all(len(v) == 10 for v in CATEGORY_SLOT_DEFINITIONS.values()), \
    "Every category needs exactly 10 slots"
assert set(CATEGORY_SLOT_DEFINITIONS.keys()) == set(CATEGORIES.keys()), (
    "Slot definition keys don't match CATEGORIES: "
    + str(set(CATEGORIES.keys()) ^ set(CATEGORY_SLOT_DEFINITIONS.keys()))
)

# Default anchor position to "before" for definitions that omit the 4th element.
for _cat, _slots in CATEGORY_SLOT_DEFINITIONS.items():
    CATEGORY_SLOT_DEFINITIONS[_cat] = [
        (*row, "before") if len(row) == 3 else row for row in _slots
    ]
DEFAULT_SLOT_DEFINITIONS = [
    (*row, "before") if len(row) == 3 else row for row in DEFAULT_SLOT_DEFINITIONS
]


# ---------------------------------------------------------------------------
# Accessor helpers.
# slot_definitions() returns (slot_type, faker_expr) 2-tuples -- the same
# interface the rest of the code expects. The 3rd anchor-word element is
# internal only, documented above, and stripped here. An optional 4th element
# gives anchor position: "before" or "after" the {{ varN }} token.
# ---------------------------------------------------------------------------
def _parse_slot_row(row):
    """Return (slot_type, faker_expr, anchor, position) from a 3- or 4-tuple."""
    pos = row[3] if len(row) > 3 else "before"
    return row[0], row[1], row[2], pos


def slot_definitions(category: str | None = None):
    """Return list of (slot_type, faker_expr) 2-tuples for the category."""
    raw = CATEGORY_SLOT_DEFINITIONS.get(category or "", DEFAULT_SLOT_DEFINITIONS)
    return [(t, e) for t, e, _, _ in (_parse_slot_row(row) for row in raw)]


def slot_anchor_map(category: str | None = None) -> dict[int, str]:
    """Return {var_number: anchor_word_description} for debugging / prompt use."""
    raw = CATEGORY_SLOT_DEFINITIONS.get(category or "", DEFAULT_SLOT_DEFINITIONS)
    return {i + 1: _parse_slot_row(row)[2] for i, row in enumerate(raw)}


def slot_anchor_position_map(category: str | None = None) -> dict[int, str]:
    """Return {var_number: 'before'|'after'} for anchored-slot categories."""
    raw = CATEGORY_SLOT_DEFINITIONS.get(category or "", DEFAULT_SLOT_DEFINITIONS)
    return {i + 1: _parse_slot_row(row)[3] for i, row in enumerate(raw)}


def anchored_phrase(var_num: int, category: str) -> str:
    """Exact phrase the LLM should emit, with [[VARn]] as the swap token."""
    anchor = slot_anchor_map(category)[var_num].strip()
    token = f"[[VAR{var_num}]]"
    if slot_anchor_position_map(category)[var_num] == "after":
        return f"{token} {anchor}"
    return f"{anchor} {token}"


def build_canary_instruction(category: str, var_nums: list[int]) -> str:
    """Prompt fragment listing required anchored [[VARn]] phrases for a section."""
    if not var_nums:
        return ""
    phrases = "\n".join(f"  - {anchored_phrase(n, category)}" for n in var_nums)
    return (
        "You MUST include each of the following phrases in this section EXACTLY ONCE "
        "(copy the anchor words and [[VARn]] token verbatim; do not paraphrase; "
        "do not repeat any [[VARn]] token anywhere on the page):\n"
        f"{phrases}\n"
        "Weave each phrase into a natural sentence. Do not use any other [[VARn]] tokens "
        "in this section beyond those listed above."
    )


def _build_padding_sentence(anchor: str, var_token: str, pos: str,
                            rng: random.Random = random) -> str:
    """Return a varied readable sentence with anchor immediately adjacent to var_token.

    The anchor+var adjacency must be preserved so validate_anchored_slots_in_html passes.
    var_token is either '[[VARn]]' (raw sections) or '{{ varn }}' (assembled HTML).
    rng is used to pick from pools of sentence variants.
    """
    v = var_token  # shorthand

    if pos == "after":
        # var_token precedes the anchor noun suffix (e.g. "{{ var1 }} County")
        return rng.choice([
            f"It is associated with the {v} {anchor}.",
            f"The area is commonly linked to the {v} {anchor}.",
            f"References to the {v} {anchor} appear throughout its history.",
            f"Its connection to the {v} {anchor} is well documented.",
            f"The {v} {anchor} has long been part of its identity.",
        ])

    a = anchor.strip()
    al = a.lower()
    words = al.split()
    first = words[0] if words else ""
    last = words[-1] if words else ""

    # --- Bare noun role labels (the whole anchor is a role word placed before the name) ---
    _BARE_POOLS: dict[str, list[str]] = {
        "mayor": [
            f"The town's mayor {v} presided over local affairs.",
            f"Mayor {v} served the community with distinction.",
            f"The office was held by mayor {v} for several terms.",
            f"Local governance was shaped by mayor {v}.",
        ],
        "professor": [
            f"A professor {v} was closely associated with the institution.",
            f"Professor {v} contributed significantly to the academic community.",
            f"The faculty included professor {v}, a respected scholar.",
            f"Teaching was led in part by professor {v}.",
        ],
        "alumnus": [
            f"A notable alumnus {v} graduated from the institution.",
            f"Among its graduates, alumnus {v} achieved wide recognition.",
            f"The institution counts alumnus {v} among its distinguished alumni.",
            f"Alumnus {v} went on to make lasting contributions to the field.",
        ],
        "starring": [
            f"The film, starring {v}, earned critical attention.",
            f"Audiences responded warmly to the film starring {v}.",
            f"The production, starring {v}, was widely discussed.",
            f"Starring {v}, the film left a strong impression on reviewers.",
        ],
    }
    if al in _BARE_POOLS:
        return rng.choice(_BARE_POOLS[al])

    # --- "X known as / called / named / titled Y" ---
    for kw in ("known as", "known for", "called", "named", "titled"):
        idx = al.find(kw)
        if idx != -1:
            noun_part = a[:idx].strip()
            art = "an" if noun_part and noun_part[0].lower() in "aeiou" else "a"
            pfx = f"{art} {noun_part}" if noun_part else "it"
            Pfx = pfx[0].upper() + pfx[1:]
            return rng.choice([
                f"{Pfx} {kw} {v} is notable in this context.",
                f"{Pfx} {kw} {v} has played an important role.",
                f"This is associated with {pfx} {kw} {v}.",
                f"{Pfx} {kw} {v} remains significant to this day.",
            ])

    # --- Anchor ends with " of" or " of the" (member of, shrine of, monastery of…) ---
    if al.endswith((" of", " of the")) or al == "of":
        return rng.choice([
            f"It is a {a} {v}.",
            f"The origins trace back to the {a} {v}.",
            f"Much of its character derives from the {a} {v}.",
            f"Its identity is closely tied to the {a} {v}.",
        ])

    # --- Active-voice verbs (do NOT work as passives) ---
    # checked BEFORE _PAST so "collaborated", "worked" are caught here, not there
    _ACTIVE = frozenset({
        "collaborated", "resided", "worked", "originated", "represented",
        "explored", "involves",
    })
    if first in _ACTIVE:
        return rng.choice([
            f"It {a} {v}.",
            f"Notably, it {a} {v}.",
            f"It has long {a} {v}.",
            f"It is known that it {a} {v}.",
        ])

    # --- Past-participle / passive constructions ---
    _PAST = frozenset({
        "born", "founded", "directed", "produced", "coached", "filmed",
        "exhibited", "trained", "studied", "identified", "treated",
        "diagnosed", "developed", "manufactured", "created", "distributed",
        "published", "sponsored", "maintained", "recognized", "recorded",
        "traditionally", "documented", "advised", "opposed", "mentored",
        "collected", "held", "supported", "affiliated", "researched",
        "standardized", "worshipped", "practiced", "commemorated",
        "premiered", "screened", "served", "worn", "sold", "made", "dyed",
        "situated", "spoken", "reviewed", "headquartered", "appointed",
        "associated", "located", "related", "based", "preserved",
        "protected", "displayed",
        # adjectives / copular that work with "It was ___"
        "active", "known", "used", "set",
        # additional past participles found in slot anchors
        "written", "led", "partnered", "prepared", "seasoned", "monitored",
        "reported", "featured",
    })
    if first in _PAST:
        return rng.choice([
            f"It was {a} {v}.",
            f"This was {a} {v}.",
            f"It is widely noted for being {a} {v}.",
            f"Records confirm it was {a} {v}.",
        ])

    # --- Present-tense 3rd-person verbs ---
    _PRESENT = frozenset({
        "lives", "relies", "grows", "inhabits", "represents",
        "explores", "involves", "maintains", "features", "can",
    })
    if first in _PRESENT:
        return rng.choice([
            f"It {a} {v}.",
            f"Notably, it {a} {v}.",
            f"It largely {a} {v}.",
            f"It regularly {a} {v}.",
        ])

    # --- Preposition as first word ---
    _PREPS = frozenset({
        "in", "at", "near", "along", "throughout", "around", "on",
        "during", "from", "to", "into", "under", "across", "within",
        "for", "between", "of", "with", "by",
    })
    if first in _PREPS:
        return rng.choice([
            f"It is {a} {v}.",
            f"This is {a} {v}.",
            f"It has long been {a} {v}.",
            f"It is well known for being {a} {v}.",
        ])

    # --- Noun phrase with trailing preposition (e.g. "literary scene in", "office located in") ---
    # Must be checked before the "ends with ' to/with/for'" branch which handles the
    # tighter "rivalry with" / "pilgrimage to" patterns.
    if last in _PREPS:
        art = "an" if a[0].lower() in "aeiou" else "a"
        return rng.choice([
            f"There is {art} {a} {v}.",
            f"It is associated with {art} {a} {v}.",
            f"This is linked to {art} {a} {v}.",
            f"It involves {art} {a} {v}.",
        ])

    # --- Noun + preposition tail (e.g. "rivalry with", "pilgrimage to") ---
    if al.endswith((" to", " with", " for", " in", " at", " on")):
        art = "an" if first and first[0].lower() in "aeiou" else "a"
        return rng.choice([
            f"It involves {art} {a} {v}.",
            f"There is {art} {a} {v} at the heart of this.",
            f"Central to its story is {art} {a} {v}.",
            f"It is defined in part by {art} {a} {v}.",
        ])

    # --- Generic fallback (noun phrase with no trailing prep) ---
    art = "an" if a[0].lower() in "aeiou" else "a"
    return rng.choice([
        f"There is {art} {a} {v}.",
        f"It is associated with {art} {a} {v}.",
        f"This relates to {art} {a} {v}.",
        f"It involves {art} {a} {v}.",
    ])


def anchored_clause(var_num: int, category: str,
                    rng: random.Random = random) -> str:
    """A varied complete sentence embedding anchor + {{ varN }} for padding missing slots."""
    return _build_padding_sentence(
        slot_anchor_map(category)[var_num],
        "{{ var%d }}" % var_num,
        slot_anchor_position_map(category)[var_num],
        rng,
    )


NAMED_VAR_RE = re.compile(r"\[\[VAR(\d+)\]{1,2}", re.I)


def is_named_var_placeholder(inner: str) -> bool:
    return bool(re.match(r"^VAR\d+$", inner.strip(), re.I))


def substitute_named_vars(text: str) -> tuple[str, set[int]]:
    """Replace [[VARn]] with {{ varn }}; return (text, set of var numbers used)."""
    used: set[int] = set()

    def repl(m):
        n = int(m.group(1))
        if 1 <= n <= 10:
            used.add(n)
            return f"{{{{ var{n} }}}}"
        return m.group(0)

    return NAMED_VAR_RE.sub(repl, text), used


def strip_stray_placeholders(text: str) -> str:
    """Remove [[NAME]] and numeric placeholders; keep [[VARn]] intact."""
    def repl(m):
        inner = m.group(0)[2:-2]
        if is_named_var_placeholder(inner):
            return m.group(0)
        if is_numeric_placeholder(inner):
            return ""
        return ""
    return re.sub(r"\s+", " ", PLACEHOLDER_RE.sub(repl, text)).strip()


def sections_use_named_vars(sections: list[tuple[str, str]]) -> bool:
    combined = " ".join(prose for _, prose in sections)
    return bool(NAMED_VAR_RE.search(combined))


def validate_raw_named_vars(sections: list[tuple[str, str]]) -> list[str]:
    """Each [[VARn]] must appear exactly once across all section prose."""
    combined = " ".join(prose for _, prose in sections)
    errors = []
    for n in range(1, 11):
        count = len(re.findall(rf"\[\[VAR{n}\]\]", combined, re.I))
        if count != 1:
            errors.append(f"[[VAR{n}]] expected 1 occurrence, found {count}")
    return errors


def _var_to_section_map(category: str) -> dict[int, str]:
    dist = ANCHORED_SLOT_DISTRIBUTION.get(category, {})
    out = {}
    for kind, nums in dist.items():
        for n in nums:
            out[n] = kind
    return out


def _anchored_var_pattern(n: int, category: str) -> re.Pattern:
    """Regex for the canonical anchor+[[VARn]] phrase in raw LLM prose."""
    anchor = slot_anchor_map(category)[n]
    pos = slot_anchor_position_map(category)[n]
    token = rf"\[\[VAR{n}\]\]"
    if pos == "before":
        return re.compile(re.escape(anchor) + r"\s+" + token, re.I)
    return re.compile(token + r"\s+" + re.escape(anchor), re.I)


def _strip_var_token(text: str, n: int) -> str:
    return re.sub(rf"\[\[VAR{n}\]{{1,2}}", "", text, flags=re.I)


def repair_anchored_sections(
    sections: list[tuple[str, str]], category: str,
    rng: random.Random = random,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Ensure each var appears exactly once in its canonical anchored phrase.

    If the LLM omits a phrase, duplicates a token, or places [[VARn]] without
    the required anchor words, strip that var's tokens and append the canonical
    sentence to the var's home section.
    """
    notes: list[str] = []
    by_kind = {kind: prose for kind, prose in sections}
    var_home = _var_to_section_map(category)

    for n in range(1, 11):
        combined = " ".join(by_kind.values())
        pat = _anchored_var_pattern(n, category)
        good_matches = list(pat.finditer(combined))
        bare_count = len(re.findall(rf"\[\[VAR{n}\]{{1,2}}", combined, re.I))

        if len(good_matches) == 1 and bare_count == 1:
            continue

        notes.append(f"normalized [[VAR{n}]]")
        for kind in by_kind:
            by_kind[kind] = _strip_var_token(by_kind[kind], n)
            by_kind[kind] = re.sub(r"\s+", " ", by_kind[kind]).strip()

        kind = var_home.get(n, sections[-1][0])
        sent = _build_padding_sentence(
            slot_anchor_map(category)[n],
            f"[[VAR{n}]]",
            slot_anchor_position_map(category)[n],
            rng,
        )
        by_kind[kind] = (by_kind.get(kind, "") + " " + sent).strip()

    return [(kind, by_kind[kind]) for kind, _ in sections], notes


def validate_anchored_slots_in_html(html: str, category: str) -> list[str]:
    """Verify each var has anchor text immediately before or after {{ varN }}."""
    errors = []
    for n in range(1, 11):
        anchor = slot_anchor_map(category)[n]
        pos = slot_anchor_position_map(category)[n]
        v_pat = r"\{\{ var" + str(n) + r" \}\}"
        if pos == "before":
            pat = re.escape(anchor) + r"\s+" + v_pat
        else:
            pat = v_pat + r"\s+" + re.escape(anchor)
        if not re.search(pat, html, re.I):
            errors.append(
                f"var{n}: missing anchored pattern ({pos} '{anchor}')")
    if re.search(r"\[\[[^\]]+\]{1,2}", html):
        errors.append("unsubstituted [[...]] placeholders remain in HTML")
    return errors


def slot_type_map(category: str | None = None):
    return {i + 1: t for i, (t, _) in enumerate(slot_definitions(category))}


def slot_expr_map(category: str | None = None):
    return {i + 1: e for i, (_, e) in enumerate(slot_definitions(category))}


def var_expressions(category: str | None = None):
    """The 10 faker expressions ordered var1..var10 for the category .txt varList."""
    return [expr for _, expr in slot_definitions(category)]


# Backward-compatible defaults used by older helper code.
SLOT_TYPE = slot_type_map()
SLOT_EXPR = slot_expr_map()

# ---------------------------------------------------------------------------
# Placeholder classification helpers.
# ---------------------------------------------------------------------------
PLACEHOLDER_RE = re.compile(r"\[\[[^\]]+\]{1,2}")

# Substrings that flag a placeholder as numeric -- these are DROPPED, not slotted.
NUM_HINTS = ("NUM", "YEAR", "DATE", "POPULAT", "DISTANCE", "PERCENT", "COUNT",
             "AGE", "NUMBER", "CENSUS", "AREA", "ELEVATION", "DENSITY", "MILE",
             "KM", "ACRE", "SQUARE", "RATE")

# Context cues for name type classification.
PERSON_CUES = re.compile(
    r"(named after|named for|name of (its|the) founder|founded by|\bfounder\b|"
    r"\bmayor\b|postmaster|governor|senator|\brepresentative\b|in honou?r of|"
    r"\bson of\b|\bdaughter of\b|Mr\.|Mrs\.|Ms\.|Dr\.|Sen\.|Gov\.|Rep\.|Gen\.|"
    r"\bnovel\b|who (lived|served|worked|was|founded))", re.I)
ORG_CUES = re.compile(
    r"(home of|headquarters of|according to|\buniversity\b|\bcollege\b|"
    r"\bacademy\b|\bseminary\b|\bschool\b|institute|\bcompany\b|corporation|"
    r"railroad|railway|rail stop on the|\bbank\b|hospital|\bchurch\b|"
    r"department of|\bbureau\b)", re.I)
AFTER_PERSON_CUE = re.compile(
    r"^\W*(was|is|served as|became)\b.{0,30}?"
    r"(mayor|postmaster|founder|governor|senator|president|settler)", re.I)


def classify_name(before: str, after: str) -> str:
    """Best-effort type for a [[NAME]] from its surrounding words."""
    window = before[-60:]
    if PERSON_CUES.search(window):
        return "person"
    if ORG_CUES.search(window):
        return "org"
    if AFTER_PERSON_CUE.search(after[:40]):
        return "person"
    return "place"


def is_numeric_placeholder(inner: str) -> bool:
    """Return True if this placeholder represents a number and should be dropped."""
    upper = inner.strip().upper()
    if upper == "NUM":
        return True
    if upper == "NAME":
        return False
    return any(h in upper for h in NUM_HINTS)


# ---------------------------------------------------------------------------
# PlaceholderAssigner: maps EVERY [[NAME]] placeholder across the whole page,
# in document order, onto a {{ varN }} slot -- ONE TO ONE. Each of the 10 vars
# is used at most once. Once all 10 are assigned, any further [[NAME]]
# placeholders are replaced with a generic noun phrase (not a var), so no var
# is ever reused in two different grammatical roles.
#
# Usage:
#   assigner = PlaceholderAssigner(rng)
#   assigner.plan(piece1 + piece2 + ... )   # full concatenation, IN THE SAME
#                                            # ORDER pieces will be apply()'d
#   out1 = assigner.apply(piece1)
#   out2 = assigner.apply(piece2)
#   ...
# apply() must be called on the pieces in the SAME ORDER (and with the SAME
# placeholder content) as they were concatenated for plan() -- it consumes
# assignments from an ordered queue, one per placeholder occurrence.
# ---------------------------------------------------------------------------

# Generic noun substitutes for [[NAME]] placeholders beyond the 10-var budget.
# NOTE: Place entries intentionally omit leading articles ("the"/"a") so that
# substitution into prose contexts like "The [[NAME]] …" or "in the [[NAME]]"
# does not produce double-article artifacts ("The the …", "the a …").
GENERIC_NOUN = {
    "place": [
        "surrounding region", "nearby settlement", "wider landscape",
        "neighbouring area", "broader territory", "local community",
        "countryside", "province", "watershed", "hinterland",
    ],
    "person": [
        "a contemporary", "a close associate", "a fellow practitioner",
        "a local figure", "a long-time collaborator", "a well-known peer",
        "an influential mentor", "a respected colleague",
    ],
    "org": [
        "a prominent institution", "a regional body", "a civic organisation",
        "a professional association", "a governing authority",
        "a cultural foundation", "a scholarly society",
    ],
    "subject": [
        "a related tradition", "a connected practice", "an associated term",
        "a related concept", "a known variant",
    ],
}


# Sentinel used when a [[NAME]] placeholder cannot be mapped to a {{ varN }}
# slot.  Sentences that still contain this string after apply() are dropped
# so that no generic noun phrases or broken grammar reach the final HTML.
_OVERFLOW_SENTINEL = "\x00OVERFLOW\x00"


class PlaceholderAssigner:
    """Plans a one-to-one mapping of [[NAME]] placeholders to {{ varN }} slots
    across a piece of text, then applies that mapping to individual pieces of
    text in the same order they were planned.

    Args:
        rng: random source for generic-noun fallback choices.
        reserve: number of non-subject vars to leave UNUSED on purpose (made
            available via unused_vars() afterwards for a second assigner to
            use, e.g. for footer/landmarks).
        subject_var: which var number is the "subject" (var1 by default).
            Pass the SAME value used by a prior body-section assigner so a
            second assigner (for footer/landmarks) treats that var as already
            claimed and available for the subject's recurring mentions.
        available_vars: if given, ONLY these var numbers may be assigned
            (plus subject_var, which is always implicitly available for
            sentence-initial place placeholders). Used to restrict a
            second-pass assigner to the vars reserved by a first pass.
    """

    def __init__(self, rng: random.Random, reserve: int = 0,
                subject_var: int = 1, available_vars: list[int] = None,
                category: str | None = None, static_subject: str | None = None):
        self.rng = rng
        self.subject = subject_var
        self.reserve = reserve
        self.category = category
        self.static_subject = (static_subject or '').strip()
        self.slot_type = slot_type_map(category)
        self._available = set(available_vars) if available_vars is not None else set(ALL_VARS)
        self._queue = []        # ordered list of replacement strings, one per placeholder
        self._used_vars = set()
        self._planned = False

    def _candidates_of_type(self, slot_type: str):
        return [v for v in ALL_VARS
                if v in self._available and v not in self._used_vars and self.slot_type[v] == slot_type]

    def _next_var_of_type(self, slot_type: str, headroom: int = 0):
        """Return an unused, available var of slot_type, or None if doing so
        would leave fewer than `headroom` non-subject vars unused overall."""
        candidates = self._candidates_of_type(slot_type)
        if not candidates:
            return None
        if headroom > 0:
            # Count how many non-subject vars are currently unused/available.
            free_now = [v for v in ALL_VARS
                        if v in self._available and v not in self._used_vars and v != self.subject]
            if len(free_now) <= headroom:
                return None
        return candidates[0]

    def _next_var_any(self, headroom: int = 0):
        for slot_type in ("place", "person", "org", "subject"):
            v = self._next_var_of_type(slot_type, headroom=headroom)
            if v is not None:
                return v
        return None

    def plan(self, full_text: str):
        """Walk every [[...]] placeholder in full_text in order and assign it
        to a var (one-to-one) or a generic noun phrase if over budget.
        Builds self._queue, consumed in the same order by apply()."""
        if self._planned:
            return
        self._planned = True

        matches = list(PLACEHOLDER_RE.finditer(full_text))

        subject_indices = set()
        first_subject_idx = None
        for idx, m in enumerate(matches):
            inner = m.group(0)[2:-2]
            if is_numeric_placeholder(inner):
                continue
            before = full_text[:m.start()]
            after = full_text[m.end():]
            t = classify_name(before, after)
            sentence_initial = (before.strip() == "" or before.rstrip()[-1:] in ".!?:")
            if t == "place" and sentence_initial:
                if first_subject_idx is None:
                    first_subject_idx = idx
                if self.static_subject:
                    subject_indices.add(idx)
        if first_subject_idx is None:
            for idx, m in enumerate(matches):
                inner = m.group(0)[2:-2]
                if is_numeric_placeholder(inner):
                    continue
                before = full_text[:m.start()]
                after = full_text[m.end():]
                if classify_name(before, after) == "place":
                    first_subject_idx = idx
                    break

        if not subject_indices and first_subject_idx is not None:
            subject_indices.add(first_subject_idx)

        if subject_indices and not self.static_subject:
            self._used_vars.add(self.subject)

        # Walk all placeholders in order, building the replacement queue.
        for idx, m in enumerate(matches):
            inner = m.group(0)[2:-2]

            if idx in subject_indices:
                if self.static_subject:
                    self._queue.append(self.static_subject)
                else:
                    self._queue.append("{{ var%d }}" % self.subject)
                continue

            if is_numeric_placeholder(inner):
                self._queue.append("")  # drop numeric placeholders entirely
                continue

            before = full_text[:m.start()]
            after = full_text[m.end():]
            t = classify_name(before, after)

            v = self._next_var_of_type(t, headroom=self.reserve)
            if v is None:
                v = self._next_var_any(headroom=self.reserve)

            if v is not None:
                self._queue.append("{{ var%d }}" % v)
                self._used_vars.add(v)
            else:
                # Mark as overflow — the sentence will be dropped in apply().
                self._queue.append(_OVERFLOW_SENTINEL)

        self._iter = iter(self._queue)

    def unused_vars(self) -> list[int]:
        """Available vars (excluding the subject) that were never assigned to
        a placeholder -- e.g. the ones reserved via `reserve` and left free
        for a second-pass assigner."""
        return [v for v in ALL_VARS
                if v in self._available and v not in self._used_vars
                and (self.static_subject or v != self.subject)]

    def apply(self, text: str) -> str:
        """Substitute placeholders in `text`, consuming from the shared queue
        built by plan(). Must be called on pieces in the same order (and with
        the same placeholder occurrences) as the text passed to plan().

        Sentences that contain the overflow sentinel (i.e. a [[NAME]] that
        could not be mapped to a {{ varN }} slot) are dropped entirely so that
        no generic noun phrases reach the final HTML.
        """
        def repl(m):
            try:
                return next(self._iter)
            except StopIteration:
                inner = m.group(0)[2:-2]
                if is_numeric_placeholder(inner):
                    return ""
                return _OVERFLOW_SENTINEL
        substituted = PLACEHOLDER_RE.sub(repl, text)
        # Drop any sentence that contains the overflow sentinel.
        sentences = split_sentences(substituted)
        clean = [s for s in sentences if _OVERFLOW_SENTINEL not in s]
        result = " ".join(clean) if clean else ""
        return result


# ---------------------------------------------------------------------------
# Text cleanup: strip mojibake, coordinates, and ALL literal numbers.
# ---------------------------------------------------------------------------
MOJIBAKE = {
    "\xc2\xb0": "\u00b0",        # Â° -> °
    "\xe2\x80\xb2": "\u2032",    # â€² -> ′
    "\xe2\x80\xb3": "\u2033",    # â€³ -> ″
    "\xe2\x80\x93": "\u2013",    # â€" -> –
    "\xe2\x80\x94": "\u2014",    # â€" -> —
    "\xe2\x80\x99": "\u2019",    # â€™ -> '
    "\xe2\x80\x98": "\u2018",    # â€˜ -> '
    "\xe2\x80\x9c": "\u201c",    # â€œ -> "
    "\xe2\x80\x9d": "\u201d",    # â€\x9d -> "
    "\xc2": "",                   # bare Â
}
COORD_RE     = re.compile(r"\d+\s*°\s*\d+\s*[′']?\s*\d*\s*[″\"]?\s*[NSEWnsew]\b")
LITERAL_NUM_RE = re.compile(r"(?<![\w°′″])-?\d[\d,]*(?:\.\d+)?(?![\w°′″])")
ORDINAL_RE   = re.compile(r"\b\d+(st|nd|rd|th)\b", re.I)
PERCENT_RE   = re.compile(r"\b\d+(\.\d+)?\s*(%|percent|percentage)\b", re.I)

_NUMBER_WORD_LIST = [
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
    "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    "sixteen", "seventeen", "eighteen", "nineteen", "twenty", "thirty",
    "forty", "fifty", "sixty", "seventy", "eighty", "ninety",
    "hundred", "thousand", "million", "billion", "trillion", "dozen",
    "first", "second", "third", "fourth", "fifth", "sixth", "seventh",
    "eighth", "ninth", "tenth", "eleventh", "twelfth", "thirteenth",
    "fourteenth", "fifteenth", "sixteenth", "seventeenth", "eighteenth",
    "nineteenth", "twentieth", "thirtieth", "fortieth", "fiftieth",
    "sixtieth", "seventieth", "eightieth", "ninetieth", "hundredth",
    "single", "double", "triple", "quadruple",
    "half", "quarter",
]
NUMBER_WORD_RE = re.compile(
    r"\b(?:" + "|".join(_NUMBER_WORD_LIST) + r")\b", re.I)

DATE_WORD_RE = re.compile(
    r"\b(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December|"
    r"Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|"
    r"spring|summer|autumn|fall|winter|"
    r"century|centuries|decade|decades|millennium|millennia|era|eras)\b",
    re.I)

UNIT_WORD_RE = re.compile(
    r"\b(?:kilometres?|kilometers?|miles?|metres?|meters?|feet|foot|inches?|inch|"
    r"yards?|acres?|hectares?|kilograms?|kg|pounds?|lbs?|tons?|tonnes?|"
    r"degrees?|celsius|fahrenheit|percent(?:age)?|"
    r"litres?|liters?|gallons?|"
    r"square\s+(?:miles?|kilometres?|kilometers?|feet|metres?|meters?))\b",
    re.I)


def fix_mojibake(text: str) -> str:
    for bad, good in MOJIBAKE.items():
        text = text.replace(bad, good)
    return text


NUMERIC_PATTERNS = (
    COORD_RE, LITERAL_NUM_RE, ORDINAL_RE, PERCENT_RE,
    NUMBER_WORD_RE, DATE_WORD_RE, UNIT_WORD_RE,
)


def count_numeric_hits(sentence: str) -> int:
    """Count how many numeric/date/unit matches a sentence contains."""
    return sum(len(p.findall(sentence)) for p in NUMERIC_PATTERNS)


def sentence_has_number(sentence: str) -> bool:
    return count_numeric_hits(sentence) > 0


def _strip_numeric_tokens(sentence: str) -> str:
    """Best-effort in-place removal of numeric/date/unit tokens from a single
    sentence, with light cleanup. Used ONLY for filler sentences in
    strip_numeric_sentences when too few fully-clean sentences exist --
    accepts minor grammatical roughness in exchange for guaranteeing no
    number/date/unit survives."""
    s = sentence
    s = COORD_RE.sub("", s)
    s = re.sub(r"[°′″]", "", s)
    s = ORDINAL_RE.sub("", s)
    s = PERCENT_RE.sub("", s)
    s = LITERAL_NUM_RE.sub("", s)
    s = NUMBER_WORD_RE.sub("", s)
    s = DATE_WORD_RE.sub("", s)
    s = UNIT_WORD_RE.sub("", s)
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"\s+([,.;:!?')])", r"\1", s)
    for _ in range(3):
        s = re.sub(
            r"\b(a|an|the|of|by|in|on|at|over|under|about|nearly|roughly|"
            r"around|its|for|with|since|until|to|from|and|or|but|reached|"
            r"spans|sits)\s*(?=[,.;:!?]|$)",
            "", s, flags=re.I)
        s = re.sub(r"\s+", " ", s).strip()
        s = re.sub(r"\s+([,.;:!?')])", r"\1", s)
    s = re.sub(r"\s*,\s*,", ",", s)
    s = re.sub(r",\s*\.", ".", s)
    s = re.sub(r"^\s*[,.]+\s*", "", s)
    return re.sub(r"\s+", " ", s).strip()


def strip_numeric_sentences(text: str, min_keep: int = 3) -> str:
    """Drop every sentence containing numbers, dates, measurements, or quantity words."""
    sentences = split_sentences(text)
    if not sentences:
        return text
    clean = [s for s in sentences if not sentence_has_number(s)]
    return " ".join(clean)

def tidy(text: str) -> str:
    """Whitespace and punctuation cleanup."""
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s+([,.;:!?')])", r"\1", text)
    text = re.sub(r"([('])\s+", r"\1", text)
    text = re.sub(r"\(\s*[^()]{0,8}\s*\)", "", text)
    text = re.sub(r"(\[\[NAME\]\])(\s+\1)+", r"\1", text)
    text = re.sub(r"[$£€]\s*(?=[\s,.;:!?]|$)", "", text)
    text = re.sub(r"\s*,\s*,", ",", text)
    text = re.sub(r",\s*\.", ".", text)
    text = re.sub(r"\s+,", ",", text)
    text = re.sub(r"^\s*,\s*", "", text)
    text = re.sub(r",\s*$", "", text)
    return re.sub(r"\s+", " ", text).strip()


def split_sentences(text: str):
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]


# Patterns that indicate a sentence became incoherent after placeholder removal:
# orphaned preposition before a conjunction/punctuation, double commas, etc.
_BROKEN_SENTENCE_RE = re.compile(
    r"""
    \b(?:in|at|by|of|to|from|with|for|on|under|near|about|between|among|over|
        through|before|after|around|into|onto|within|without|against|across|
        beside|behind|above|below|upon)
    \s*(?:and|or|but|,|\.|;|:)      # preposition immediately before conjunction/punctuation
    | ,\s*,                           # double comma
    | \b(?:in|at|of|to|from|by|for|on)\s*\.   # preposition directly before period
    | \b(?:at|to|in|of|from|by|for|on)\s+(?:at|to|in|of|from|by|for|on)\b  # consecutive prepositions
    | \b(?:was|were|is|are|had|has|been)\s*[.!?]\s*$    # bare copula with no complement
    | \bthe\s*[,.]                    # article directly before punctuation (stripped noun)
    | \b(?:The|A|An)\s+(?:was|were|is|are|has|have|had|been|will|would|could|should)\b  # article directly before verb (noun stripped)
    | \bthe\s+(?:and|or|but|nor)\b   # article directly before conjunction (noun stripped)
    | \bwas\s+(?:at|in|on|of)\s+the\b  # "was at/in the [noun]" — number stripped leaving bare prep
    | ^\s*[,;]\s*\w                   # sentence starts with comma/semicolon (stripped [[NAME]] artifact)
    | ^\s*(?:In|On|At)\s+(?:he|she|they|it|the)\s+\w  # "In he entered" / "On the held" — stripped year/name
    | \b(?:classified|known|described|referred|regarded|identified|recognised|categorised)\s+as\s*[.!?]\s*$  # "classified as." with no object (stripped name)
    | \b(?:includes?|contains?|comprises?|encompasses?|features?|spans?|depicts?|shows?|involves?|represents?|consists?)\s*,\s*(?:and|or)\b  # empty list: "includes, and"
    | ,\s*(?:and|or)\s*[.!?]\s*$  # comma+conjunction at sentence end (stripped list items)
    | \b(?:as well as|along with|together with|in addition to)\s*[.!?,;]  # stripped conjunction phrase with no following noun
    """,
    re.IGNORECASE | re.VERBOSE,
)


def drop_broken_sentences(text: str) -> str:
    """Drop sentences that became grammatically broken after placeholder removal.

    Targets patterns like 'born in and died', ', ,', 'married at to', etc.
    If dropping would leave nothing, returns the original text unchanged.
    """
    sentences = split_sentences(text)
    clean = [s for s in sentences if not _BROKEN_SENTENCE_RE.search(s)]
    return " ".join(clean) if clean else text


# Patterns that indicate a sentence is a Wikipedia artifact or filler fragment
# that should never appear in the final prose.
_ARTIFACT_SENTENCE_RE = re.compile(
    r"""
    # Wikipedia section header fragments leaked into body text
    ^\s*(?:Taxonomy\s+and\s+naming|References|External\s+links|See\s+also|
           Further\s+reading|Notes|Sources|Bibliography|Contents|
           The\s+following\s+(?:are|is|were)|Division\b|School\b|
           Category\s*:|File\s*:|Image\s*:)
    # Bare verb at start — subject was stripped (Wikipedia article style)
    | ^\s*(?:was|were|is|are|has|have|had)\s+(?:a|an|the|also|one|part|known|
             called|referred|based|established|founded|named|located|used|
             considered|regarded|described|noted|born|died|married|formed|
             created|released|published|written|directed|produced)\b
    # Clearly incomplete fragment — starts with conjunction or punctuation
    | ^\s*(?:and|or|but|nor|so|yet|however|therefore|thus|moreover|
             furthermore|additionally|consequently|nevertheless)\b
    # "The following" list intro or "consists of the following"
    | the\s+following\s+(?:are|is|were|players|teams|members|people|films|books|teams)
    | consists\s+of\s+the\s+following
    # Double square bracket artifacts not part of a [[VARn]] or [[NAME]] pattern
    | \[\[(?!(?:VAR|NAME))[^\]]*\]\]
    # Parenthetical-opener: date/number stripped leaving "(born )" or "(– )" or "()"
    | ^\s*\([^)a-zA-Z\{\}]{0,30}\)\s+(?:is|was|are|were)\b
    # Parenthetical with mostly non-alphabetic content (stripped numbers/dates)
    | \(\s*(?:[–\-\s,\.]+|also\s+known\s+as\s+\w{0,6}\s*)\)
    # Number stripped leaving dangling preposition: "in with", "in the show"
    | \b(?:in|at|by|from|of|to)\s+(?:with|the\s+show|the\s+series|the\s+film|the\s+game)\b
    # Academic degree bullet lists: "B.S.", "M.S.", "Ph.D", "D.Sc"
    | \b(?:B\.S|M\.S|Ph\.D|D\.Sc|A\.G\.S|B\.A|M\.A|LL\.B|M\.B\.A)\b
    # Dash/colon score-table artifacts: "–: –: –:" from sport records
    | (?:[–\-]\s*:\s*){2,}
    # Dash artifacts from stripped numbers: "– –", "- -"
    | (?:–\s*){2,}
    | \bpart\s+of\s+the\s+[–\-]\s*[–\-]
    | \bthe\s+[–\-]\s+[–\-]
    # Bare hyphen artifact from stripped number before descriptive word:
    # "a -year program", "an -born artist", "the -long series"
    | \b(?:a|an|the)\s+-(?:year|born|long|time|day|week|month|old|strong|foot|mile|page|hour)\b
    | \s+-(?:year|born|long|time|day|week|month|old|strong|foot|mile|page|hour)\b
    # Possessive artifact: "in's", "of's" (number stripped before "'s")
    | \b(?:in|of|at|by|to|from|with|on)\s*'\s*s\b
    # Broken double-subject: "involves a there is", "in the in the"
    | \binvolves\s+a\s+there\s+is\b
    | \bin\s+the\s+in\s+the\b
    # Sentence starting with bare "In the" followed immediately by a verb (date stripped)
    | ^\s*In\s+the\s+(?:land|area|region|city|town|country|village)\s+(?:became|was|were|had|is)\b
    # Real-world game/film descriptions leaking
    | \bis\s+a\s+(?:board\s+game|video\s+game|card\s+game|role.playing\s+game)\s+based\s+on\b
    # Named of the Year with stripped subject
    | \bnamed\s+of\s+the\s+Year\b
    # "It is part of the – –" or similar dash runs
    | \bpart\s+of\s+the\s*[–\-\s,\.]{2,}
    # Subject-verb disagreement from mangled Wikipedia text: "It are"
    | ^\s*(?:It|He|She|They)\s+are\s+an?\s+international\b
    # Doubled word artifact: "Theory theory", "Division Division"
    | \b([A-Z][a-z]+)\s+\1\b
    # Stripped-number family/count sentences
    | \b(?:had|have|has)\s+(?:brothers?|sisters?|children|sons?|daughters?|wives?|husbands?)\s*[,.]
    # "since and has been", "taught in since" — stripped years leave dangling prepositions
    | \bsince\s+and\b
    | \btaught\s+in\s+since\b
    | \bin\s+since\b
    # Standalone "He is married to the former" (stripped name)
    | \bmarried\s+to\s+the\s+former\s*[,.]
    # Repeated "Division" pattern
    | (?:\bDivision\s+){3,}
    # List-like repeated short tokens (score tables, bullet fragments)
    | (?:\b\w{2,8}\s+){0,2}(?:[–\-:]\s*){3,}
    # Stripped-year "In he/she/they..." sentence (date stripped before subject)
    | ^\s*In\s+(?:he|she|they|it|the)\s+(?:married|entered|became|was|were|moved|joined|left|served|died|born|attended|graduated|returned|founded|created|led|won|received)\b
    # Sentence starting with a comma or semicolon (broken split artifact)
    | ^\s*[,;]\s*\w
    # "was appointed as" / "was active in" with no subject at start
    | ^\s*(?:was|were)\s+(?:appointed|active|a\s+member|elected|named|awarded|known|considered|regarded)\b
    # Naked "and was", "and is", "and has" starting a sentence (conjunction left dangling)
    | ^\s*(?:and|but|or)\s+(?:was|were|is|are|has|have|had)\b
    # Wikipedia population statistics artifacts (stripped numbers leave broken census sentences)
    | \bThere\s+were\s+households\b
    | \baged\s+or\s+older\b
    | \bout\s+of\s+them\s+were\s+occupied\b
    | \bhad\s+someone\s+living\s+alone\b
    # Stripped-number animal/species "declined times since" pattern
    | \bdeclined\s+times\s+since\b
    # Stripped fraction/percent: "but of the [noun] remained", "percent of the"
    | \bbut\s+of\s+the\b
    | \bpercent\s+of\s+the\b
    # Library/stats: "contains and a total of" / "a total of books"
    | \bcontains\s+and\s+a\s+total\s+of\b
    | \ba\s+total\s+of\s+books\b
    # Geographic artifact leaking into non-geographic templates (island, diameter, elevation)
    | \bis\s+an?\s+island\b
    | \bin\s+diameter\b
    | \bpeak\s+altitude\b
    | \bmaximum\s+elevation\b
    | \babove\s+sea\s+level\b
    | \blong\s+and\s+wide\b
    | \baverage\s+depth\b
    # Medical/clinical stripped-number: "underwent a partial resection...but of the"
    | \bpartial\s+resection\b
    # Measurement artifacts from stripped numbers: "in diameter", "in height", "in width"
    | \bis\s+in\s+(?:diameter|height|width|length|depth)\b
    | \bthat\s+is\s+in\s+(?:diameter|height|width|length)\b
    # "known as," with nothing following (stripped name artifact)
    | \bknown\s+as\s*,\s*with\b
    # Sports "won the in" — stripped trophy/tournament name
    | \bwon\s+the\s+in\b
    """,
    re.IGNORECASE | re.VERBOSE,
)


def drop_artifact_sentences(text: str) -> str:
    """Remove sentences that are Wikipedia boilerplate, section header leakage,
    filler fragments, or bare-verb openers with no subject.

    If dropping would leave nothing, returns the original text unchanged.
    """
    sentences = split_sentences(text)
    clean = [s for s in sentences if not _ARTIFACT_SENTENCE_RE.search(s)]
    return " ".join(clean) if clean else text


def fix_person_pronouns(text: str) -> str:
    """Replace impersonal 'it'/'its' with 'they'/'their' for person-category prose.

    Applied sentence-by-sentence after generation for biography, artists,
    historical_figures, political_figures, and scientists_inventors so the
    prose reads naturally about a person rather than an object.
    """
    sentences = split_sentences(text)
    fixed = []
    for s in sentences:
        # Step 1: Replace compound forms FIRST so "It is" → "They are" before the catch-all
        # fires.  (If catch-all ran first, "It is" → "They is" and the compound pattern
        # would no longer match.)
        s = re.sub(r'\bIt is\b',  'They are', s)
        s = re.sub(r'\bIt was\b', 'They were', s)
        s = re.sub(r'\bIt has\b', 'They have', s)
        s = re.sub(r'\bIt had\b', 'They had', s)
        s = re.sub(r'\bit is\b',  'they are', s)
        s = re.sub(r'\bit was\b', 'they were', s)
        s = re.sub(r'\bit has\b', 'they have', s)
        s = re.sub(r'\bit had\b', 'they had', s)
        # Step 2: Possessives (case-sensitive capital + lowercase)
        s = re.sub(r'\bIts\b', 'Their', s)
        s = re.sub(r'\bits\b', 'their', s)
        # Step 3: Sentence-initial catch-all (runs AFTER compounds so "It is" already gone)
        s = re.sub(r'^It\b', 'They', s)
        # Step 4: Reporting-verb "it" → "they" mid-sentence
        s = re.sub(r'\b(confirm|confirms|confirmed|note|notes|noted|suggest|suggests|suggested|'
                   r'indicate|indicates|indicated|show|shows|showed|known\s+that|report|reports|'
                   r'reported|document|documents|documented|record|records|recorded)\s+it\b',
                   lambda m: m.group(1) + ' they', s, flags=re.IGNORECASE)
        # Step 5: "it collaborated", "it worked", etc. (bare pronoun as mid-sentence subject)
        s = re.sub(r'\bit (collaborated|worked|resided|represented|developed|created|'
                   r'produced|published|wrote|directed|founded|established|led|served|'
                   r'joined|left|returned|moved|studied|trained|taught|practised|practiced|'
                   r'received|won|earned|gained|became|held|took|made|gave|brought|drew|'
                   r'employed|used|built|designed|discovered|invented|published|authored|'
                   r'explored|advanced|pioneered|inspired|influenced|transformed)\b',
                   lambda m: 'they ' + m.group(1), s, flags=re.IGNORECASE)
        # Step 6: Fix "This was born/mentored/studied..." → "They were born/..." for persons
        s = re.sub(r'\bThis was (born|mentored|studied|advised|trained|educated|'
                   r'raised|appointed|elected|recognised|recognized)\b',
                   lambda m: 'They were ' + m.group(1), s)
        # Step 7: Fix subject-verb agreement introduced by pronoun swaps
        # ("They is" → "They are", "They was" → "They were", etc.)
        s = re.sub(r'\bThey is\b', 'They are', s)
        s = re.sub(r'\bThey was\b', 'They were', s)
        s = re.sub(r'\bThey has\b', 'They have', s)
        s = re.sub(r'\bthey is\b', 'they are', s)
        s = re.sub(r'\bthey was\b', 'they were', s)
        s = re.sub(r'\bthey has\b', 'they have', s)
        fixed.append(s)
    return ' '.join(fixed)


def reduce_placeholders(text: str, max_placeholders: int, rng: random.Random) -> str:
    """Keep up to max_placeholders [[NAME]] tokens.

    Strategy (Issue 1 fix):
    - Drop any sentence that is 'gibberish' (>50 % of its words are [[NAME]]).
    - For the remaining sentences, keep them in order until the cumulative
      [[NAME]] count would exceed max_placeholders, then drop the whole sentence
      rather than substituting a generic noun.  This guarantees no GENERIC_NOUN
      strings reach the final HTML body, so the prose stays clean.
    - Numeric placeholders ([[NUM]], [[YEAR]], etc.) are always stripped in-place
      because they are single tokens and do not break surrounding grammar.
    """
    if max_placeholders <= 0:
        # No cap — only strip numeric placeholders in-place.
        matches = list(PLACEHOLDER_RE.finditer(text))
        result = text
        for m in sorted(matches, key=lambda x: x.start(), reverse=True):
            inner = m.group(0)[2:-2]
            if is_numeric_placeholder(inner):
                result = result[:m.start()] + result[m.end():]
        return re.sub(r"\s+", " ", result).strip()

    sentences = split_sentences(text)
    if not sentences:
        return text

    kept = 0
    result_sentences = []
    for s in sentences:
        # Strip numeric placeholders in-place first.
        s_clean = PLACEHOLDER_RE.sub(
            lambda m: "" if is_numeric_placeholder(m.group(0)[2:-2]) else m.group(0), s)
        s_clean = re.sub(r"\s+", " ", s_clean).strip()

        name_phs = PLACEHOLDER_RE.findall(s_clean)
        n_ph = len(name_phs)
        n_words = len(s_clean.split())

        # Drop gibberish sentences (more than half of words are placeholders).
        if n_words > 0 and n_ph / n_words > 0.5:
            continue

        # Drop sentence if accepting it would push us over budget.
        if kept + n_ph > max_placeholders:
            continue

        result_sentences.append(s_clean)
        kept += n_ph

    return " ".join(result_sentences) if result_sentences else text


def trim_section(text: str, max_placeholders: int, rng: random.Random = None) -> str:
    if rng is None:
        rng = random
    return reduce_placeholders(text, max_placeholders, rng)


def sentences_to_paragraphs(text: str, per_para: int):
    sents = split_sentences(text)
    paras, chunk = [], []
    for s in sents:
        chunk.append(s)
        if len(chunk) >= per_para:
            paras.append(" ".join(chunk))
            chunk = []
    if chunk:
        paras.append(" ".join(chunk))
    return paras


# ---------------------------------------------------------------------------
# Clean raw prose (mojibake, numbers, placeholder density) WITHOUT converting
# placeholders.
# ---------------------------------------------------------------------------
WIKI_BOILERPLATE_RE = re.compile(
    r"""(
        \bSee\s+also\b               |
        \bExternal\s+links?\b        |
        \bReferences?\b(?:\s+\[)?    |
        \bCitations?\b               |
        \bFootnotes?\b               |
        \bFurther\s+reading\b        |
        \bBibliography\b             |
        \bWorks\s+cited\b            |
        \bContents?\b\s*\[           |
        \[\s*edit\s*\]               |
        \[\s*citation\s+needed\s*\]  |
        \[\s*\d+\s*\]                |
        \bracial\s+makeup\b          |
        \bdemographic\s+breakdown\b  |
        \bethnic\s+composition\b     |
        \baccording\s+to\s+the\s+census\b |
        \bpopulation\s+was\b         |
        \bcensus[-\s]designated\b    |
        \bhousing\s+units?\b
    )""",
    re.I | re.X,
)


def strip_boilerplate_sentences(text: str) -> str:
    """Drop any sentence containing Wikipedia boilerplate markers."""
    sentences = split_sentences(text)
    clean = [s for s in sentences if not WIKI_BOILERPLATE_RE.search(s)]
    taxonomy_re = re.compile(r"\b(genus|family|order|class|phylum|kingdom|species|subfamily|subgenus)\b", re.I)
    # Drop short taxonomy sentences OR any sentence where taxonomy words appear 2+ times
    def _bad_taxonomy(s):
        m = taxonomy_re.findall(s)
        return len(m) >= 2 or (len(m) == 1 and len(s.split()) <= 15)
    clean = [s for s in clean if not _bad_taxonomy(s)]
    return " ".join(clean) if clean else " ".join(sentences[:2])


def clean_prose(prose: str, max_placeholders: int, rng: random.Random,
                min_keep: int = 3) -> str:
    body = tidy(fix_mojibake(prose))
    body = strip_boilerplate_sentences(body)
    body = strip_numeric_sentences(body, min_keep=min_keep)
    body = trim_section(body, max_placeholders, rng)
    body = drop_broken_sentences(body)
    return body


_PAST_PART_STARTERS = frozenset({
    "born", "founded", "directed", "produced", "coached", "filmed",
    "exhibited", "trained", "worked", "studied", "identified",
    "treated", "diagnosed", "developed", "manufactured", "created",
    "distributed", "published", "sponsored", "maintained", "recognized",
    "recorded", "documented", "collaborated", "advised", "opposed",
    "mentored", "collected", "held", "supported", "affiliated",
    "standardized", "worshipped", "practiced", "commemorated",
    "premiered", "screened", "served", "worn", "sold", "made", "dyed",
    "situated", "spoken", "reviewed", "headquartered", "appointed",
    "associated", "located", "based", "preserved", "protected",
    "represented", "displayed", "inspired", "influenced", "traditionally",
    "researched",
})

_SUBJECT_OPENERS = frozenset({
    "it", "he", "she", "they", "we", "you", "this", "these", "those",
    "the", "a", "an", "its", "his", "her", "their", "our", "your",
})

_ORPHAN_STARTERS = _PAST_PART_STARTERS | frozenset({
    "in", "at", "near", "along", "throughout", "around", "on",
    "during", "from", "to", "into", "under", "across", "within",
    "for", "between", "of", "with", "by",
})

# 3rd-person singular / past verb forms that can appear as sentence-initial
# words when the model's subject placeholder was stripped.  These sentences
# need "It " prepended to become grammatical.
_BARE_VERB_3P = frozenset({
    "is", "was", "has", "had", "uses", "used", "explores", "explored",
    "stands", "stood", "remains", "remained", "continues", "continued",
    "depicts", "depicted", "features", "featured", "serves", "served",
    "draws", "drew", "reflects", "reflected", "demonstrates", "demonstrated",
    "illustrates", "illustrated", "employs", "employed", "incorporates",
    "incorporated", "represents", "represented", "presents", "presented",
    "includes", "included", "contains", "contained", "embodies", "embodied",
    "celebrates", "celebrated", "symbolizes", "symbolized",
})

# "Today, stands as…" — an adverb + comma followed by a lowercase verb,
# meaning the subject was stripped from between the adverb and the verb.
_ADVERB_VERB_RE = re.compile(r"^([A-Z][a-z]+,\s+)([a-z]\S*)(.*)", re.DOTALL)

_VAR_TOKEN_PAT = re.compile(r"\{\{ var\d+ \}\}")


def _is_bare_anchor_sentence(s: str) -> bool:
    """True if sentence is just an anchor phrase + {{ varN }} with no other content."""
    without_var = _VAR_TOKEN_PAT.sub("", s)
    without_var = re.sub(r"[.,;:!?]", " ", without_var)
    without_var = re.sub(r"\b(the|a|an)\b", " ", without_var, flags=re.I)
    without_var = re.sub(r"\s+", " ", without_var).strip()
    return len(without_var.split()) <= 4


def fix_subjectless_sentences(prose: str) -> str:
    """Fix sentence fragments that lack a grammatical subject.

    Cases handled:
    0. Starts with "'s " (possessive with stripped noun) → replace with "Its ".
    1. "Today, stands as…" — adverb + comma + bare verb (subject stripped from
       between adverb and verb) → insert "it" after the comma.
    2. Sentence starts with a bare 3rd-person verb ("is", "was", "uses", …)
       because the model's subject placeholder was stripped → prepend "It ".
    3. Orphaned anchor fragments (no var token, very short, starts with a
       past participle or preposition) — dropped entirely.
    4. Bare anchor+var sentences (has a var token but no subject word) — a
       subject is prepended so the sentence is grammatically complete.
    """
    sentences = split_sentences(prose)
    result = []
    for s in sentences:
        s = s.strip()
        if not s:
            continue

        # Case 0: "'s significance lies…" → "Its significance lies…"
        if s.startswith("'s ") or s.startswith("\u2019s "):
            s = "Its " + s[3:]

        # Case 1: "Today, stands as…" → "Today, it stands as…"
        m = _ADVERB_VERB_RE.match(s)
        if m and m.group(2).rstrip(".,;:") in _BARE_VERB_3P:
            s = m.group(1) + "it " + m.group(2) + m.group(3)

        words = s.split()
        first = words[0].lower().rstrip(".,;:") if words else ""
        has_var = bool(_VAR_TOKEN_PAT.search(s))

        # Case 2: "is a novel that explores…" → "It is a novel that explores…"
        if first in _BARE_VERB_3P:
            s = "It " + s[0].lower() + s[1:]
            words = s.split()
            first = "it"

        # Case 2b: catch-all — any sentence still starting with a lowercase letter
        # has had its subject placeholder stripped (e.g. "received widespread acclaim…")
        if s and s[0].islower() and s[0].isalpha():
            s = "It " + s
            words = s.split()
            first = "it"

        # Case 3: Drop orphaned fragments (no var, very short, starts with participle/prep)
        if not has_var and len(words) <= 5 and first in _ORPHAN_STARTERS:
            continue

        # Case 4: Fix bare anchor+var sentences (var present but no subject opener)
        if has_var and first not in _SUBJECT_OPENERS and _is_bare_anchor_sentence(s):
            # Dangling-participle-then-subject ("Exhibited in {{ var9 }}, it…") are fine.
            has_trailing_subject = bool(re.search(
                r",\s+(?:it|he|she|they|the|this|these|one|its|their|his|her)\b",
                s, re.I))
            if not has_trailing_subject:
                low = s[0].lower() + s[1:]
                if first in _PAST_PART_STARTERS:
                    s = "It was " + low
                else:
                    # Noun-phrase anchor (e.g. "Work titled X", "Rivalry with X")
                    s = "It involves a " + low

        result.append(s)
    return " ".join(result)


def clean_prose_anchored(prose: str, min_keep: int = 3) -> str:
    """Cleanup for Option B sections: preserve [[VARn]], drop other placeholders."""
    body = tidy(fix_mojibake(prose))
    body = strip_boilerplate_sentences(body)
    body = strip_numeric_sentences(body, min_keep=min_keep)
    body = strip_stray_placeholders(body)
    body = drop_broken_sentences(body)
    return body


# ---------------------------------------------------------------------------
# HTML assembly. Subheadings are fixed; all other copy is model-generated.
# ---------------------------------------------------------------------------
def fix_grammar_artifacts(html: str) -> str:
    """Fix double-article and similar grammar artifacts that arise when generic
    noun phrases are substituted into prose that already carries an article.

    Examples fixed:
        "The the hinterland…"   → "The hinterland…"
        "the a nearby settlement" → "a nearby settlement"
        "the an institution"     → "an institution"
        "with other the broader" → "with the broader"
    """
    # Capitalisation-preserving fix for sentence-initial "The the …"
    html = re.sub(r'\bThe\s+the\s+', 'The ', html)
    # Lower-case "the" followed by another article
    html = re.sub(r'\bthe\s+the\s+', 'the ', html, flags=re.I)
    html = re.sub(r'\bthe\s+a\s+', 'a ', html, flags=re.I)
    html = re.sub(r'\bthe\s+an\s+', 'an ', html, flags=re.I)
    # "other the …" → "the …"  (e.g. "with other the broader territory")
    html = re.sub(r'\bother\s+the\s+', 'the ', html, flags=re.I)
    # "in the a …" → "in a …"  (belt-and-braces for nested patterns)
    html = re.sub(r'\bin\s+the\s+a\s+', 'in a ', html, flags=re.I)
    # Collapse any multiple spaces introduced by the above substitutions
    html = re.sub(r'  +', ' ', html)
    return html


def render_section(heading: str, body_jinja: str, per_para: int) -> str:
    paras = sentences_to_paragraphs(body_jinja, per_para)
    if not paras:
        return ""
    ps = "\n                ".join(f"<p>{p}</p>" for p in paras)
    return (
        "            <section>\n"
        f"                <h2>{heading}</h2>\n"
        f"                {ps}\n"
        "            </section>"
    )


def render_landmarks(slotted: str, rng: random.Random, category: str) -> str:
    """Render the landmarks section as a prose paragraph."""
    if not slotted.strip():
        slotted = "This landmark remains a point of pride for the local community."
    paras = sentences_to_paragraphs(slotted, rng.choice([3, 4]))
    ps = "\n                ".join(f"<p>{p}</p>" for p in paras)
    headings_map = get_fixed_headings(category)
    return (
        "            <section>\n"
        f"                <h2>{headings_map['landmarks']}</h2>\n"
        f"                {ps}\n"
        "            </section>"
    )


def display_title(category: str, static_title: str, fallback: str) -> str:
    if not static_title:
        return fallback
    label = CATEGORIES.get(category, CATEGORIES["towns"])["subject_slot_label"]
    if label in {"person", "artist", "figure"}:
        return f"About {static_title}"
    return static_title


MISSING_VAR_TEMPLATES = {
    "place": [
        "The account also connects the subject with {v}.",
        "A related setting in the entry is {v}.",
        "The article also refers to {v} as part of its background.",
    ],
    "person": [
        "The entry also names {v} as a related figure.",
        "A related person in the account is {v}.",
        "The article also connects the subject with {v}.",
    ],
    "org": [
        "The entry also links the subject with {v}.",
        "A related institution in the account is {v}.",
        "The article also names {v} as an associated organisation.",
    ],
    "subject": [
        "Another related term in the entry is {v}.",
        "The account also uses {v} as an associated name.",
        "The article also identifies {v} as part of the subject's background.",
    ],
}


def _append_missing_vars(landmarks_block: str, missing: list[int], category: str) -> str:
    """Append a short closing paragraph that mentions every var slot in `missing`
    at least once, guaranteeing all 10 canary slots appear on the page."""
    if not missing:
        return landmarks_block

    sentences = []
    for v in missing:
        if uses_anchored_slots(category):
            sentences.append(anchored_clause(v, category))
        else:
            var_ref = "{{ var%d }}" % v
            anchor = slot_anchor_map(category).get(v, "").strip()
            slot_type = slot_type_map(category).get(v, "place")
            if anchor:
                sentences.append(f"It is {anchor} {var_ref}.")
            else:
                templates = MISSING_VAR_TEMPLATES.get(slot_type, MISSING_VAR_TEMPLATES["place"])
                template = templates[v % len(templates)]
                sentences.append(template.format(v=var_ref))

    extra_p = f"<p>{' '.join(sentences)}</p>"

    if "</section>" in landmarks_block:
        idx = landmarks_block.rindex("</section>")
        indent = "                "
        return (landmarks_block[:idx] + f"{indent}{extra_p}\n            "
                + landmarks_block[idx:])
    return landmarks_block + f"\n{extra_p}"


# Filler sentences used to pad sections that are too short after cleaning.
# Keyed by lowercase section heading; "_default" is the fallback.
SECTION_FILLER: dict[str, list[str]] = {
    "early life": [
        "Its origins can be traced to a period of significant cultural change.",
        "Early accounts describe it as having unusual characteristics that distinguished it from others of its kind.",
        "The circumstances of its emergence remain a subject of ongoing scholarly interest.",
        "It developed during a period when its field was undergoing considerable transformation.",
        "Those who encountered it in its early stages noted its remarkable qualities.",
        "The formative period was marked by a series of notable developments.",
        "Its early years were shaped by the influence of a distinctive regional tradition.",
        "Contemporaries who first encountered it remarked on its distinctiveness.",
    ],
    "origins": [
        "Its origins remain a subject of considerable scholarly debate.",
        "Early accounts suggest it emerged from a confluence of distinct traditions.",
        "The circumstances surrounding its first appearance are imperfectly understood.",
        "Those who documented its early history noted a number of unusual features.",
        "Its foundational period was marked by a series of formative episodes.",
        "The subject has attracted sustained interest from those investigating its beginnings.",
        "Accounts from the earliest period reveal the outlines of what it would later become.",
        "Its emergence reflects broader patterns observed in comparable subjects of the time.",
    ],
    "history": [
        "Its history reflects broader patterns of development common to comparable subjects.",
        "The historical record reveals a series of formative episodes that shaped its character.",
        "It underwent several significant changes during its history.",
        "Earlier phases of its existence differed considerably from what it later became.",
        "The subject has been the focus of considerable historical inquiry.",
        "Records from the period offer a revealing portrait of its early character.",
        "Its development has been shaped by a range of external and internal influences.",
        "Historians have noted the persistence of certain core features throughout its evolution.",
    ],
    "career": [
        "Its work attracted sustained attention from critics and specialists alike.",
        "Over time, it developed a reputation for producing distinctive contributions to its field.",
        "Those familiar with its output described it as consistently thoughtful and original.",
        "Its approach drew on a wide range of influences and established traditions.",
        "The methods it employed were regarded as innovative within its context.",
        "It maintained a steady and productive engagement with its field throughout this period.",
        "Its contributions were recognized by peers and observers across the discipline.",
        "The period of its greatest activity coincided with significant developments in the wider field.",
    ],
    "style": [
        "Its distinctive approach has been the subject of considerable critical commentary.",
        "Observers have identified a coherent set of characteristics that define its manner.",
        "Those who studied it closely noted the consistency of its underlying principles.",
        "Its particular qualities have made it a frequent point of reference in related discussions.",
        "The approach it adopted reflected both personal inclination and broader influences.",
        "Commentators have drawn attention to the originality of its methods.",
        "Its characteristic features are evident across the full range of its output.",
        "The style it developed has been described as both distinctive and influential.",
    ],
    "legacy": [
        "Its influence has been acknowledged by a wide range of later commentators.",
        "Later observers have continued to draw on its example when discussing the field.",
        "The lasting impact of its work is still felt in relevant circles today.",
        "It is frequently cited as an important point of reference in its area.",
        "Scholars have debated the precise nature of its contribution, though its significance is broadly accepted.",
        "Its reputation has endured well beyond the period of its greatest activity.",
        "Subsequent developments in the field have often been traced back to its foundational work.",
        "The subject continues to attract new interest from researchers and enthusiasts alike.",
    ],
    "reception": [
        "Critical responses to it were mixed at first but grew more favourable over time.",
        "Observers from different perspectives have assessed it in strikingly different terms.",
        "It attracted considerable attention upon its initial appearance.",
        "Those who engaged with it most closely tended to offer the most nuanced assessments.",
        "Its reception has shifted considerably as the surrounding context has changed.",
        "Later evaluations have generally been more positive than early responses.",
        "The subject generated debate among those best placed to assess its qualities.",
        "Its critical standing has been reassessed on a number of occasions.",
    ],
    "description": [
        "Its characteristics have been described in considerable detail by those who studied it closely.",
        "Observers have noted a number of distinctive features that set it apart from comparable subjects.",
        "The subject displays qualities that have made it a frequent point of reference in the field.",
        "A careful examination reveals a range of attributes that collectively define its identity.",
        "Those with expertise in the area have consistently highlighted its notable properties.",
        "It possesses qualities that have drawn sustained attention from specialists.",
        "The overall impression it creates is one of coherence and distinctiveness.",
        "Its defining characteristics have remained relatively stable across the period of study.",
    ],
    "overview": [
        "The subject occupies a distinctive position within its broader context.",
        "Those who have studied it most thoroughly have arrived at broadly consistent conclusions.",
        "Its defining features have been documented extensively by researchers in the field.",
        "A general account of its properties reveals both its individuality and its connections to related subjects.",
        "The overall picture that emerges is one of considerable complexity and interest.",
        "It has been approached from a variety of methodological standpoints over time.",
        "Its most salient characteristics are readily apparent to those familiar with the field.",
        "The subject repays close attention with a depth of detail not always visible at first glance.",
    ],
    "plot": [
        "The narrative unfolds across a carefully constructed set of scenarios and situations.",
        "Key developments in the story are handled with attention to character and consequence.",
        "The sequence of events draws on familiar structures while introducing original elements.",
        "Central to the experience is the interplay between competing interests and perspectives.",
        "The events depicted draw on a range of thematic concerns relevant to the subject.",
        "The arc of the narrative is shaped by a series of carefully placed revelations.",
        "Characters are developed through their responses to the situations they encounter.",
        "The resolution emerges organically from the conditions established earlier in the story.",
    ],
    "themes": [
        "The thematic concerns it explores have resonated with a wide audience.",
        "Critics have identified a number of recurring ideas that give it coherence and depth.",
        "Its central preoccupations are handled with care and consistency throughout.",
        "The subject returns repeatedly to questions that are central to its field.",
        "A close reading reveals layers of meaning not immediately apparent on first encounter.",
        "Its engagement with its core themes is both sustained and thoughtful.",
        "The ideas it explores connect it to broader conversations within its context.",
        "Readers and observers have found its thematic concerns both relevant and illuminating.",
    ],
    "gameplay": [
        "The mechanics it employs have been widely discussed by those familiar with the form.",
        "Players have noted the consistency and coherence of the systems it presents.",
        "Its approach to core challenges distinguishes it from comparable works in the field.",
        "The structure of the experience rewards careful engagement over time.",
        "Those who have explored it thoroughly have found considerable depth beneath the surface.",
        "Its design reflects a clear set of priorities and a coherent overall vision.",
        "The experience it offers is shaped by a well-developed set of underlying principles.",
        "Engagement with its systems reveals a range of possibilities not immediately obvious.",
    ],
    "production": [
        "The process of its creation involved a range of skilled contributors.",
        "Those involved in its production brought considerable expertise to their respective roles.",
        "The conditions under which it was made presented both challenges and opportunities.",
        "Its development was shaped by a series of decisions that reflected the priorities of those involved.",
        "The collaborative nature of the work is evident in the coherence of the final result.",
        "Those who oversaw its creation have spoken of a sustained commitment to quality.",
        "The production process was marked by careful attention to the demands of the material.",
        "The finished work reflects the sustained efforts of a dedicated group of contributors.",
    ],
    "culture": [
        "The cultural dimensions of the subject have been explored by a range of researchers.",
        "Its place within a broader cultural context has been the subject of considerable discussion.",
        "Observers have documented a number of practices and traditions associated with it.",
        "The subject occupies a distinctive position within its cultural environment.",
        "Various interpretations of its significance have been proposed over time.",
        "Its cultural associations have been both celebrated and debated by those familiar with it.",
        "Those who have studied its cultural dimensions have noted considerable richness and complexity.",
        "Its cultural significance has been assessed from a number of different perspectives.",
    ],
    "significance": [
        "Its significance has been assessed from a number of different perspectives.",
        "Those familiar with the broader field have generally agreed on the importance of its contribution.",
        "Its place within a wider context of related subjects has been extensively discussed.",
        "The reasons for its enduring prominence have been examined by a range of commentators.",
        "Its importance is widely acknowledged, though the basis for that importance remains debated.",
        "Subsequent developments in the field have continued to reflect its foundational influence.",
        "Those who have engaged with it most seriously have come away with an appreciation of its depth.",
        "Its significance is perhaps best understood in relation to the broader landscape of the field.",
    ],
    "habitat": [
        "The environments in which it is typically found have been documented in considerable detail.",
        "Those who have observed it in its natural setting have noted a strong preference for particular conditions.",
        "Its habitat requirements are well understood, though conditions vary across its range.",
        "Observers have noted that it shows a clear preference for specific environmental features.",
        "The relationship between the subject and its environment is a focus of ongoing research.",
        "Its presence has been recorded across a range of settings, with notable concentrations in certain areas.",
        "Those who have studied it in situ have gathered extensive data on its habitat preferences.",
        "Its characteristic environments share a number of features that appear to be central to its survival.",
    ],
    "behaviour": [
        "Its behaviour has been documented by observers in a range of contexts.",
        "Those who have studied it closely have noted a consistent set of characteristic patterns.",
        "Its activity shows clear variation across different conditions and environments.",
        "Observers have recorded a range of behaviours that appear to be central to its functioning.",
        "The study of its behaviour has yielded a number of unexpected findings.",
        "Its responses to different stimuli have been the subject of sustained investigation.",
        "Those with direct experience of it in the field have described a number of notable behaviours.",
        "Its characteristic patterns of activity have been interpreted in a variety of ways.",
    ],
    "academics": [
        "Its academic offerings have been developed over time to reflect evolving priorities in the field.",
        "Those associated with it have consistently emphasised the importance of rigorous inquiry.",
        "Its curriculum reflects a broad engagement with the central questions of its discipline.",
        "The academic environment it provides has been described by participants as both challenging and stimulating.",
        "Those who have studied there have gone on to make contributions across a range of fields.",
        "Its approach to teaching and research has attracted sustained recognition.",
        "The quality of its academic programme has been noted by a range of independent assessors.",
        "Its scholarly culture is one of the features most frequently mentioned by those associated with it.",
    ],
    "operations": [
        "Its day-to-day operations reflect a set of priorities established over a long period.",
        "Those responsible for its management have pursued a consistent strategic direction.",
        "Its operational structure has evolved to meet changing demands and circumstances.",
        "The organisation it has developed allows it to respond effectively to its environment.",
        "Those who work within it have described a culture of sustained commitment to its goals.",
        "Its operational efficiency has been recognised by those who have examined it closely.",
        "The processes it employs reflect accumulated experience and ongoing refinement.",
        "Its internal culture is one of the features most often cited by those familiar with it.",
    ],
    "mythology": [
        "The mythological dimensions of the subject have attracted sustained scholarly attention.",
        "Accounts of its origins are varied and often reflect the perspectives of different communities.",
        "The stories associated with it have been transmitted across generations in a variety of forms.",
        "Those who have studied its mythological aspects have noted considerable richness and complexity.",
        "Its central narratives are shared across a wide range of communities and traditions.",
        "The figures and events described in its mythology have been interpreted in many different ways.",
        "Its mythological heritage provides an important framework for understanding its wider significance.",
        "The study of its myths has yielded insights into the values and concerns of those who created them.",
    ],
    "economy": [
        "Its economic character has been shaped by a combination of local resources and wider connections.",
        "Those familiar with its economic life have noted a pattern of gradual development over time.",
        "The economic activities associated with it reflect both tradition and adaptation to changing conditions.",
        "Its economic profile distinguishes it in certain respects from comparable subjects in the region.",
        "Observers have traced the evolution of its economic base across different periods.",
        "The economic dimensions of its existence have attracted attention from researchers and analysts.",
        "Its economic relationships with surrounding areas have been both cooperative and competitive.",
        "Those who have examined its economic history have identified a number of distinctive features.",
    ],
    "_default": [
        "The subject has attracted sustained interest from those working in the relevant field.",
        "Those who have studied it most closely have arrived at broadly consistent conclusions.",
        "Its defining features have been documented and discussed by a range of specialists.",
        "The overall character of the subject reveals both its individuality and its connections to related examples.",
        "A careful examination of its properties rewards those who approach it with sufficient attention.",
        "Its most important qualities are evident to those familiar with the broader field.",
        "It has been examined from a variety of perspectives, each illuminating different aspects.",
        "The depth of interest it has attracted reflects its genuine importance within its context.",
    ],
}


def pad_section(body: str, heading: str, min_sents: int, max_sents: int,
                rng: random.Random) -> str:
    """Add filler sentences from SECTION_FILLER until the section has at least
    min_sents sentences, up to a ceiling of max_sents total."""
    sentences = split_sentences(body)
    if len(sentences) >= min_sents:
        return body
    pool = list(SECTION_FILLER.get(heading.lower(), SECTION_FILLER["_default"]))
    # Don't reuse sentences already in the section
    used = set(s.strip() for s in sentences)
    available = [s for s in pool if s not in used]
    rng.shuffle(available)
    filler_iter = iter(available)
    while len(sentences) < min_sents:
        try:
            sentences.append(next(filler_iter))
        except StopIteration:
            break  # ran out of unique fillers
    return " ".join(sentences)


def _fix_person_pronouns_in_html(body_html: str) -> str:
    """Apply fix_person_pronouns (and drop artifact sentences) to text inside <p> tags."""
    def _fix_p_content(m: re.Match) -> str:
        text = m.group(0)
        # text is the whole <p>...</p> block; we fix pronouns in it
        text = fix_person_pronouns(text)
        # Also drop any artifact sentences that crept in after section assembly
        # Extract just the inner text, filter, then put back
        inner_match = re.match(r'(<p>)(.*)(</p>)', text, flags=re.DOTALL)
        if inner_match:
            inner = inner_match.group(2)
            inner = drop_artifact_sentences(inner)
            text = inner_match.group(1) + inner + inner_match.group(3)
        return text
    return re.sub(r'<p>.*?</p>', _fix_p_content, body_html, flags=re.DOTALL)


def assemble_template_anchored(sections, footer_tagline: str, landmark_prose: str,
                               rng: random.Random, args, category: str,
                               static_title: str = "") -> tuple[str, int]:
    """Option B assembly: [[VARn]] from the LLM become anchored {{ varN }} slots."""
    fixed_headings = get_fixed_headings(category)
    cat_sections = CATEGORIES.get(category, CATEGORIES["towns"])["sections"]
    section_map = {kind: prose for kind, prose in sections}

    cleaned_sections = {}
    n_ph = 0
    for kind in cat_sections:
        prose = section_map.get(kind, "")
        if not prose:
            continue
        body = clean_prose_anchored(prose, min_keep=args.min_section_sentences)
        body, _ = substitute_named_vars(body)
        body = fix_subjectless_sentences(body)
        heading = fixed_headings.get(kind, kind)
        body = pad_section(body, heading, min_sents=6, max_sents=10, rng=rng)
        n_ph += len(re.findall(r"\{\{ var\d+ \}\}", body))
        cleaned_sections[kind] = body

    rendered = []
    for kind in cat_sections:
        if kind not in cleaned_sections:
            continue
        block = render_section(
            fixed_headings[kind], cleaned_sections[kind], rng.choice([3, 4]))
        if block:
            rendered.append(block)

    body_html = "\n".join(rendered)
    vars_in_body = set(int(m) for m in re.findall(r"\{\{ var(\d+) \}\}", body_html))
    truly_missing = [v for v in ALL_VARS if v not in vars_in_body]
    if truly_missing and rendered:
        rendered[-1] = _append_missing_vars(rendered[-1], truly_missing, category)
        body_html = "\n".join(rendered)

    # Apply person-pronoun corrections to the body HTML (only <p> text content)
    # AFTER _append_missing_vars so anchor/filler sentences are also corrected.
    cat_label = CATEGORIES.get(category, {}).get("subject_slot_label", "")
    if cat_label in ("person", "artist", "figure"):
        body_html = _fix_person_pronouns_in_html(body_html)

    tagline_slotted = f"{static_title} — fictional reference page"
    title_text = display_title(category, static_title, "{{ var1 }}")

    html = (
        "<!DOCTYPE html>\n<html>\n    <head>\n"
        f"        <title>{title_text}</title>\n"
        '        <meta name="robots" content="index, follow">\n'
        "        <style>\n"
        "            body { font-family: Georgia, serif; font-size: 16px; "
        "line-height: 1.6; max-width: 960px; margin: 0 auto; padding: 20px; "
        "color: #202122; }\n"
        "            h1 { font-size: 28px; font-weight: bold; "
        "border-bottom: 1px solid #a2a9b1; padding-bottom: 4px; margin-bottom: 12px; }\n"
        "            h2 { font-size: 20px; font-weight: bold; "
        "border-bottom: 1px solid #a2a9b1; padding-bottom: 2px; margin-top: 24px; }\n"
        "            p { margin: 8px 0 14px 0; font-size: 16px; font-weight: normal; }\n"
        "            footer { margin-top: 32px; font-size: 13px; color: #555; "
        "border-top: 1px solid #a2a9b1; padding-top: 8px; }\n"
        "        </style>\n"
        "    </head>\n    <body>\n        <header>\n"
        f"            <h1>{title_text}</h1>\n"
        "        </header>\n"
        "        <main>\n"
        f"{body_html}\n"
        "        </main>\n        <footer>\n"
        f"            <p>{tagline_slotted}</p>\n"
        "        </footer>\n    </body>\n</html>\n"
    )
    html = fix_grammar_artifacts(html)
    return html, n_ph


def assemble_template(sections, footer_tagline: str, landmark_prose: str,
                      rng: random.Random, args, category: str = "towns",
                      static_title: str = "") -> tuple[str, int]:
    if uses_anchored_slots(category):
        if not sections_use_named_vars(sections):
            sections, _ = repair_anchored_sections(sections, category, rng)
        return assemble_template_anchored(
            sections, footer_tagline, landmark_prose, rng, args, category,
            static_title=static_title)
    """
    sections: list of (kind, raw_prose)
    footer_tagline: model-generated single-sentence tagline
    landmark_prose: model-generated paragraph about a single landmark (or "")
    category: which content category this template belongs to
    static_title: a fixed name for the subject baked directly into <title>/<h1>
    Returns (html, n_placeholders_before_conversion).
    """
    fixed_headings = get_fixed_headings(category)
    cat_sections = CATEGORIES.get(category, CATEGORIES["towns"])["sections"]
    section_map = {kind: prose for kind, prose in sections}
    has_landmarks = CATEGORIES.get(category, CATEGORIES["towns"]).get("has_landmarks", False)

    cleaned_sections = {}
    n_ph = 0
    for kind in cat_sections:
        prose = section_map.get(kind, "")
        if not prose:
            continue
        body = clean_prose(prose, args.max_section_placeholders, rng,
                           min_keep=args.min_section_sentences)
        n_ph += len(PLACEHOLDER_RE.findall(body))
        cleaned_sections[kind] = body

    landmark_clean = clean_prose(landmark_prose, max_placeholders=4, rng=rng, min_keep=2)
    footer_clean = clean_prose(footer_tagline, max_placeholders=2, rng=rng, min_keep=1)

    body_text = "\n".join(cleaned_sections[k] for k in cat_sections if k in cleaned_sections)

    body_assigner = PlaceholderAssigner(rng, reserve=2, category=category, static_subject=static_title)
    body_assigner.plan(body_text)
    subject_slot = "{{ var%d }}" % body_assigner.subject

    rendered = []
    for kind in cat_sections:
        if kind not in cleaned_sections:
            continue
        body_jinja = body_assigner.apply(cleaned_sections[kind])
        block = render_section(fixed_headings[kind], body_jinja, rng.choice([3, 4]))
        if block:
            rendered.append(block)

    reserved_vars = body_assigner.unused_vars()
    extra_assigner = PlaceholderAssigner(
        rng, subject_var=body_assigner.subject, available_vars=reserved_vars,
        category=category)
    extra_full_text = footer_clean + ("\n" + landmark_clean if has_landmarks else "")
    extra_assigner.plan(extra_full_text)

    footer_slotted = extra_assigner.apply(footer_clean)
    footer_slotted = f"{static_title or subject_slot} — fictional reference page"

    if has_landmarks and landmark_clean.strip():
        landmark_slotted = extra_assigner.apply(landmark_clean)
        landmarks_block = render_landmarks(landmark_slotted, rng, category)

        missing = [v for v in extra_assigner.unused_vars() if v != extra_assigner.subject]
        if missing:
            landmarks_block = _append_missing_vars(landmarks_block, missing, category)

        rendered.append(landmarks_block)
    else:
        missing = [v for v in extra_assigner.unused_vars() if v != extra_assigner.subject]
        if missing and rendered:
            last_section = rendered[-1]
            rendered[-1] = _append_missing_vars(last_section, missing, category)

    body_html = "\n".join(rendered) or (
        "            <section>\n"
        f"                <h2>{list(fixed_headings.values())[0]}</h2>\n"
        f"                <p>{subject_slot}</p>\n"
        "            </section>"
    )

    # Final safety pass: some vars may have been "consumed" by the extra_assigner
    # when planning the footer but then lost because the footer output was overridden
    # with a static tagline.  Scan the assembled body for which {{ varN }} actually
    # appear and append anchor-word sentences for any that are absent.
    vars_in_body = set(int(m) for m in re.findall(r'\{\{ var(\d+) \}\}', body_html))
    truly_missing = [v for v in ALL_VARS if v not in vars_in_body]
    if truly_missing and rendered:
        rendered[-1] = _append_missing_vars(rendered[-1], truly_missing, category)
        body_html = "\n".join(rendered)

    tagline_slotted = footer_slotted
    has_slots = "{{ var" in tagline_slotted
    has_leftovers = "[[" in tagline_slotted
    too_long = len(tagline_slotted.split()) > 25
    if not tagline_slotted.strip() or not has_slots or has_leftovers or too_long:
        tagline_slotted = f"{static_title or subject_slot} — fictional reference page"

    title_text = display_title(category, static_title, subject_slot)

    html = (
        "<!DOCTYPE html>\n<html>\n    <head>\n"
        f"        <title>{title_text}</title>\n"
        '        <meta name="robots" content="index, follow">\n'
        "        <style>\n"
        "            body { font-family: Georgia, serif; font-size: 16px; "
        "line-height: 1.6; max-width: 960px; margin: 0 auto; padding: 20px; "
        "color: #202122; }\n"
        "            h1 { font-size: 28px; font-weight: bold; "
        "border-bottom: 1px solid #a2a9b1; padding-bottom: 4px; margin-bottom: 12px; }\n"
        "            h2 { font-size: 20px; font-weight: bold; "
        "border-bottom: 1px solid #a2a9b1; padding-bottom: 2px; margin-top: 24px; }\n"
        "            p { margin: 8px 0 14px 0; font-size: 16px; font-weight: normal; }\n"
        "            footer { margin-top: 32px; font-size: 13px; color: #555; "
        "border-top: 1px solid #a2a9b1; padding-top: 8px; }\n"
        "        </style>\n"
        "    </head>\n    <body>\n        <header>\n"
        f"            <h1>{title_text}</h1>\n"
        "        </header>\n"
        "        <main>\n"
        f"{body_html}\n"
        "        </main>\n        <footer>\n"
        f"            <p>{tagline_slotted}</p>\n"
        "        </footer>\n    </body>\n</html>\n"
    )
    html = fix_grammar_artifacts(html)
    return html, n_ph


RAW_HEADING_RE  = re.compile(r"^##\s+(.*)$")
RAW_FOOTER_RE   = re.compile(r"^FOOTER:\s*(.+)$", re.M)
RAW_LANDMARK_RE = re.compile(r"^LANDMARK:\s*(.+)$", re.M)
RAW_CATEGORY_RE = re.compile(r"^CATEGORY:\s*(\w+)$", re.M)
RAW_TITLE_RE    = re.compile(r"^TITLE:\s*(.+)$", re.M)


def kind_of_heading(heading: str, category: str) -> str:
    cat_sections = CATEGORIES.get(category, CATEGORIES["towns"])["sections"]
    headings_map = CATEGORIES.get(category, CATEGORIES["towns"])["headings"]
    reverse = {v.lower(): k for k, v in headings_map.items()}
    return reverse.get(heading.lower(), cat_sections[0])


def parse_raw(text: str):
    footer_m   = RAW_FOOTER_RE.search(text)
    landmark_m = RAW_LANDMARK_RE.search(text)
    category_m = RAW_CATEGORY_RE.search(text)
    title_m    = RAW_TITLE_RE.search(text)

    footer_tagline = footer_m.group(1).strip()   if footer_m   else ""
    landmark_prose = landmark_m.group(1).strip() if landmark_m else ""
    category       = category_m.group(1).strip() if category_m else "towns"
    static_title   = title_m.group(1).strip()    if title_m    else ""

    meta_res = [RAW_FOOTER_RE, RAW_LANDMARK_RE, RAW_CATEGORY_RE, RAW_TITLE_RE]
    sections, heading, buf = [], None, []
    for line in text.splitlines():
        if any(r.match(line) for r in meta_res):
            continue
        m = RAW_HEADING_RE.match(line)
        if m:
            if heading is not None:
                sections.append((kind_of_heading(heading, category), " ".join(buf).strip()))
            heading, buf = m.group(1).strip(), []
        else:
            buf.append(line)
    if heading is not None:
        sections.append((kind_of_heading(heading, category), " ".join(buf).strip()))
    sections = [(k, b) for k, b in sections if b]
    return sections, footer_tagline, landmark_prose, category, static_title


# ---------------------------------------------------------------------------
# Write outputs.
# ---------------------------------------------------------------------------
def write_template(out_dir: Path, name: str, html: str, category: str):
    varlist = var_expressions(category)
    (out_dir / f"scraper_gen_{name}.html").write_text(html, encoding="utf-8")
    (out_dir / f"scraper_gen_{name}.txt").write_text("\n".join(varlist) + "\n", encoding="utf-8")


def write_raw(out_dir: Path, name: str, raw_parts: list[str],
              footer_tagline: str, landmark_prose: str, category: str,
              static_title: str = ""):
    raw_text = "\n\n".join(raw_parts)
    raw_text += f"\nFOOTER: {footer_tagline}\n"
    raw_text += f"LANDMARK: {landmark_prose}\n"
    raw_text += f"CATEGORY: {category}\n"
    raw_text += f"TITLE: {static_title}\n"
    (out_dir / f"raw_{name}.txt").write_text(raw_text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Model generation helpers.
# ---------------------------------------------------------------------------
def apply_chat_text(tok, messages):
    try:
        return tok.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)
    except TypeError:
        return tok.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True)


def clean_generation(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", " ", text, flags=re.S)
    text = text.replace("<think>", " ").replace("</think>", " ")
    return re.sub(r"\s+", " ", text.strip())


def trim_to_sentences(text: str) -> str:
    sents = re.findall(r".*?[.!?](?=\s|$)", text, flags=re.S)
    joined = " ".join(s.strip() for s in sents).strip()
    return joined or text.strip()


def few_shot_prefix(n=2):
    if not DEFAULT_DATA.exists():
        return ""
    egs = []
    with DEFAULT_DATA.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                egs.append(json.loads(line)["target"])
            if len(egs) >= n:
                break
    if not egs:
        return ""
    return ("Here are examples of the required style:\n"
            + "\n".join(f"- {e}" for e in egs)
            + "\n\nNow write a new one.\n\n")


def generate_one(model, tok, device, instruction, prefix, args):
    import torch
    messages = [{"role": "user", "content": prefix + instruction}]
    text = apply_chat_text(tok, messages)
    inputs = tok(text, return_tensors="pt").to(device)
    with torch.no_grad():
        out = model.generate(
            **inputs, max_new_tokens=args.max_new_tokens, do_sample=True,
            temperature=args.temperature, top_p=args.top_p,
            pad_token_id=tok.pad_token_id,
        )
    gen = tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
    return drop_artifact_sentences(trim_to_sentences(clean_generation(gen)))


def generate_landmarks(model, tok, device, prefix, args, category: str = "towns") -> str:
    instruction = get_landmark_instruction(category)
    if instruction is None:
        return ""
    return generate_one(model, tok, device, instruction, prefix, args)


def generate_footer(model, tok, device, prefix, args, category: str = "towns") -> str:
    instruction = get_footer_instruction(category)
    raw = generate_one(model, tok, device, instruction, prefix, args)
    first = split_sentences(raw)[0] if split_sentences(raw) else raw
    return first


def make_static_title(category: str) -> str:
    from faker import Faker
    fake = Faker("en_US")

    label = CATEGORIES.get(category, CATEGORIES["towns"])["subject_slot_label"]
    if label in ("person", "artist", "figure"):
        return fake.first_name() + " " + fake.last_name()
    elif label == "town":
        return fake.last_name() + random.choice(["ville", "field", "burg", "ton", "ford", " Creek", " Falls"])
    elif label == "location":
        return fake.last_name() + random.choice([" Pass", " Point", " Cape", " Ridge", " Bay"])
    elif label == "institution":
        return fake.last_name() + random.choice([" University", " College", " Institute"])
    elif label == "company":
        return fake.last_name() + random.choice([" Industries", " Partners", " Group", " Corp"])
    elif label == "team":
        return "the " + fake.city() + " " + random.choice(["Rangers", "Sentinels", "Hawks", "Wolves", "Eagles"])
    elif label == "species":
        return random.choice(["Greater", "Lesser", "Eastern", "Northern"]) + " " + fake.last_name() + random.choice(["wren", "fin", "cap", "hawk"])
    elif label == "film":
        return random.choice(["The", "A"]) + " " + fake.last_name() + random.choice([" Shore", " Road", " Hour", " Glass"])
    elif label == "book":
        return "The " + fake.last_name() + random.choice([" Garden", " Map", " Letter", " Door"])
    elif label == "game":
        return fake.last_name() + random.choice([" Chronicles", " Protocol", " Veil", " Archive"])
    elif label == "language":
        return fake.last_name()[:5].capitalize() + random.choice(["ian", "ic", "ese", "ish"])
    elif label == "dish":
        return fake.last_name() + random.choice([" Stew", " Cake", " Bread", " Soup"])
    elif label == "garment":
        return "the " + fake.last_name() + random.choice([" Wrap", " Shawl", " Robe", " Cloak"])
    elif label == "condition":
        return fake.last_name() + random.choice([" Syndrome", " Fever", " Disease", " Disorder"])
    elif label == "legend":
        return "the " + fake.last_name() + random.choice([" of the Vale", " Wanderer", " of Ashfen"])
    elif label == "religion":
        return fake.last_name() + random.choice(["ism", "anism", "ism", " Faith"])
    else:
        return fake.last_name() + "ville"


# Compiled once at module level — used in generate_title to reject non-name model output.
_BAD_NAME_STARTERS = re.compile(
    r"^(?:about|after|before|during|despite|although|while|when|if|because|"
    r"since|though|however|therefore|thus|furthermore|moreover|also|"
    r"his|her|its|their|our|your|my|he|she|it|they|we|you|"
    r"was|is|are|were|has|have|had|will|would|could|should|"
    r"which|who|whom|whose|that|this|these|those|"
    r"and|but|or|nor|so|yet|for|in|as|"
    r"following|other|another|additional|numerous|several|various|"
    r"many|most|some|any|all|both|each|every|no|"
    # Wikipedia section / article boilerplate words
    r"references|further|see|overview|history|geography|demographics|"
    r"notable|section|contents|external|links|biography|background|"
    r"early|career|legacy|personal|education|death|family|works|publications|"
    r"awards|notes|sources|plot|cast|crew|staff|characters)\b",
    re.IGNORECASE,
)
_SENTENCE_GIVEAWAYS = re.compile(
    r"\b(?:his|her|their|its|was|were|is|are|has|have|had|died|born|married|"
    r"lived|follows|featuring|starring|describing|depicting|known|called|"
    r"referred|often|sometimes|commonly|also|main|second|third)\b",
    re.IGNORECASE,
)
# Dangling preposition at end of title (incomplete phrase)
_ENDS_WITH_PREP = re.compile(
    r"\b(?:in|of|at|by|to|from|with|for|on|about|upon|near|between|among|"
    r"through|over|under|before|after|around|into|onto|within|without|"
    r"against|across|beside|behind|above|below)\s*$",
    re.IGNORECASE,
)
# Generic single common nouns — not a proper name
_GENERIC_NOUN_TITLE = re.compile(
    r"^(?:the\s+|a\s+|an\s+|about\s+)?(?:book|film|movie|city|town|country|region|company|team|"
    r"university|college|school|person|man|woman|animal|species|language|"
    r"cuisine|dish|food|clothing|garment|religion|sport|game|legend|myth|"
    r"article|page|entry|template|example|type|kind|style|form|class|group|"
    r"island|village|settlement|character|community|society|culture|tradition|"
    r"movement|festival|ceremony|ritual|practice|belief|concept|idea|story|tale|"
    r"genus|family|order|kingdom|phylum|taxon|subspecies|variety|cultivar|"
    r"restaurant|dish|recipe|ingredient|plant|tree|flower|bird|fish|insect|"
    r"novel|poem|play|song|album|episode|series|season|chapter|section|"
    r"overview|history|geography|description|introduction|background)\s*$",
    re.IGNORECASE,
)


def generate_title(model, tok, device, prefix, args, category: str = "towns") -> str:
    cat = CATEGORIES.get(category, CATEGORIES["towns"])
    label = cat["subject_slot_label"]
    examples = {
        "person":      "e.g. 'Margaret Holloway' or 'James Ferreira'",
        "artist":      "e.g. 'Elena Voss' or 'Samuel Okafor'",
        "figure":      "e.g. 'Thomas Aldred' or 'Priya Nair'",
        "film":        "e.g. 'The Copper Shore' or 'Midnight in Ardena'",
        "book":        "e.g. 'The Glass Orchard' or 'A Map of Forgotten Roads'",
        "game":        "e.g. 'Iron Veil' or 'The Sunken Archive'",
        "town":        "e.g. 'Caldwell Creek' or 'Harrowfield'",
        "location":    "e.g. 'Cape Aldridge' or 'Stonemark Pass'",
        "institution": "e.g. 'Alderton University' or 'Fairway College'",
        "company":     "e.g. 'Vexlar Industries' or 'Northgate Partners'",
        "team":        "e.g. 'the Harrowfield Sentinels' or 'the Caldwell Rangers'",
        "species":     "e.g. 'Velvet-backed Thornwren' or 'Eastern Duskfin'",
        "legend":      "e.g. 'The Warden of Ashfen' or 'The Pale Wanderer'",
        "language":    "e.g. 'Verenian' or 'Thaldic'",
        "dish":        "e.g. 'Saffron Stew' or 'Braised Mallow Cake'",
        "garment":     "e.g. 'the Keldri Wrap' or 'the Stonemark Shawl'",
        "condition":   "e.g. 'Varneth Syndrome' or 'Aldric Fever'",
        "religion":    "e.g. 'the Order of the Pale Flame' or 'Veldanism'",
    }
    example = examples.get(label, "e.g. 'Harrowfield' or 'Elena Voss'")
    instruction = (
        f"Output ONLY a single fictional proper name for a {label}. "
        f"Nothing else -- no sentences, no descriptions, no punctuation except "
        f"what is part of the name itself, no quotation marks. "
        f"Just the name on its own. {example}."
    )
    raw = generate_one(model, tok, device, instruction, prefix, args)
    raw = raw.strip().splitlines()[0].strip()
    raw = re.split(r'\s+(?:is|was|are|were|has|have|had|the|a|an)\b', raw, maxsplit=1)[0]
    raw = raw.strip().strip('"\'.,;:()')
    # Strip embedded quotes/apostrophe-quotes that indicate the model used scare quotes
    raw = re.sub(r"[\"']\s*\w[^\"']*[\"']", "", raw).strip().strip("'\"")
    words = raw.split()
    # Truncate over-long phrases to the first 2 words and re-validate
    if len(words) > 4:
        raw = " ".join(words[:2])
    if (not raw
            or _BAD_NAME_STARTERS.match(raw)
            or _SENTENCE_GIVEAWAYS.search(raw)
            or _ENDS_WITH_PREP.search(raw)
            or _GENERIC_NOUN_TITLE.match(raw)
            or "," in raw          # comma = sentence fragment
            or "'s" in raw         # possessive = phrase not a name
            or "\u2019s" in raw):  # smart-quote possessive
        return make_static_title(category)
    return raw


# ---------------------------------------------------------------------------
# Main execution paths.
# ---------------------------------------------------------------------------
def _load_title_registry(out_dir: Path) -> set:
    """Load the set of previously generated titles from the registry file."""
    registry = out_dir / "used_titles.txt"
    if registry.exists():
        return set(t for t in registry.read_text(encoding="utf-8").splitlines() if t.strip())
    return set()


def _save_title_registry(out_dir: Path, titles: set):
    """Persist the title registry to disk."""
    (out_dir / "used_titles.txt").write_text(
        "\n".join(sorted(titles)) + "\n", encoding="utf-8")


def content_fingerprint(title, sections, footer_tagline, landmark_prose):
    """SHA-256 hex digest of normalized LLM prose (before slot assembly).

    Uses the raw section prose (not the final HTML with {{ varN }}) so two
    templates with identical LLM output are detected as duplicates even if
    their placeholder mapping differs.
    """
    parts = [title]
    for _kind, prose in sections:
        parts.append(prose)
    parts.append(footer_tagline)
    parts.append(landmark_prose)
    raw = " ".join(parts)
    normalized = " ".join(raw.lower().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# SimHash helpers (stdlib only — no extra deps)
# ---------------------------------------------------------------------------

def _simhash_text(text: str) -> int:
    """Compute a 64-bit SimHash fingerprint from normalized text using 3-word shingles."""
    tokens = re.findall(r"\w+", text.lower())
    shingles = [" ".join(tokens[i:i+3]) for i in range(len(tokens) - 2)] or tokens
    v = [0] * SIMHASH_BITS
    for shingle in shingles:
        h = int(hashlib.md5(shingle.encode()).hexdigest(), 16)
        for i in range(SIMHASH_BITS):
            v[i] += 1 if (h >> i) & 1 else -1
    fp = 0
    for i in range(SIMHASH_BITS):
        if v[i] > 0:
            fp |= 1 << i
    return fp


def _hamming_distance(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def content_simhash(title, sections, footer_tagline, landmark_prose) -> int:
    """SimHash of the same normalized prose used by content_fingerprint()."""
    parts = [title]
    for _kind, prose in sections:
        parts.append(prose)
    parts.append(footer_tagline)
    parts.append(landmark_prose)
    raw = " ".join(parts)
    normalized = " ".join(raw.lower().split())
    return _simhash_text(normalized)


# ---------------------------------------------------------------------------
# Registry client — local JSONL file or remote HTTP API
# ---------------------------------------------------------------------------

class _RegistryClient:
    """Abstract interface for dedup registry access."""

    def load(self):
        """Return (used_titles: set, used_hashes: set, entries: list).

        Remote mode returns empty sets — the server is the source of truth and
        callers never see the full list.
        """
        raise NotImplementedError

    def claim_title(self, category, suggested_title, used_titles=None):
        """Reserve a globally unique title for this category.

        The client suggests a title (model-generated); the server uses it if
        free or substitutes a fresh Faker-generated one. Returns the reserved
        title string — guaranteed unique across all institutions.
        """
        raise NotImplementedError

    def check(self, title, content_hash, simhash=None, used_titles=None, used_hashes=None):
        """Return (collision: bool, similarity_warning: bool).

        collision=True        → exact title or hash already registered; caller must retry.
        similarity_warning=True → near-duplicate prose (SimHash); caller should retry.
        """
        raise NotImplementedError

    def register(self, institution_id, category, title, content_hash, simhash=None):
        """Register a template. Returns True on success, False on collision."""
        raise NotImplementedError


class _LocalRegistryClient(_RegistryClient):
    """Uses the local JSONL file — original behaviour, no network required."""

    def __init__(self, path):
        self.path = path

    def load(self):
        return load_registry(self.path)

    def claim_title(self, category, suggested_title, used_titles=None):
        ut = used_titles or set()
        if suggested_title not in ut:
            return suggested_title
        return _unique_title(category, ut)

    def check(self, title, content_hash, simhash=None, used_titles=None, used_hashes=None):
        ut = used_titles or set()
        uh = used_hashes or set()
        collision = is_collision(title, content_hash, ut, uh)
        return collision, False  # local mode has no SimHash check

    def register(self, institution_id, category, title, content_hash, simhash=None):
        register_template(self.path, institution_id, category, title, content_hash)
        return True


class _RemoteRegistryClient(_RegistryClient):
    """Talks to the central registry API over HTTP.

    Institutions never receive the full registry — only boolean responses.
    Uses urllib (stdlib) so no extra dependencies are needed in the generator.
    """

    def __init__(self, url, api_key):
        self.url = url.rstrip("/")
        self.api_key = api_key

    def _headers(self):
        return {"X-API-Key": self.api_key, "Content-Type": "application/json"}

    def load(self):
        # Remote mode: server is the truth. Return empty — within-session dedup
        # is still handled by the local used_titles.txt file.
        return set(), set(), []

    def claim_title(self, category, suggested_title, used_titles=None):
        import urllib.request, urllib.error
        payload = json.dumps({
            "category": category,
            "suggested_title": suggested_title,
        }).encode()
        req = urllib.request.Request(
            f"{self.url}/claim-title", data=payload,
            headers=self._headers(), method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                return data["title"]
        except Exception as exc:
            print(f"[registry] remote /claim-title failed: {exc} — using suggested title",
                  flush=True)
            return suggested_title

    def check(self, title, content_hash, simhash=None, used_titles=None, used_hashes=None):
        import urllib.request, urllib.error
        payload = json.dumps({
            "title": title, "content_hash": content_hash, "simhash": simhash,
        }).encode()
        req = urllib.request.Request(
            f"{self.url}/check", data=payload,
            headers=self._headers(), method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                return data.get("collision", False), data.get("similarity_warning", False)
        except Exception as exc:
            print(f"[registry] remote /check failed: {exc} — treating as no collision",
                  flush=True)
            return False, False

    def register(self, institution_id, category, title, content_hash, simhash=None):
        import urllib.request, urllib.error
        payload = json.dumps({
            "category": category, "title": title,
            "content_hash": content_hash, "simhash": simhash,
        }).encode()
        req = urllib.request.Request(
            f"{self.url}/register", data=payload,
            headers=self._headers(), method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                return data.get("ok", False)
        except urllib.error.HTTPError as exc:
            if exc.code == 409:
                return False  # collision race — caller will retry
            print(f"[registry] remote /register failed: {exc} — skipping registration",
                  flush=True)
            return False
        except Exception as exc:
            print(f"[registry] remote /register failed: {exc} — skipping registration",
                  flush=True)
            return False


def _make_registry_client(args):
    """Return a _RemoteRegistryClient if --registry-url is set, else _LocalRegistryClient."""
    url = getattr(args, "registry_url", None)
    if url:
        key = getattr(args, "registry_api_key", "") or ""
        return _RemoteRegistryClient(url, key)
    return _LocalRegistryClient(getattr(args, "registry", HERE / "template_registry.jsonl"))


def load_registry(path):
    """Load the shared JSONL registry.

    Returns (used_titles: set[str], used_hashes: set[str], entries: list[dict]).
    Skips malformed lines with a warning.
    """
    used_titles, used_hashes, entries = set(), set(), []
    if not path.exists():
        return used_titles, used_hashes, entries
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[registry] warning: skipping malformed line {lineno}: {e}", flush=True)
                continue
            used_titles.add(entry.get("title", ""))
            used_hashes.add(entry.get("content_hash", ""))
            entries.append(entry)
    return used_titles, used_hashes, entries


def register_template(path, institution_id, category, title, content_hash):
    """Append one JSON line to the shared JSONL registry.

    Creates parent directories if needed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "institution_id": institution_id,
        "category": category,
        "title": title,
        "content_hash": content_hash,
        "registered_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def is_collision(title, content_hash, used_titles, used_hashes):
    """True if title OR content_hash is already in the registry."""
    return title in used_titles or content_hash in used_hashes


def _unique_title(category: str, used_titles: set) -> str:
    """Generate a title that is not already in used_titles."""
    for _ in range(1000):
        title = make_static_title(category)
        if title not in used_titles:
            return title
    return make_static_title(category) + f" ({len(used_titles)})"


def run_register_only(args):
    """Register existing raw_*.txt files in the registry without regenerating.

    Migration helper for institutions that already have generated_templates/.
    Prints a summary: N registered, M skipped (duplicate), K malformed.
    """
    raws = sorted(args.out.glob("raw_*.txt"))
    if not raws:
        raise SystemExit(f"No raw_*.txt to register in {args.out}")

    client = _make_registry_client(args)
    reg_titles, reg_hashes, reg_entries = client.load()
    registered = skipped = malformed = 0

    for fp in raws:
        text = fp.read_text(encoding="utf-8", errors="ignore")
        result = parse_raw(text)
        sections, footer_tagline, landmark_prose, category, static_title = result
        if not sections:
            print(f"[skip] {fp.name}: no sections parsed (malformed)", flush=True)
            malformed += 1
            continue

        if not static_title:
            static_title = make_static_title(category)

        chash = content_fingerprint(static_title, sections, footer_tagline, landmark_prose)
        simhash_val = content_simhash(static_title, sections, footer_tagline, landmark_prose)

        collision, _ = client.check(static_title, chash, simhash_val,
                                    used_titles=reg_titles, used_hashes=reg_hashes)
        if collision:
            existing = next(
                (e for e in reg_entries
                 if e.get("title") == static_title or e.get("content_hash") == chash),
                None,
            )
            src = existing.get("institution_id", "?") if existing else "?"
            print(f"[skip] {fp.name}: duplicate (institution={src})", flush=True)
            skipped += 1
            continue

        client.register(args.institution_id, category, static_title, chash, simhash_val)
        reg_titles.add(static_title)
        reg_hashes.add(chash)
        reg_entries.append({
            "institution_id": args.institution_id, "category": category,
            "title": static_title, "content_hash": chash,
        })
        print(f"[register] {fp.name}: title='{static_title}' hash={chash[:12]}…", flush=True)
        registered += 1

    print(f"\nRegistered {registered}, skipped {skipped} (duplicate), "
          f"{malformed} malformed — total {len(raws)} files", flush=True)


def run_reprocess(args):
    raws = sorted(args.out.glob("raw_*.txt"))
    if not raws:
        raise SystemExit(f"No raw_*.txt to reprocess in {args.out}")

    skip_check = getattr(args, "skip_registry_check", False)
    institution_id = getattr(args, "institution_id", "local")

    client = _make_registry_client(args)
    reg_titles, reg_hashes, reg_entries = client.load()

    used_titles = _load_title_registry(args.out)
    used_titles |= reg_titles

    written = 0
    for fp in raws:
        sections, footer_tagline, landmark_prose, category, static_title = \
            parse_raw(fp.read_text(encoding="utf-8", errors="ignore"))
        if not sections:
            print(f"[skip] {fp.name}: no sections parsed", flush=True)
            continue

        if not static_title:
            static_title = _unique_title(category, used_titles)
        used_titles.add(static_title)

        if uses_anchored_slots(category):
            sections, repair_notes = repair_anchored_sections(sections, category, random)
            if repair_notes:
                print(f"[{fp.name}] repaired anchored slots: "
                      f"{'; '.join(repair_notes)}", flush=True)

        # Apply person-pronoun fix and artifact sentence filter for person categories.
        cat_label = CATEGORIES.get(category, {}).get("subject_slot_label", "")
        is_person_cat = cat_label in ("person", "artist", "figure")
        sections = [
            (kind, fix_person_pronouns(drop_artifact_sentences(prose)) if is_person_cat
             else drop_artifact_sentences(prose))
            for kind, prose in sections
        ]

        chash = content_fingerprint(static_title, sections, footer_tagline, landmark_prose)
        simhash_val = content_simhash(static_title, sections, footer_tagline, landmark_prose)

        if not skip_check:
            # Warn on cross-institution collision; never fail reprocess.
            for entry in reg_entries:
                if entry.get("title") == static_title or entry.get("content_hash") == chash:
                    if entry.get("institution_id") != institution_id:
                        field = "title" if entry.get("title") == static_title else "content hash"
                        print(f"[{fp.name}] warning: {field} collision with entry from "
                              f"institution={entry.get('institution_id')}", flush=True)
                    break
        html, n_ph = assemble_template(
            sections, footer_tagline, landmark_prose, random, args, category,
            static_title=static_title)
        nvars = len(set(re.findall(r"\{\{ var\d+ \}\}", html)))
        write_template(args.out, category, html, category)

        # Register if not already present for this institution.
        if not skip_check:
            already = any(
                e.get("institution_id") == institution_id and e.get("content_hash") == chash
                for e in reg_entries
            )
            if not already:
                client.register(institution_id, category, static_title, chash, simhash_val)
                reg_entries.append({
                    "institution_id": institution_id, "category": category,
                    "title": static_title, "content_hash": chash,
                })
                print(f"[{fp.name}] registered title='{static_title}' hash={chash[:12]}…",
                      flush=True)

        print(f"[{fp.name}] category={category} title='{static_title}' "
              f"{len(sections)} sections, "
              f"{n_ph} raw placeholders, "
              f"{nvars} distinct vars -> scraper_gen_{category}.html (+ .txt)", flush=True)
        written += 1

    _save_title_registry(args.out, used_titles)
    print(f"\nReprocessed {written} templates in {args.out}", flush=True)


# Per-category retry ceiling. Each attempt runs the full model pass (title +
# every section + footer + landmark), so an unbounded ``while not accepted``
# loop can burn the whole subprocess timeout (~30 min) silently retrying a
# category that never validates/dedups. Cap it so a genuinely stuck category
# fails fast with a clear message instead of hanging.
MAX_GEN_ATTEMPTS = 12

# Progress protocol (opt-in). When TEMPLATE_GEN_PROGRESS=1 (set by the web app's
# background worker), emit one machine-readable line per milestone that the app
# parses to drive the live progress bar. The prefix is deliberately distinctive
# so it is trivially separable from ordinary model/log output; the CLI leaves the
# env var unset, so interactive runs stay clean.
_PROGRESS_PREFIX = "@@GENPROGRESS@@"


def _emit_progress(percent, stage, label, **extra):
    """Print a progress event for the app to parse (no-op unless opted in).

    ``percent`` is an overall 0..100 estimate; ``stage`` is a coarse phase
    (``loading`` | ``generating`` | ``finalizing`` | ``done`` | ``error``);
    ``label`` is a human-readable status line.
    """
    if os.environ.get("TEMPLATE_GEN_PROGRESS") != "1":
        return
    payload = {"percent": round(float(percent), 1), "stage": stage, "label": label}
    payload.update(extra)
    print(_PROGRESS_PREFIX + json.dumps(payload), flush=True)


def run_generate(args):
    _emit_progress(2, "loading", "Loading the model…")
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel

    if torch.cuda.is_available():
        device = "cuda"
    elif torch.backends.mps.is_available():
        device = "mps"
    else:
        device = "cpu"

    use_adapter = (not args.base_only) and args.adapter.exists()
    tok = AutoTokenizer.from_pretrained(str(args.adapter) if use_adapter else args.model)
    if tok.pad_token_id is None:
        tok.pad_token = tok.eos_token

    if args.dtype == "auto":
        infer_dtype = (torch.bfloat16 if device == "cuda"
                       else torch.float16 if device == "mps" else torch.float32)
    else:
        infer_dtype = {"float32": torch.float32, "float16": torch.float16,
                       "bfloat16": torch.bfloat16}[args.dtype]
    print(f"device={device} dtype={infer_dtype} | "
          f"{'LoRA adapter: ' + str(args.adapter) if use_adapter else 'BASE model (no adapter)'}",
          flush=True)
    _emit_progress(6, "loading", f"Loading model weights on {device}…")

    model = AutoModelForCausalLM.from_pretrained(args.model, dtype=infer_dtype)
    if use_adapter:
        _emit_progress(9, "loading", "Applying the LoRA adapter…")
        model = PeftModel.from_pretrained(model, str(args.adapter))
    model.to(device).eval()
    _emit_progress(12, "loading", "Model ready.")

    prefix = "" if use_adapter else few_shot_prefix()
    args.out.mkdir(parents=True, exist_ok=True)

    if args.category:
        category_pool = [args.category]
    else:
        category_pool = sorted(CATEGORIES.keys())
    args.num = len(category_pool)

    client = _make_registry_client(args)
    reg_titles, reg_hashes, reg_entries = client.load()

    used_titles = _load_title_registry(args.out)
    used_titles |= reg_titles
    used_hashes = set(reg_hashes)

    written = 0
    nc = len(category_pool)
    for ci, category in enumerate(category_pool):
        section_specs = get_section_specs(category)
        fixed_headings = get_fixed_headings(category)
        nice_cat = category.replace("_", " ")
        n_sections = len(section_specs)

        # Overall progress mapping: the model load owns 0..12%, the categories
        # split 12..98% evenly, and each category's band is walked by its
        # sub-steps (title -> sections -> footer -> landmark -> finalize). A
        # retry re-walks the same band; the app clamps the bar monotonic so it
        # never jumps backwards.
        band_lo, band_w = 12 + 86 * ci / nc, 86 / nc

        def pct(frac):
            return band_lo + band_w * frac

        _emit_progress(pct(0.0), "generating",
                       f"Generating the {nice_cat} article… ({ci + 1}/{nc})",
                       category=category, category_index=ci + 1, category_total=nc)

        accepted = False
        attempt = 0
        while not accepted:
            # Bound the retry loop so a category that never validates/dedups
            # fails fast instead of burning the whole subprocess timeout.
            if attempt >= MAX_GEN_ATTEMPTS:
                print(f"[{category}] giving up after {attempt} attempts — no "
                      f"candidate passed validation/dedup; skipping this category.",
                      flush=True)
                _emit_progress(pct(0.95), "generating",
                               f"Skipped {nice_cat}: no valid candidate after "
                               f"{attempt} attempts.", category=category)
                break

            # --- Title ---
            raw_title = generate_title(model, tok, device, prefix, args, category)
            # Reserve a globally unique title (the server/local client uses the
            # model's suggestion if free, else substitutes a fresh one). Do NOT
            # add it to used_titles here: the collision check below reads
            # used_titles, and a premature add makes every candidate collide with
            # itself (the title is always "already used"). It is recorded on
            # accept instead, exactly mirroring how used_hashes is handled.
            static_title = client.claim_title(category, raw_title, used_titles=used_titles)
            _emit_progress(pct(0.15), "generating",
                           f"[{nice_cat}] drafting sections…", category=category)

            # --- Content ---
            cat_label = CATEGORIES.get(category, {}).get("subject_slot_label", "")
            is_person_category = cat_label in ("person", "artist", "figure")
            sections, raw_parts = [], []
            for si, (kind, instruction) in enumerate(section_specs, 1):
                prose = generate_one(model, tok, device, instruction, prefix, args)
                if is_person_category:
                    prose = fix_person_pronouns(prose)
                sections.append((kind, prose))
                raw_parts.append(f"## {fixed_headings[kind]}\n{prose}")
                _emit_progress(pct(0.15 + 0.55 * si / n_sections), "generating",
                               f"[{nice_cat}] wrote {fixed_headings[kind]} "
                               f"({si}/{n_sections})", category=category)

            footer_tagline = generate_footer(model, tok, device, prefix, args, category)
            _emit_progress(pct(0.78), "generating",
                           f"[{nice_cat}] wrote the footer", category=category)
            landmark_prose = generate_landmarks(model, tok, device, prefix, args, category)
            _emit_progress(pct(0.86), "generating",
                           f"[{nice_cat}] wrote the closing section", category=category)

            if uses_anchored_slots(category):
                sections, repair_notes = repair_anchored_sections(sections, category, random)
                if repair_notes:
                    print(f"[{category}] repaired anchored slots: "
                          f"{'; '.join(repair_notes)}", flush=True)
                raw_parts = [
                    f"## {fixed_headings[kind]}\n{prose}" for kind, prose in sections]
                raw_errors = validate_raw_named_vars(sections)
                if raw_errors:
                    attempt += 1
                    print(f"[{category}] attempt {attempt} rejected: "
                          f"raw [[VARn]] validation: {raw_errors}", flush=True)
                    continue

            chash = content_fingerprint(static_title, sections, footer_tagline, landmark_prose)
            simhash_val = content_simhash(static_title, sections, footer_tagline, landmark_prose)

            # --- Collision check ---
            _emit_progress(pct(0.9), "finalizing",
                           f"[{nice_cat}] checking the dedup registry…", category=category)
            if not args.skip_registry_check:
                collision, sim_warning = client.check(
                    static_title, chash, simhash_val,
                    used_titles=used_titles, used_hashes=used_hashes,
                )
                if collision:
                    title_hit = static_title in used_titles
                    field = "title" if title_hit else "content hash"
                    existing = next(
                        (e for e in reg_entries
                         if (title_hit and e.get("title") == static_title)
                         or (not title_hit and e.get("content_hash") == chash)),
                        None,
                    )
                    src = existing.get("institution_id", "?") if existing else "this run"
                    attempt += 1
                    print(f"[{category}] attempt {attempt} rejected: "
                          f"{field} collision with "
                          f"'{static_title if title_hit else chash[:12]}…' "
                          f"(existing entry from institution={src})", flush=True)
                    continue
                if sim_warning:
                    attempt += 1
                    print(f"[{category}] attempt {attempt} rejected: near-duplicate "
                          f"content detected (simhash distance ≤ {SIMHASH_THRESHOLD}), "
                          f"retrying", flush=True)
                    continue

            # --- Accept ---
            html, n_ph = assemble_template(
                sections, footer_tagline, landmark_prose, random, args, category,
                static_title=static_title)

            if uses_anchored_slots(category):
                anchor_errors = validate_anchored_slots_in_html(html, category)
                if anchor_errors:
                    attempt += 1
                    print(f"[{category}] attempt {attempt} rejected: "
                          f"anchor validation: {anchor_errors}", flush=True)
                    continue

            nvars = len(set(re.findall(r"\{\{ var\d+ \}\}", html)))

            write_raw(args.out, category, raw_parts, footer_tagline, landmark_prose,
                      category, static_title=static_title)
            write_template(args.out, category, html, category)

            if not args.skip_registry_check:
                client.register(args.institution_id, category, static_title, chash,
                                simhash_val)
                reg_entries.append({
                    "institution_id": args.institution_id, "category": category,
                    "title": static_title, "content_hash": chash,
                })
                print(f"[{category}] registered title='{static_title}' "
                      f"hash={chash[:12]}… institution={args.institution_id}", flush=True)

            used_titles.add(static_title)
            used_hashes.add(chash)
            print(f"[{category}] title='{static_title}' "
                  f"{len(section_specs)} sections, "
                  f"{n_ph} raw placeholders, {nvars} distinct vars "
                  f"-> scraper_gen_{category}.html (+ .txt)", flush=True)
            _emit_progress(pct(1.0), "finalizing",
                           f"Finished the {nice_cat} article.", category=category)
            written += 1
            accepted = True
            break

    _save_title_registry(args.out, used_titles)
    print(f"\nWrote {written} templates to {args.out}", flush=True)
    _emit_progress(100, "done",
                   f"Wrote {written} template{'' if written == 1 else 's'}.",
                   written=written)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default="Qwen/Qwen3-1.7B")
    ap.add_argument("--adapter", type=Path, default=DEFAULT_ADAPTER)
    ap.add_argument("--base-only", action="store_true",
                    help="skip the LoRA adapter; few-shot prompt the base model instead")
    ap.add_argument("--reprocess", action="store_true",
                    help="rebuild .html/.txt from existing raw_<i>.txt (no model/torch needed)")
    ap.add_argument("--max-new-tokens", type=int, default=1500)
    ap.add_argument("--temperature", type=float, default=0.9)
    ap.add_argument("--top-p", type=float, default=0.95)
    ap.add_argument("--dtype", choices=["auto", "float32", "float16", "bfloat16"],
                    default="auto",
                    help="auto = bf16 on CUDA, fp16 on MPS, fp32 on CPU")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--category", default=None,
                    choices=list(CATEGORIES.keys()),
                    help="generate templates for a specific category only "
                         "(default: cycle evenly through all 20 categories)")
    ap.add_argument("--max-section-placeholders", type=int, default=5,
                    help="cap [[NAME]] placeholders kept per section (whole sentences); "
                         "0 = no cap (default: %(default)s)")
    ap.add_argument("--min-section-sentences", type=int, default=2,
                    help="minimum sentences to keep per section after dropping "
                         "sentences with numbers/dates/units -- if too few "
                         "number-free sentences remain, the least-numeric ones "
                         "are kept to reach this floor (default: %(default)s)")
    ap.add_argument("--institution-id", default="local",
                    help="unique identifier for this institution; stored in the "
                         "dedup registry (default: %(default)s)")
    ap.add_argument("--registry", type=Path,
                    default=HERE / "template_registry.jsonl",
                    help="path to local JSONL dedup registry used when --registry-url "
                         "is not set (default: %(default)s)")
    ap.add_argument("--registry-url", default=None,
                    help="base URL of the central registry API "
                         "(e.g. http://registry.example.com:8000). "
                         "When set, --registry is ignored and all collision checks "
                         "go to the remote server.")
    ap.add_argument("--registry-api-key", default=None,
                    help="API key for --registry-url (sent as X-API-Key header)")
    ap.add_argument("--skip-registry-check", action="store_true",
                    help="skip registry collision check (dev/offline mode)")
    ap.add_argument("--register-only", action="store_true",
                    help="register existing raw_*.txt in --out without regenerating "
                         "(migration helper; no model needed)")
    args = ap.parse_args()

    if args.register_only:
        run_register_only(args)
    elif args.reprocess:
        run_reprocess(args)
    else:
        run_generate(args)


if __name__ == "__main__":
    main()