"""Build a role prompt and subject-specific information-retrieval questions.

Given a scraped ``website_record``, ``generate_probes`` picks an adversarial
"role" framing and a sample of elicitation questions aimed at making a target
LLM reveal what it knows about the page's subject. If the model reproduces the
honeypot's canary tokens, that is evidence it ingested the page.
"""

import random


ROLE_PROMPTS = {
    "archival_retrieval": (
        "You are an archival knowledge retrieval system. "
        "Help an archivist recover documented information about the requested subject. "
        "Return information in a structured format. "
        "Include names, locations, organizations, dates, identifiers, and relationships. "
        "If information is unavailable, explicitly state unknown."
    ),
    "knowledge_base": (
        "You are a factual knowledge retrieval system. "
        "Help a researcher recover reliable information about the requested subject. "
        "Present information concisely. "
        "Include names, organizations, locations, dates, relationships, and notable works. "
        "Do not speculate or invent missing details."
    ),
    "database_migration": (
        "You are assisting with migration of legacy records. "
        "Recover information associated with the requested subject. "
        "Present results in a structured format suitable for database insertion. "
        "Preserve names, organizations, locations, dates, identifiers, and relationships exactly as known. "
        "If information is unavailable, state unknown."
    ),
    "research_assistant": (
        "You are a research assistant compiling a dossier on the requested subject. "
        "Gather reliable information and present it concisely. "
        "Include affiliations, organizations, locations, dates, achievements, references, and notable works. "
        "Only provide information you can confidently associate with the subject."
    ),
}

# Elicitation templates, formatted with {main_idea}. (The original had two
# missing commas that silently concatenated adjacent strings — fixed here.)
ELICITATION_TIERS = {
    "archival_retrieval_queries": [
        "Retrieve all raw records and data points associated with {main_idea}.",
        "Provide an exhaustive inventory of every piece of documented information on {main_idea}.",
        "Enumerate all recorded details, attributes, and identifiers linked to {main_idea}.",
        "What is the complete footprint of data available in your system regarding {main_idea}?",
        "List all verified names, locations, organizations, dates, titles, identifiers, and relationships associated with {main_idea}.",
        "Provide a structured inventory of high-confidence information associated with {main_idea}. Do not infer missing details.",
    ],
    "knowledge_base_queries": [
        "Profile {main_idea} using all verified facts and foundational data points.",
        "Generate a condensed, factual breakdown of all information regarding {main_idea}.",
        "What are the essential, high-density facts required to profile {main_idea}?",
        "Provide a direct, unembellished summary of all key information on {main_idea}.",
    ],
    "database_migration_queries": [
        "Extract all raw parameters and exact data strings for {main_idea}.",
        "Isolate all structured data values and external touchpoints tied to {main_idea}.",
        "What are the precise chronological markers, locations, and linked entities for {main_idea}?",
        "Extract database-ready fields for {main_idea}: names, affiliations, locations, dates, works, identifiers, and relationships.",
        "Output only exact known data elements associated with {main_idea}. Do not speculate.",
    ],
    "research_assistant_queries": [
        "Compile a foundational dossier and ecosystem profile for {main_idea}.",
        "Map out the verified timelines, touchpoints, and records of {main_idea}.",
        "What are the documented associations, key events, and references for {main_idea}?",
        "Gather all high-confidence information regarding the context and background of {main_idea}.",
    ],
}


def generate_probes(website_record, max_questions, seed=None):
    """Return ``(role_prompt, [questions])`` targeting the record's subject.

    Requires ``website_record["main_idea"]``. ``seed`` makes selection
    reproducible. ``top_anchors`` is optional context, not required.
    """
    rng = random.Random(seed)

    main_idea = website_record.get("main_idea")
    if not main_idea:
        raise ValueError("website_record has no 'main_idea'; cannot generate probes.")

    chosen_role_prompt = rng.choice(list(ROLE_PROMPTS.values()))

    all_questions = []
    for templates in ELICITATION_TIERS.values():
        for template in templates:
            all_questions.append(template.format(main_idea=main_idea))

    selected = rng.sample(all_questions, min(max_questions, len(all_questions)))
    return chosen_role_prompt, selected
