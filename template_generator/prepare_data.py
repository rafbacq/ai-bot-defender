#!/usr/bin/env python3
"""
Build a supervised fine-tuning (SFT) dataset for the honeypot template model.

Supports 20 content categories sourced from:
  1. ../cleaned_intros/         -- Wikipedia-style town intros (already masked)
  2. data/text_generator_dataset/<category>/  -- Wikipedia articles per category,
     scraped by scrape_wikipedia.py and masked here with spaCy NER.

Every example is normalised to [[NAME]] placeholders and tagged with its
category so the model learns category-aware generation. Numbers are stripped
entirely -- the model is trained to write number-free prose.

Output: template_generator/data/sft.jsonl
    {"instruction": "...", "target": "...", "category": "us_cities"}
"""
'''
build a supervised fine-tuning (SFT) dataset for template generation.
turns wikipedia article texts into data/sft.jsonl that train.py fine-tunes on.
'''
import argparse
import json
import random
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
DEFAULT_INTROS = PROJECT_ROOT / "cleaned_intros"
DEFAULT_WIKI_CATEGORIES = HERE / "data" / "text_generator_dataset"
DEFAULT_OUT = HERE / "data" / "sft.jsonl"

NAME_PH = "[[NAME]]" #converts nouns into placeholders

# category definitions.
# each category has:
#   display: simple name for the category (used in prompts)
#   subject: what the article is about (used in instructions)
#   sections: the different sections the model will be asked to write

#20 categories 
CATEGORIES = {
    "tourist_locations": {
        "display": "tourist location or landmark",
        "subject": "fictional tourist location or landmark",
        "sections": ["history", "description", "significance"],
    },
    "biography": {
        "display": "person",
        "subject": "fictional person",
        "sections": ["early_life", "career", "legacy"],
    },
    "towns": {
        "display": "U.S. town or small city",
        "subject": "fictional U.S. town or small city",
        "sections": ["history", "culture", "economy"],
    },
    "artists": {
        "display": "visual artist",
        "subject": "fictional visual artist",
        "sections": ["early_life", "style", "legacy"],
    },
    "movies": {
        "display": "film",
        "subject": "fictional film",
        "sections": ["plot", "production", "reception"],
    },
    "books": {
        "display": "novel or book",
        "subject": "fictional novel",
        "sections": ["plot", "themes", "reception"],
    },
    "historical_figures": {
        "display": "historical figure",
        "subject": "fictional historical figure",
        "sections": ["early_life", "career", "legacy"],
    },
    "animals": {
        "display": "animal species",
        "subject": "fictional animal species",
        "sections": ["description", "habitat", "behaviour"],
    },
    "political_figures": {
        "display": "political figure",
        "subject": "fictional political figure",
        "sections": ["early_life", "career", "legacy"],
    },
    "universities": {
        "display": "university or college",
        "subject": "fictional university or college",
        "sections": ["history", "academics", "culture"],
    },
    "companies": {
        "display": "company or corporation",
        "subject": "fictional company",
        "sections": ["history", "operations", "culture"],
    },
    "languages": {
        "display": "language",
        "subject": "fictional language",
        "sections": ["overview", "description", "history"],
    },
    "cuisine": {
        "display": "dish or cuisine",
        "subject": "fictional dish or regional cuisine",
        "sections": ["overview", "description", "history"],
    },
    "scientists_inventors": {
        "display": "scientist or inventor",
        "subject": "fictional scientist or inventor",
        "sections": ["early_life", "career", "legacy"],
    },
    "clothing": {
        "display": "garment or clothing tradition",
        "subject": "fictional garment or clothing tradition",
        "sections": ["description", "history", "significance"],
    },
    "medicine": {
        "display": "medical condition or treatment",
        "subject": "fictional medical condition",
        "sections": ["overview", "description", "history"],
    },
    "sports_teams": {
        "display": "sports team",
        "subject": "fictional sports team",
        "sections": ["history", "culture", "legacy"],
    },
    "folklore": {
        "display": "folktale or legend",
        "subject": "fictional folktale or legend",
        "sections": ["origins", "mythology", "legacy"],
    },
    "video_games": {
        "display": "video game",
        "subject": "fictional video game",
        "sections": ["overview", "gameplay", "reception"],
    },
    "religion": {
        "display": "religion or belief system",
        "subject": "fictional religion or belief system",
        "sections": ["origins", "overview", "legacy"],
    },
}

# maps section kinds to display headings
SECTION_HEADINGS = {
    "history":      "History",
    "culture":      "Culture",
    "economy":      "Economy",
    "description":  "Description",
    "habitat":      "Habitat",
    "behaviour":    "Behaviour",
    "cultivation":  "Cultivation",
    "plot":         "Plot",
    "production":   "Production",
    "reception":    "Reception",
    "premise":      "Premise",
    "themes":       "Themes",
    "gameplay":     "Gameplay",
    "story":        "Story",
    "development":  "Development",
    "background":   "Background",
    "recording":    "Recording",
    "style":        "Style",
    "legacy":       "Legacy",
    "operations":   "Operations",
    "early_life":   "Early Life",
    "career":       "Career",
    "observation":  "Observation",
    "significance": "Significance",
    "properties":   "Properties",
    "uses":         "Uses",
    "safety":       "Safety",
    "origins":      "Origins",
    "mythology":    "Mythology",
    "overview":     "Overview",
    "features":     "Features",
    "powers":       "Powers",
    "academics":    "Academics",
}

# placeholder rule added to every instruction.
PLACEHOLDER_RULE = (
    "Use [[NAME]] for every proper name (person, place, organisation, title, brand, "
    "species, etc.). Do NOT include any numbers, dates, years, statistics, or "
    "percentages -- omit or rephrase to avoid them entirely. "
    "Write 4-6 sentences of plain encyclopaedia prose."
)

# section specific instruction templates. {subject} is filled with the category subject.
SECTION_INSTRUCTIONS = {
    "history":      "Write the 'History' section of a Wikipedia-style article about a {subject}. Describe its origins, founding, and key developments over time. " + PLACEHOLDER_RULE,
    "culture":      "Write the 'Culture' section of a Wikipedia-style article about a {subject}. Describe traditions, arts, community character, and notable cultural features. " + PLACEHOLDER_RULE,
    "economy":      "Write the 'Economy' section of a Wikipedia-style article about a {subject}. Describe the main industries, employers, and economic character without any numbers. " + PLACEHOLDER_RULE,
    "description":  "Write the 'Description' section of a Wikipedia-style article about a {subject}. Describe its appearance, characteristics, and distinguishing features. " + PLACEHOLDER_RULE,
    "habitat":      "Write the 'Habitat' section of a Wikipedia-style article about a {subject}. Describe where it lives, the environment it prefers, and its range. " + PLACEHOLDER_RULE,
    "behaviour":    "Write the 'Behaviour' section of a Wikipedia-style article about a {subject}. Describe how it behaves, feeds, and interacts with its environment. " + PLACEHOLDER_RULE,
    "cultivation":  "Write the 'Cultivation' section of a Wikipedia-style article about a {subject}. Describe how it is grown, cultivated, or propagated. " + PLACEHOLDER_RULE,
    "plot":         "Write the 'Plot' section of a Wikipedia-style article about a {subject}. Summarise the story without spoiling the ending, using [[NAME]] for all character and place names. " + PLACEHOLDER_RULE,
    "production":   "Write the 'Production' section of a Wikipedia-style article about a {subject}. Describe how it was made, who was involved, and any notable behind-the-scenes details. " + PLACEHOLDER_RULE,
    "reception":    "Write the 'Reception' section of a Wikipedia-style article about a {subject}. Describe how it was received by audiences and critics without using numbers or scores. " + PLACEHOLDER_RULE,
    "premise":      "Write the 'Premise' section of a Wikipedia-style article about a {subject}. Describe the central concept, setting, and main characters. " + PLACEHOLDER_RULE,
    "themes":       "Write the 'Themes' section of a Wikipedia-style article about a {subject}. Describe the central ideas, motifs, and messages explored. " + PLACEHOLDER_RULE,
    "gameplay":     "Write the 'Gameplay' section of a Wikipedia-style article about a {subject}. Describe the core mechanics, player experience, and notable features. " + PLACEHOLDER_RULE,
    "story":        "Write the 'Story' section of a Wikipedia-style article about a {subject}. Summarise the narrative and main characters using [[NAME]] for all names. " + PLACEHOLDER_RULE,
    "development":  "Write the 'Development' section of a Wikipedia-style article about a {subject}. Describe how it was created, who made it, and what inspired it. " + PLACEHOLDER_RULE,
    "background":   "Write the 'Background' section of a Wikipedia-style article about a {subject}. Describe the context and circumstances that led to its creation. " + PLACEHOLDER_RULE,
    "recording":    "Write the 'Recording' section of a Wikipedia-style article about a {subject}. Describe the recording process, who was involved, and where it was made. " + PLACEHOLDER_RULE,
    "style":        "Write the 'Style' section of a Wikipedia-style article about a {subject}. Describe the artistic style, influences, and distinctive characteristics. " + PLACEHOLDER_RULE,
    "legacy":       "Write the 'Legacy' section of a Wikipedia-style article about a {subject}. Describe its lasting impact, influence, and cultural significance. " + PLACEHOLDER_RULE,
    "operations":   "Write the 'Operations' section of a Wikipedia-style article about a {subject}. Describe how it operates, its key activities, and organisational structure. " + PLACEHOLDER_RULE,
    "early_life":   "Write the 'Early Life' section of a Wikipedia-style article about a {subject}. Describe their background, upbringing, and formative experiences. " + PLACEHOLDER_RULE,
    "career":       "Write the 'Career' section of a Wikipedia-style article about a {subject}. Describe their professional journey, key achievements, and notable work. " + PLACEHOLDER_RULE,
    "observation":  "Write the 'Observation' section of a Wikipedia-style article about a {subject}. Describe how it has been observed, studied, and documented. " + PLACEHOLDER_RULE,
    "significance": "Write the 'Significance' section of a Wikipedia-style article about a {subject}. Describe its scientific, cultural, or historical importance. " + PLACEHOLDER_RULE,
    "properties":   "Write the 'Properties' section of a Wikipedia-style article about a {subject}. Describe its physical and chemical characteristics without using numbers. " + PLACEHOLDER_RULE,
    "uses":         "Write the 'Uses' section of a Wikipedia-style article about a {subject}. Describe its practical applications and how it is used. " + PLACEHOLDER_RULE,
    "safety":       "Write the 'Safety' section of a Wikipedia-style article about a {subject}. Describe any known hazards, precautions, and safe handling practices. " + PLACEHOLDER_RULE,
    "origins":      "Write the 'Origins' section of a Wikipedia-style article about a {subject}. Describe where it comes from and the historical context of its creation. " + PLACEHOLDER_RULE,
    "mythology":    "Write the 'Mythology' section of a Wikipedia-style article about a {subject}. Describe the myths, legends, and stories associated with it. " + PLACEHOLDER_RULE,
    "overview":     "Write the 'Overview' section of a Wikipedia-style article about a {subject}. Provide a general introduction to what it is and why it matters. " + PLACEHOLDER_RULE,
    "features":     "Write the 'Features' section of a Wikipedia-style article about a {subject}. Describe its key features, capabilities, and distinguishing qualities. " + PLACEHOLDER_RULE,
    "powers":       "Write the 'Powers' section of a Wikipedia-style article about a {subject}. Describe their abilities, strengths, and special characteristics. " + PLACEHOLDER_RULE,
    "academics":    "Write the 'Academics' section of a Wikipedia-style article about a {subject}. Describe the academic programmes, research focus, and educational character. " + PLACEHOLDER_RULE,
}

# gets the instruction for a given section kind and category
def get_instruction(section_kind: str, category: str) -> str:
    subject = CATEGORIES[category]["subject"]
    template = SECTION_INSTRUCTIONS.get(section_kind, SECTION_INSTRUCTIONS["overview"])
    return template.format(subject=subject)

# define regex patterns for numbers, coordinates, and percentages
LITERAL_NUM_RE = re.compile(r"(?<![\w°′″])-?\d[\d,]*(?:\.\d+)?(?![\w°′″])")
ORDINAL_RE = re.compile(r"\b\d+(st|nd|rd|th)\b", re.I)
PERCENT_RE = re.compile(r"\b\d+(\.\d+)?\s*(%|percent)\b", re.I)
COORD_RE = re.compile(r"\d+\s*°\s*\d+\s*[′']?\s*\d*\s*[″\"]?\s*[NSEWnsew]\b")

# removes numbers from text
def strip_numbers(text: str) -> str:
    text = COORD_RE.sub("", text)
    text = ORDINAL_RE.sub("", text)
    text = PERCENT_RE.sub("", text)
    text = LITERAL_NUM_RE.sub("", text)
    return text

# cleans up whitespace and punctuation
def tidy(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s+([,.;:!?'])", r"\1", text)
    text = re.sub(r"([('])\s+", r"\1", text)
    text = re.sub(r"(\[\[NAME\]\])(\s+\1)+", r"\1", text)
    text = re.sub(r"\s*,\s*,", ",", text)
    text = re.sub(r",\s*\.", ".", text)
    return re.sub(r"\s+", " ", text).strip()

# replaces <var_name> with [[NAME]] from cleaned_intros
def normalize_intro(text: str) -> str:
    text = re.sub(r"[<>\s]*\bvar_num\b[<>\s]*",  " [[NAME]] ", text)
    text = re.sub(r"[<>\s]*\bvar_name\b[<>\s]*", " [[NAME]] ", text)
    text = text.replace("<", " ").replace(">", " ")
    text = strip_numbers(text)
    return tidy(text)

# ---------------------------------------------------------------------------
# spaCy masking.
# ---------------------------------------------------------------------------
# define labels for named entities to be masked
NAME_LABELS = {
    "PERSON", "GPE", "LOC", "ORG", "FAC", "NORP", "EVENT",
    "WORK_OF_ART", "PRODUCT", "LANGUAGE",
    "DATE", "TIME", "CARDINAL", "ORDINAL", "QUANTITY", "PERCENT", "MONEY",
}

# headings to skip, don't include in training data 
SKIP_HEADINGS = {
    "references", "external links", "see also", "notes", "citations",
    "footnotes", "further reading", "bibliography", "sources", "gallery",
    "works cited",
}

# regex pattern for section headings
HEADING_RE = re.compile(r"^\s*={2,}\s*(.*?)\s*={2,}\s*$", re.M)

# loads spacy model
def load_spacy():
    try:
        import spacy
        return spacy.load("en_core_web_sm",
                          disable=["lemmatizer", "tagger", "parser", "attribute_ruler"])
    except (ImportError, OSError):
        return None

# masks named entities with [[NAME]]
def mask_with_spacy(text: str, nlp) -> str:
    doc = nlp(text)
    spans = [(e.start_char, e.end_char) for e in doc.ents if e.label_ in NAME_LABELS]
    for start, end in sorted(spans, reverse=True):
        text = text[:start] + NAME_PH + text[end:]
    return text

# cleans up wikipedia text, removes markup and boilerplate
def clean_wiki(text: str) -> str:
    text = re.sub(r"/[^/\n]{1,40}/", " ", text)
    text = re.sub(r"\[[^\]\n]{0,40}\]", " ", text)
    text = re.sub(r"\([^)\n]*listen[^)\n]*\)", " ", text, flags=re.I)
    return text

# splits wikipedia text into sections
def split_sections(raw: str):
    parts = HEADING_RE.split(raw)
    yield "intro", parts[0]
    for i in range(1, len(parts) - 1, 2):
        heading = parts[i].strip()
        if heading.lower().strip() in SKIP_HEADINGS:
            continue
        yield heading, parts[i + 1]

# splits text into paragraphs
def to_paragraphs(body: str):
    out = []
    for para in re.split(r"\n\s*\n", body):
        para = re.sub(r"\s*\n\s*", " ", para).strip()
        if para:
            out.append(para)
    return out

# turn paragraphts into training examples, returns nothing if not enough words or placeholders
def emit(buf: list, section_kind: str, category: str, args, rng) -> list:
    text = tidy(strip_numbers(" ".join(buf)))
    words = text.split()
    if len(words) > args.max_words:
        text = " ".join(words[:args.max_words])
    nwords = len(text.split())
    nph = text.count("[[NAME]]")
    if not (args.min_words <= nwords <= args.max_words) or nph < args.min_placeholders:
        return []
    instruction = get_instruction(section_kind, category)
    return [{"instruction": instruction, "target": text, "category": category}]

# build chunks of training examples from wikipedia paragraphs
# passes each chunk to emit to check if it's valid
def chunk_examples(paragraphs: list, section_kind: str, category: str, args, rng) -> list:
    examples, buf, words = [], [], 0
    for para in paragraphs:
        para = tidy(strip_numbers(para))
        n = len(para.split())
        if n == 0:
            continue
        if words and words + n > args.max_words:
            examples += emit(buf, section_kind, category, args, rng)
            buf, words = [], 0
        buf.append(para)
        words += n
        if words >= args.min_words:
            examples += emit(buf, section_kind, category, args, rng)
            buf, words = [], 0
    if buf:
        examples += emit(buf, section_kind, category, args, rng)
    return examples

# map wikipedia section headings to section kinds per category
def heading_to_section_kind(heading: str, category: str) -> str:
    h = heading.lower()
    cat_sections = CATEGORIES.get(category, {}).get("sections", ["overview"])

    # match the heading to one of the category's sections
    mapping = {
        "history": "history", "founding": "history", "background": "background",
        "culture": "culture", "tradition": "culture",
        "economy": "economy", "industry": "economy", "business": "economy",
        "description": "description", "appearance": "description",
        "habitat": "habitat", "range": "habitat", "distribution": "habitat",
        "behaviour": "behaviour", "behavior": "behaviour", "ecology": "behaviour",
        "cultivation": "cultivation", "growing": "cultivation",
        "plot": "plot", "synopsis": "plot", "story": "story",
        "production": "production", "development": "development", "making": "production",
        "reception": "reception", "legacy": "legacy", "impact": "legacy",
        "premise": "premise", "concept": "premise",
        "themes": "themes", "theme": "themes",
        "gameplay": "gameplay", "mechanics": "gameplay",
        "recording": "recording", "recording sessions": "recording",
        "style": "style", "musical style": "style", "influences": "style",
        "operations": "operations", "business operations": "operations",
        "early life": "early_life", "childhood": "early_life", "education": "early_life",
        "career": "career", "professional career": "career",
        "observation": "observation",
        "significance": "significance",
        "properties": "properties", "physical properties": "properties",
        "uses": "uses", "applications": "uses",
        "safety": "safety", "hazards": "safety",
        "origins": "origins", "origin": "origins",
        "mythology": "mythology", "myths": "mythology",
        "overview": "overview",
        "features": "features",
        "powers": "powers", "abilities": "powers",
        "academics": "academics", "academic programs": "academics",
    }
    kind = mapping.get(h, None)

    # fall back to the first section kind for the category
    if kind is None or kind not in cat_sections:
        kind = cat_sections[0]
    return kind

# build training examples from cleaned_intros
def build_intro_examples(args, rng) -> list:
    files = sorted(args.intros.glob("*.txt"))
    rng.shuffle(files) #randomly shuffle the files
    out, skipped = [], 0
    for fp in files:
        raw = fp.read_text(errors="ignore").strip()
        if not raw:
            skipped += 1
            continue
        norm = normalize_intro(raw)
        nwords = len(norm.split())
        nph = norm.count("[[NAME]]")
        if not (args.min_words <= nwords <= args.max_words) or nph < args.min_placeholders:
            skipped += 1
            continue
        instruction = get_instruction("history", "towns")
        out.append({"instruction": instruction, "target": norm, "category": "towns"})
        if args.intro_limit and len(out) >= args.intro_limit:
            break
    print(f"cleaned_intros: kept {len(out)} (skipped {skipped})")
    return out

# processes all 20 categories 
# take all scraped article from all categories and turn it into training example
def build_category_examples(args, rng, nlp) -> list:
    all_examples = []

    for category, cat_info in CATEGORIES.items():
        cat_dir = args.wiki_categories / category
        if not cat_dir.exists():
            print(f"[{category}] folder not found at {cat_dir} -- skipping")
            continue

        files = sorted(cat_dir.glob("*.txt"))
        rng.shuffle(files)
        if args.wiki_limit:
            files = files[:args.wiki_limit]

        if not files:
            print(f"[{category}] no .txt files found -- skipping")
            continue

        pending = [] 
        for fp in files:
            raw = fp.read_text(errors="ignore")
            if not raw.strip():
                continue
            for heading, body in split_sections(raw):
                paras = to_paragraphs(clean_wiki(body))
                if not paras:
                    continue
                joined = "\n\n".join(paras)[:args.wiki_section_chars]
                section_kind = heading_to_section_kind(
                    heading if heading != "intro" else cat_info["sections"][0],
                    category
                )
                pending.append((section_kind, joined))

        if not pending:
            print(f"[{category}] no sections extracted -- skipping")
            continue

        # batch spaCy masking
        texts = [t for _, t in pending]
        kinds = [k for k, _ in pending]
        cat_examples = []

        if nlp is not None:
            masked_iter = nlp.pipe(texts, batch_size=64)
            for kind, doc_text, original in zip(kinds, masked_iter, texts):
                masked = original
                doc = nlp(original)
                spans = [
                    (e.start_char, e.end_char)
                    for e in doc.ents if e.label_ in NAME_LABELS
                ]
                for start, end in sorted(spans, reverse=True):
                    masked = masked[:start] + NAME_PH + masked[end:]
                paragraphs = masked.split("\n\n")
                cat_examples += chunk_examples(paragraphs, kind, category, args, rng)
        else:
            # no spaCy, skip NER masking, get rid of numbers and build examples.
            for kind, text in zip(kinds, texts):
                paragraphs = text.split("\n\n")
                cat_examples += chunk_examples(paragraphs, kind, category, args, rng)

        if args.wiki_example_limit:
            cat_examples = cat_examples[:args.wiki_example_limit]

        print(f"[{category}] kept {len(cat_examples)} examples from {len(files)} files")
        all_examples.extend(cat_examples)

    return all_examples


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------
def main():

    # parse arguments
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--intros", type=Path, default=DEFAULT_INTROS,
                    help="folder of cleaned intro .txt files")
    ap.add_argument("--wiki-categories", type=Path, default=DEFAULT_WIKI_CATEGORIES,
                    help="root folder of scraped Wikipedia category subfolders")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--no-wiki", action="store_true",
                    help="skip Wikipedia category folders (use only cleaned_intros)")
    ap.add_argument("--min-words", type=int, default=25)
    ap.add_argument("--max-words", type=int, default=220)
    ap.add_argument("--min-placeholders", type=int, default=3)
    ap.add_argument("--intro-limit", type=int, default=0,
                    help="cap cleaned_intros examples (0 = all)")
    ap.add_argument("--wiki-limit", type=int, default=500,
                    help="cap files processed per category (0 = all)")
    ap.add_argument("--wiki-example-limit", type=int, default=0,
                    help="cap examples emitted per category (0 = no cap)")
    ap.add_argument("--wiki-section-chars", type=int, default=4000)
    ap.add_argument("--limit", type=int, default=0,
                    help="cap total examples written (0 = all)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed) #random number generator

    # load spacy model
    nlp = load_spacy()
    if nlp is None:
        print("spaCy not available -- NER masking skipped, building from text only.")

    examples = [] #list of training examples

    # build training examples from cleaned_intros
    if args.intros.exists():
        examples += build_intro_examples(args, rng)
    else:
        print(f"cleaned_intros not found at {args.intros} -- skipping")

    if not args.no_wiki:
        if args.wiki_categories.exists():
            examples += build_category_examples(args, rng, nlp)
        else:
            print(f"Wiki categories folder not found at {args.wiki_categories} -- skipping")

    rng.shuffle(examples)
    if args.limit:
        examples = examples[:args.limit]

    # prints breakdown by category of number of examples per category
    from collections import Counter
    counts = Counter(e["category"] for e in examples)
    print("\nExamples per category:")
    for cat, count in sorted(counts.items()):
        print(f"  {cat}: {count}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for rec in examples:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"\nWrote {len(examples)} total examples to {args.out}")

if __name__ == "__main__":
    main()