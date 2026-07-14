#!/usr/bin/env python3
"""
Scrape English Wikipedia into 20 category folders for honeypot template training.

Output: data/text_generator_dataset/<category>/<article_title>.txt
"""
import os
from datasets import load_dataset

BASE_DIR = "data/text_generator_dataset"
os.makedirs(BASE_DIR, exist_ok=True)

LIMIT_PER_CATEGORY = 30000
MIN_CHARACTER_COUNT = 2000

TARGET_CATEGORIES = {
    "tourist_locations": {
        "must_have": ["tourist attraction", "landmark", "national park", "heritage site", "monument"],
        "any_of": ["visitors", "tourism", "historic site", "designated", "scenic", "UNESCO",
                   "preservation", "attraction", "sightseeing", "listed"]
    },
    "biography": {
        "must_have": ["is an american", "is a british", "is a canadian", "is an australian",
                      "was an american", "was a british"],
        "any_of": ["career", "early life", "personal life", "known for", "born in",
                   "grew up", "debut", "works", "influence"]
    },
    "towns": {
        "must_have": ["city in", "town in", "village in", "census-designated place"],
        "any_of": ["population", "incorporated", "county", "municipality", "suburb",
                   "metropolitan", "located in", "founded"]
    },
    "artists": {
        "must_have": ["painter", "sculptor", "visual artist", "illustrator", "muralist"],
        "any_of": ["exhibition", "gallery", "artwork", "commissioned", "style",
                   "medium", "canvas", "portrait", "abstract", "installation"]
    },
    "movies": {
        "must_have": ["directed by", "film", "released"],
        "any_of": ["starring", "screenplay", "box office", "cinematography",
                   "theatrical", "produced by", "cast", "academy award", "sequel"]
    },
    "books": {
        "must_have": ["novel", "book by", "written by", "published by"],
        "any_of": ["fiction", "author", "plot", "protagonist", "publisher",
                   "bestseller", "chapter", "narrative", "literary", "paperback"]
    },
    "historical_figures": {
        "must_have": ["born", "died"],
        "any_of": ["historian", "statesman", "military leader", "reign", "legacy",
                   "revolutionary", "conqueror", "empire", "ancient", "medieval",
                   "renaissance", "dynasty", "explorer", "philosopher"]
    },
    "animals": {
        "must_have": ["species", "native to", "habitat"],
        "any_of": ["mammal", "bird", "reptile", "amphibian", "insect", "fish",
                   "carnivore", "herbivore", "genus", "predator", "fauna",
                   "endangered", "wildlife", "diet", "ecosystem"]
    },
    "political_figures": {
        "must_have": ["served as", "elected", "appointed"],
        "any_of": ["senator", "governor", "minister", "mayor", "secretary",
                   "parliament", "president", "prime minister", "representative",
                   "congress", "cabinet", "diplomat", "constituency"]
    },
    "universities": {
        "must_have": ["university", "college", "founded"],
        "any_of": ["campus", "enrollment", "faculty", "undergraduate", "research",
                   "degrees", "academic", "institution", "graduate", "tuition",
                   "accredited", "liberal arts", "engineering", "medical school"]
    },
    "companies": {
        "must_have": ["founded", "headquartered"],
        "any_of": ["company", "corporation", "revenue", "industry", "subsidiary",
                   "founder", "publicly traded", "merger", "acquisition",
                   "multinational", "retail", "manufacturer", "services"]
    },
    "languages": {
        "must_have": ["language", "spoken in", "dialect"],
        "any_of": ["speakers", "grammar", "vocabulary", "linguistic", "native speakers",
                   "official language", "writing system", "alphabet", "syntax",
                   "phonology", "language family", "tonal", "creole"]
    },
    "cuisine": {
        "must_have": ["dish", "cuisine", "food"],
        "any_of": ["ingredient", "recipe", "cooking", "traditional", "regional",
                   "prepared", "served", "flavour", "staple", "culinary",
                   "spice", "baked", "fried", "fermented", "originated"]
    },
    "scientists_inventors": {
        "must_have": ["scientist", "inventor", "mathematician", "physicist",
                      "chemist", "biologist", "engineer"],
        "any_of": ["discovery", "research", "patent", "theory", "experiment",
                   "laboratory", "Nobel", "published", "breakthrough",
                   "formula", "equation", "contribution", "pioneered"]
    },
    "clothing": {
        "must_have": ["garment", "clothing", "fashion", "textile", "worn"],
        "any_of": ["fabric", "style", "design", "traditional dress", "costume",
                   "material", "woven", "tailored", "ceremonial", "cultural",
                   "embroidered", "silk", "cotton", "wool", "linen"]
    },
    "medicine": {
        "must_have": ["disease", "condition", "disorder", "syndrome", "treatment"],
        "any_of": ["symptoms", "diagnosis", "therapy", "patients", "clinical",
                   "medical", "chronic", "infection", "surgery", "medication",
                   "prevalence", "causes", "prognosis", "physician"]
    },
    "sports_teams": {
        "must_have": ["football club", "basketball team", "baseball team",
                      "sports team", "athletic club", "soccer club"],
        "any_of": ["founded", "league", "season", "championship", "stadium",
                   "roster", "coach", "rivalry", "division", "playoffs",
                   "title", "franchise", "transfer", "squad"]
    },
    "folklore": {
        "must_have": ["folklore", "legend", "folktale", "myth", "fairy tale"],
        "any_of": ["tradition", "oral tradition", "storytelling", "mythical",
                   "creature", "supernatural", "ritual", "deity", "spirit",
                   "hero", "trickster", "origin story", "passed down", "cultural"]
    },
    "video_games": {
        "must_have": ["video game", "developed by", "game developer"],
        "any_of": ["gameplay", "multiplayer", "single-player", "playstation",
                   "xbox", "nintendo", "pc", "rpg", "console", "graphics",
                   "franchise", "publisher", "mechanics", "open world", "platformer"]
    },
    "religion": {
        "must_have": ["religion", "religious", "faith", "belief", "worship"],
        "any_of": ["god", "deity", "prayer", "scripture", "church", "temple",
                   "mosque", "ritual", "clergy", "theology", "sacred",
                   "denomination", "doctrine", "followers", "spiritual"]
    },
}

for folder in TARGET_CATEGORIES.keys():
    os.makedirs(os.path.join(BASE_DIR, folder), exist_ok=True)

print("Initialising English Wikipedia streaming pipeline...")
dataset = load_dataset("wikimedia/wikipedia", "20231101.en", split="train", streaming=True)

counts = {k: 0 for k in TARGET_CATEGORIES.keys()}
total_processed = 0

print("Scanning articles...\n")

for article in dataset:
    total_processed += 1
    text  = article['text']
    title = article['title']

    if len(text) < MIN_CHARACTER_COUNT:
        continue

    intro_text = text[:1000].lower()

    for category, matrix in TARGET_CATEGORIES.items():
        if counts[category] >= LIMIT_PER_CATEGORY:
            continue

        has_must = any(word in intro_text for word in matrix["must_have"])
        has_any  = any(word in intro_text for word in matrix["any_of"])

        if has_must and has_any:
            safe_title = (title.replace(" ", "_")
                   .replace("/", "-")
                   .replace(":", "")
                   .replace("\\", "")
                   .replace('"', "")
                   .replace("?", "")
                   .replace("*", ""))
            file_path = os.path.join(BASE_DIR, category, f"{safe_title}.txt")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(text)
            counts[category] += 1

            if sum(counts.values()) % 250 == 0:
                print(f"--- PROGRESS (scanned: {total_processed}) ---")
                for cat, count in counts.items():
                    bar = "█" * (count * 20 // LIMIT_PER_CATEGORY)
                    print(f"  {cat:<25} {count:>6}/{LIMIT_PER_CATEGORY}  {bar}")
            break

    if all(count >= LIMIT_PER_CATEGORY for count in counts.values()):
        print("\nAll category targets reached!")
        break

print("\nFinal results:")
for cat, count in counts.items():
    print(f"  {cat:<25} {count:>6}")
print(f"\nTotal articles scanned: {total_processed}")