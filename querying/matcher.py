"""Compare an extractor result against one ground-truth row of canary tokens.

The score is the exact-set Jaccard similarity between the extractor's evidence
strings and the row's ``var1``..``var10`` canary tokens (case-insensitive,
whitespace-trimmed). Only list-valued extractor fields contribute, and only
``var1``..``var10`` from the row.
"""

VAR_COLUMNS = [f"var{i}" for i in range(1, 11)]


def matcher(extractor_output, row_dict):
    """Public coordinator: return the best-match record for one row."""
    evidence = flatten_extractor(extractor_output)
    return compare_row(evidence, row_dict)


def flatten_extractor(extractor_output):
    """Collect lowercase, trimmed items from all list-valued categories into a set."""
    evidence_strings = set()
    for items in extractor_output.values():
        if not isinstance(items, list):
            continue
        for item in items:
            cleaned = str(item).strip().lower()
            if cleaned:
                evidence_strings.add(cleaned)
    return evidence_strings


def flatten_row(db_row):
    """Collect lowercase, trimmed canary values (var1..var10) from a row into a set."""
    row_strings = set()
    for column in VAR_COLUMNS:
        value = db_row.get(column)
        if value and isinstance(value, str):
            cleaned = value.strip().lower()
            if cleaned and cleaned != "null":
                row_strings.add(cleaned)
    return row_strings


def compare_row(evidence_strings, db_row):
    """Jaccard similarity (intersection / union) of evidence vs. row canaries."""
    row_set = flatten_row(db_row)
    intersection = evidence_strings & row_set
    union = evidence_strings | row_set
    jaccard_score = len(intersection) / len(union) if union else 0.0
    return {
        "bot": db_row.get("user_agent", "Unknown Bot"),
        "matches": sorted(intersection),
        "jaccard_score": round(jaccard_score, 4),
    }
