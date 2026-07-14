from rapidfuzz import fuzz


def flatten_row(db_row):
    """
    Standardizes a CSV row into a set
    of lowercase canary values.
    """

    row_strings = set()

    allowed_columns = [f"var{i}" for i in range(1, 11)]
    for column in allowed_columns:
        value = db_row.get(column)
        if value is None:
            continue

        cleaned = str(value).strip().lower() #standardized for matching

        if cleaned and cleaned != "nan":

            row_strings.add(cleaned)

    return row_strings


def compare_row_v4(evidence_strings,db_row,fuzzy_threshold=95):
    """
    Compares recovered evidence against a single CSV row.
    """

    row_set = flatten_row(db_row)  # standardizing row in database

    normalized_evidence = {
        str(x).strip().lower()
        for x in evidence_strings
        if x is not None
    }

    matches = []

    for canary in row_set:
        for recovered in normalized_evidence:

            # exact match
            if recovered == canary:
                matches.append(canary)
                break

            # containment match
            if canary in recovered:
                matches.append(canary)
                break

            # fuzzy match
            similarity = fuzz.ratio(
                recovered,
                canary
            )

            if similarity >= fuzzy_threshold:
                matches.append(canary)
                break

    matches = sorted(list(set(matches)))

    hit_count = len(matches)

    total_canaries = len(row_set)

    coverage = (

        hit_count /

        total_canaries

        if total_canaries > 0

        else 0.0

    )

    # only assign a bot if at least one canary matched
    bot = None

    if hit_count > 0:

        bot = db_row.get(
            "user_agent",
            "Unknown Bot"
        )

    return {

        "bot":
            bot,

        "matches":
            matches,

        "hit_count":
            hit_count,

        "total_canaries":
            total_canaries,

        "coverage":
            round(
                coverage,
                4
            )

    }

def matcher_v4(evidence_strings,rows,fuzzy_threshold=95,min_hits=1):
    """
    Loops through all rows in the CSV.

    Instead of returning only the
    best matching row, returns an
    attribution profile containing
    every row with evidence.

    Results are sorted by hit count.
    """

    attribution_profile = []

    for row in rows:

        result = compare_row_v4(evidence_strings,row,fuzzy_threshold)

        if result["hit_count"] >= min_hits:

            attribution_profile.append(result)

    attribution_profile.sort(key=lambda x: (x["hit_count"],x["coverage"]),reverse=True)

    return attribution_profile