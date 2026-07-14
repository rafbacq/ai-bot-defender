from auto_query.src.schema_generator import generate_schema
from auto_query.src.content_extractor_llm import extract_content_llm
from auto_query.src.matcher_v4 import matcher_v4


def compress_attribution_profile(profile):#removing duplicates
    compressed = {}
    for item in profile:
        key = tuple(item["matches"])
        if key not in compressed:
            compressed[key] = item
            compressed[key]["duplicate_count"] = 1
        else:
            compressed[key]["duplicate_count"] += 1

    return sorted(compressed.values(),
                  key=lambda x:
                    (
                        x["hit_count"],
                        x["coverage"],
                        x["duplicate_count"]
                    ),
                  reverse=True
    )


def generate_attribution_summary(attribution_profiles):

    lines = []

    lines.append("=" * 60)
    lines.append("ATTRIBUTION SUMMARY")
    lines.append("=" * 60)

    for model_name, profile in attribution_profiles.items():

        lines.append("")
        lines.append(model_name)
        lines.append("")

        strong = [
            item for item in profile
            if item["hit_count"] >= 2
        ]

        supporting = [
            item for item in profile
            if item["hit_count"] == 1
        ]

        # Strong Attribution

        lines.append("Strong Attribution")
        lines.append("------------------")

        if strong:
            for item in strong:
                lines.append(item["bot"])
                lines.append(f"Coverage: {item['coverage']:.2f}")
                lines.append(f"Recovered: {item['hit_count']} / {item['total_canaries']} canaries")
                lines.append("Matches:")

                for match in item["matches"]:
                    lines.append(f"• {match}")

                lines.append("")

        else:

            lines.append("None")
            lines.append("")

        # Supporting Evidence
        lines.append("Supporting Evidence")
        lines.append("-------------------")

        if supporting:
            for item in supporting:
                lines.append(item["bot"])
                lines.append(f"Recovered: {item['hit_count']} / {item['total_canaries']} canaries")
                lines.append("Matches:")

                for match in item["matches"]:
                    lines.append(f"• {match}")
                lines.append("")

        else:

            lines.append("None")
            lines.append("")
        lines.append("=" * 60)

    return "\n".join(lines)

def evaluate_pipeline(raw_responses,faker_template,database_rows):
    """
    Runs the complete evaluation pipeline.

    Parameters
    ----------
    raw_responses

        Output of api_query_pipeline()
        or manual_query_pipeline().

    faker_template

        Contents of the Faker template.

    database_rows

        Ground truth canary database.

    Returns
    -------
    dict

        {
            "schema": ...,
            "parsed_evidence": ...,
            "attribution_profiles": ...,
            "ranking": ...,
            "summary": ...
        }

    """
    schema = generate_schema(faker_template)#generated once for every session

    parsed_evidence = {}
    for item in raw_responses:
        model_name = item["Model"]
        answer = item["Responses"]
        evidence = extract_content_llm(answer,schema)

        parsed_evidence[model_name] = evidence


    attribution_profiles = {}
    for model_name, evidence in parsed_evidence.items():
        profile = matcher_v4(evidence,database_rows)
        profile = compress_attribution_profile(profile)

        attribution_profiles[model_name] = profile



    ranking = sorted(attribution_profiles.items(),key=lambda x:x[1][0]["coverage"]
            if len(x[1]) > 0

            else 0,

        reverse=True
    )

    ranking_json = []
    for model, profile in ranking:

        if len(profile) == 0:
            ranking_json.append({
                "model":
                    model,
                "coverage":
                    0,
                "hits":
                    0,
                "top_bot":
                    None
            })

            continue

        top_match = profile[0]

        ranking_json.append({
            "model":
                model,

            "coverage":
                top_match["coverage"],

            "hits":
                top_match["hit_count"],

            "top_bot":
                top_match["bot"]

        })

    # Built once, after the ranking loop: on the branch this sat inside the loop
    # (and after its `continue`), leaving `summary` unbound whenever no model had
    # any attribution — a KeyError-on-return in the very case the report matters.
    summary = generate_attribution_summary(
        attribution_profiles
    )
#returning everything that happens after matching
    return {

        "schema":
            schema,

        "parsed_evidence":
            parsed_evidence,

        "attribution_profiles":
            attribution_profiles,

        "ranking":
            ranking_json,

        "summary":
            summary
    }
