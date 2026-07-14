def manual_query_pipeline(raw_responses):
    """
    Validates and normalizes manually collected responses for matching.
    Parameters
    ----------
    raw_responses
        [
            {
                "Model": "...",
                "Responses": "..."
            }
        ]

    Returns
    -------
    list
        Normalized responses.
    """

    normalized = []

    for item in raw_responses:

        model = str(item.get("Model", "")).strip()

        response_text = str(item.get("Responses", "")).strip()# odd spaces -- does not affect integrity of canary tokens

        normalized.append({
            "Model":
                model,
            "Responses":
                response_text
        })

    return normalized
