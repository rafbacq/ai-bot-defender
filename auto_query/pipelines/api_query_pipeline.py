from auto_query.src.llm_client_litellm import query_model


def api_query_pipeline(prompt_artifacts, models, context=None,
                       on_query=None, on_result=None, cancel_check=None):
    """
    Queries every configured LLM using the generated prompts.

    Parameters
    ----------
    prompt_artifacts : dict
        Output of generate_prompt_pipeline().

    models : dict
        Dictionary mapping display names to LiteLLM model names.

    context : dict, optional
        Extra context for the offline ``mock/*`` simulators
        (``subject`` + ``leak_candidates``). Ignored by real models.

    on_query, on_result : callable, optional
        Integration addition — live-progress hooks for the dashboard.
        ``on_query(model_name)`` fires just before a model is queried;
        ``on_result(model_name, item)`` fires with the finished raw-response
        item (including any classified error). Hook failures never break the
        query loop.

    Returns
    -------
    list

        [
            {
                "Model": "...",
                "Responses": "..."
            },
            ...
        ]

        A failed model additionally carries "Error" / "ErrorKind" /
        "ErrorDetail" keys (integration addition — the dashboard surfaces
        per-model errors with a classified, human-readable reason).
    """

    role_prompt = prompt_artifacts["role_prompt"]
    prompt = prompt_artifacts["prompt"]

    raw_responses = []
    for model_name, model in models.items():
        if cancel_check is not None:
            cancel_check()

        print()
        print(f"[QUERYING] {model_name}")

        if on_query:
            try:
                on_query(model_name)
            except Exception:
                pass

        result = query_model(model, role_prompt, prompt, context=context)
        if cancel_check is not None:
            cancel_check()

        item = {
            "Model":
                model_name,
            "Responses":
                result.get("answer","")
        }
        if result.get("error"):
            item["Error"] = result["error"]
            item["ErrorKind"] = result.get("error_kind", "provider_error")
            item["ErrorDetail"] = result.get("error_detail", "")
        raw_responses.append(item)

        if on_result:
            try:
                on_result(model_name, item)
            except Exception:
                pass

    return raw_responses
