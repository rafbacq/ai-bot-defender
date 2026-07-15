"""Bridge between the web app and the LLM-detection engine.

Detection now runs on the vendored ``auto_query`` framework (LiteLLM target
querying + internal GPT-4.1 processing + the RapidFuzz attribution matcher)
via ``auto_query_adapter``; the ``mock/*`` model ids keep the whole flow
demonstrable offline. Run history/stats still read from ``querying.store``
(the adapter persists a legacy-superset record there), and the ``querying``
package itself stays in place for the provenance/membership layer.
"""

import csv
import io
import json
import os

from auto_query.config.models import MODELS as AQ_MODELS
from auto_query.config.models import provider_of, provider_ready
from querying.store import list_runs, load_run, runs_summary

from . import auto_query_adapter
# Re-exported: provenance_service (and any older caller) imports it from here.
from .auto_query_adapter import PROXY_HTTP_ENTRY  # noqa: F401


def available_models():
    """Target model ids from the auto_query registry (mock entries first)."""
    return list(dict.fromkeys(AQ_MODELS.values()))


def model_registry():
    """Display name -> model id pairs, for UIs that want friendly labels."""
    return [{"label": label, "id": mid, "ready": provider_ready(mid)}
            for label, mid in AQ_MODELS.items()]


def is_mock(model_id):
    """True for the offline simulator ids (never sent to a provider)."""
    return str(model_id).startswith("mock/")


def model_ready(model_id):
    """True when the model can be queried right now — mock ids always, live
    ids only when one of their provider's API keys is present in the env."""
    return is_mock(model_id) or bool(provider_ready(model_id))


def model_labels():
    """Model id -> friendly display name, from the auto_query registry."""
    return {mid: label for label, mid in AQ_MODELS.items()}


def resolve_model_choice(key_mode, models):
    """Apply the launcher's querying-mode toggle to the submitted model list.

    ``key_mode == "offline"`` never touches a provider: any submitted live ids
    are dropped and the run falls back to the mock simulators when nothing
    valid remains — so the offline path always has something to demo with.
    ``key_mode == "api"`` keeps mock ids (a useful positive control) and live
    ids whose provider key is configured; a choice that leaves nothing to
    query is an error rather than a silent mock fallback, because the user
    explicitly asked for live querying.

    Returns ``(models, error)`` — exactly one of the two is meaningful.
    """
    submitted = list(dict.fromkeys(m for m in (models or []) if m))
    mocks = [m for m in available_models() if is_mock(m)]

    if key_mode != "api":
        chosen = [m for m in submitted if is_mock(m)]
        return (chosen or mocks), None

    if not submitted:
        return [], ("Select at least one model to query — or switch to the "
                    "offline demo, which needs no API keys.")
    chosen = [m for m in submitted if model_ready(m)]
    if not chosen:
        return [], ("None of the selected models has a provider API key "
                    "configured. Add a key under Provider API keys, or switch "
                    "to the offline demo.")
    return chosen, None


def provider_status():
    """Report which parts of the detection engine are usable right now."""
    internal = bool(os.environ.get("OPENAI_API_KEY_INTERNAL"))
    ready = {}
    for mid in available_models():
        provider = provider_of(mid)
        ready.setdefault(provider, bool(provider_ready(mid)))
    return {
        "mock": True,
        "engine": "auto_query",
        # Attribute/schema/extraction run on the internal GPT-4.1 client when
        # this key is set, else on the deterministic offline heuristics.
        "openai_internal": internal,
        "extractor_provider": "gpt-4.1 internal" if internal else "heuristic",
        # Per-LiteLLM-provider readiness for the registered target models.
        "providers_ready": ready,
        # Legacy keys the forensics page badges read.
        "anthropic": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "openai_extractor": internal,
        "target_provider": "litellm",
    }


def start_local_run(site_id, models, max_questions=3, seed=None):
    """Query a locally-deployed honeypot site through the reverse proxy.

    ``max_questions``/``seed`` are accepted for form compatibility but the
    auto_query engine composes a single deterministic retrieval prompt, so
    they are not used.
    """
    return auto_query_adapter.run_detection(site_id=site_id, models=models)


def start_custom_run(url, models, csv_path=None, max_questions=3, seed=None):
    """Query an arbitrary URL, matching against a ground-truth CSV."""
    return auto_query_adapter.run_detection(url=url, models=models, csv_path=csv_path)


def generate_prompt(site_id=None, url=None, cancel_check=None):
    """Build the retrieval prompt for the manual (copy/paste) workflow."""
    return auto_query_adapter.generate_prompt(
        site_id=site_id or None, url=url or None, cancel_check=cancel_check
    )


def start_manual_run(records, site_id=None, url=None):
    """Evaluate manually collected responses against a site's canary rows."""
    return auto_query_adapter.run_manual_evaluation(
        site_id=site_id or None, url=url or None, records=records
    )


# --- Downloadable run artifacts ----------------------------------------------
# The run page shows only the final attribution results; the intermediate
# pipeline stages (generated prompt, raw model responses, content extraction)
# are not rendered inline but stay inspectable as downloads. Both detection and
# manual runs share the same record shape, so every artifact works for both
# (a manual run simply has no generated prompt to offer).

RUN_ARTIFACTS = ("results", "results.csv", "prompt", "raw_responses", "extraction")


def _json_dumps(payload):
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n"


def _artifact_prompt(run):
    parts = []
    if run.get("role_prompt"):
        parts.append(f"ROLE PROMPT\n{run['role_prompt']}")
    questions = [q for q in (run.get("questions") or []) if q]
    if questions:
        label = "RETRIEVAL PROMPT" if len(questions) == 1 else "RETRIEVAL PROMPTS"
        parts.append(label + "\n" + "\n\n".join(questions))
    if not parts:
        return None
    return "\n\n".join(parts) + "\n"


def _artifact_raw_responses(run):
    items = []
    for r in run.get("results") or []:
        item = {"Model": r.get("model")}
        if r.get("error"):
            item.update(Error=r["error"], ErrorKind=r.get("error_kind"),
                        ErrorDetail=r.get("error_detail"))
        else:
            item["Responses"] = r.get("answer", "")
        items.append(item)
    return _json_dumps(items) if items else None


def _artifact_extraction(run):
    results = run.get("results") or []
    if not results:
        return None
    return _json_dumps({
        "schema": run.get("schema"),
        "extracted_evidence": {
            r["model"]: r.get("extracted") for r in results if not r.get("error")
        },
    })


def _artifact_results_csv(run):
    if not run.get("results"):
        return None
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["model", "status", "verdict", "coverage", "canaries_hit",
                     "total_canaries", "top_crawler_user_agent",
                     "matched_canaries", "error"])
    for r in run.get("results") or []:
        best = r.get("best_match") or {}
        if r.get("error"):
            writer.writerow([r.get("model"), "error", "", "", "", "", "", "",
                             r["error"]])
        else:
            writer.writerow([
                r.get("model"), "ok", "leak" if r.get("leaked") else "clean",
                best.get("coverage", best.get("jaccard_score", 0)) or 0,
                best.get("hit_count", ""), best.get("total_canaries", ""),
                best.get("bot", ""), "; ".join(best.get("matches") or []), "",
            ])
    return buf.getvalue()


def run_artifact(run, name):
    """Build one downloadable artifact for a run record.

    Returns ``(filename, media_type, content)`` or ``None`` when the run has
    nothing for that artifact (e.g. the prompt of a manual run, or an unknown
    name). ``results`` is the full persisted record — the final results — and
    ``results.csv`` its per-model summary; the other three are the hidden
    intermediate stages.
    """
    run_id = run.get("run_id") or "run"
    if name == "results":
        return (f"{run_id}-results.json", "application/json", _json_dumps(run))
    if name == "results.csv":
        content = _artifact_results_csv(run)
        return (f"{run_id}-results.csv", "text/csv", content) if content else None
    if name == "prompt":
        content = _artifact_prompt(run)
        return (f"{run_id}-prompt.txt", "text/plain; charset=utf-8",
                content) if content else None
    if name == "raw_responses":
        content = _artifact_raw_responses(run)
        return (f"{run_id}-raw-responses.json", "application/json",
                content) if content else None
    if name == "extraction":
        content = _artifact_extraction(run)
        return (f"{run_id}-extraction.json", "application/json",
                content) if content else None
    return None


__all__ = [
    "available_models",
    "model_registry",
    "model_labels",
    "model_ready",
    "is_mock",
    "resolve_model_choice",
    "run_artifact",
    "RUN_ARTIFACTS",
    "provider_status",
    "start_local_run",
    "start_custom_run",
    "generate_prompt",
    "start_manual_run",
    "list_runs",
    "load_run",
    "runs_summary",
]
