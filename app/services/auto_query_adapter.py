"""Dashboard adapter: drive the ``auto_query`` engine from the web app.

This is the host-application analogue of the auto-query-integrate branch's
``adapters/local_adapter.py``: it supplies the engine with the HTML, the faker
template text, and the ground-truth rows (the branch README's "supplied
directly by the host application" contract) and turns the evaluation output
into the run-record shape the rest of the product already binds to.

Existing seams deliberately reused (do not reimplement):

- ``querying.ground_truth`` loads canary rows from a deployed site's DB or a
  CSV — exactly the ``{var1..var10, user_agent}`` rows ``matcher_v4`` expects.
- ``querying.store.save_run`` persists the run under ``querying/runs/`` so
  history, landing-page stats, and the run-detail page keep working unchanged.
- ``app.services.sites.merged_site_config`` resolves a site's scraper version
  to its template/varList paths and its proxy hostname.

The persisted run record is a **superset** of the legacy shape: every key the
UI/stats/testsuite already read (``results[].best_match.{bot,matches,
jaccard_score}``, ``results[].leaked``, ``summary.{models_tested,matches_found,
best_score,ground_truth_rows,threshold}``) is preserved, with the engine's
richer attribution data (per-crawler ``attribution_profile``, ``ranking``,
``attribution_summary``, the extraction ``schema``) added alongside.

Detection semantics: a model counts as a leak when its top attribution reaches
``querying.config.HIGH_RISK_THRESHOLD`` coverage **or** recovers >= 2 canaries
from one crawler row (the engine's "strong attribution" bar).
"""

import os
import secrets
import sys
from datetime import datetime, timezone

import requests

from auto_query.config.models import refresh_env
from auto_query.pipelines.api_query_pipeline import api_query_pipeline
from auto_query.pipelines.evaluation_pipeline import evaluate_pipeline
from auto_query.pipelines.manual_query_pipeline import manual_query_pipeline
from auto_query.pipelines.prompt_pipeline import generate_prompt_pipeline
from querying import config as q_config
from querying.ground_truth import (
    GroundTruthError,
    load_csv_rows,
    load_site_rows,
    pick_leak_candidates,
)
from querying.store import save_run

from .. import config
from .sites import merged_site_config

# Where the app reaches the reverse proxy (host loopback by default; set to the
# nginx container name when the app shares proxy_net).
PROXY_HTTP_ENTRY = os.environ.get("PROXY_HTTP_ENTRY", "http://127.0.0.1")

PROBE_USER_AGENT = "AIBotDefender-Probe/1.0"

# hit_count at which a per-crawler attribution counts as "strong" (the
# engine's own bar, used by the attribution summary and the leak verdict).
STRONG_HIT_COUNT = 2


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_run_id():
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{secrets.token_hex(2)}"


def _emit(progress, event, data=None):
    """Fire a live-progress event; a broken listener never breaks the run."""
    if progress is None:
        return
    try:
        progress(event, data or {})
    except Exception:
        pass


def _fetch_html(url, host_header=None, verify=True, timeout=10):
    """Best-effort page fetch (also assigns our probe a canary set on the
    honeypot, which ``pick_leak_candidates`` then prefers). ``None`` on failure."""
    headers = {"User-Agent": PROBE_USER_AGENT}
    if host_header:
        headers["Host"] = host_header
    try:
        response = requests.get(url, headers=headers, timeout=timeout, verify=verify)
        response.raise_for_status()
        return response.text
    except requests.RequestException as exc:
        print(f"auto_query_adapter: fetch of {url} failed: {exc}", file=sys.stderr)
        return None


class _Inputs:
    """Everything the engine needs for one investigation, host-resolved."""

    def __init__(self, *, template_html, rendered_html, faker_template, rows,
                 source, target_url=None, host_header=None, site_id=None):
        self.template_html = template_html
        self.rendered_html = rendered_html
        self.faker_template = faker_template
        self.rows = rows
        self.source = source
        self.target_url = target_url
        self.host_header = host_header
        self.site_id = site_id


def _site_inputs(site_id, scrape=True, need_rows=True):
    """Resolve a local honeypot site: template + varList + DB rows (+ scrape)."""
    site = merged_site_config(site_id)
    version = site["scraper_version"]
    template_path = config.TEMPLATES_DIR / f"scraper{version}.html"
    varlist_path = config.WEBSITE_DIR / "varLists" / f"scraper{version}.txt"
    if not template_path.exists():
        raise GroundTruthError(
            f"Site '{site_id}' uses scraper{version} but {template_path} does not "
            "exist — deploy the site (the playbook scaffolds the flavor) first."
        )
    if not varlist_path.exists():
        raise GroundTruthError(
            f"Site '{site_id}' uses scraper{version} but its canary varList "
            f"{varlist_path} does not exist — run the playbook to render it."
        )

    target_url = f"{PROXY_HTTP_ENTRY}/"
    host_header = site["local_hostname"]
    rendered = _fetch_html(target_url, host_header, verify=False) if scrape else None

    rows = []
    if need_rows:
        rows = load_site_rows(
            str(config.PROJECT_ROOT), site_id, site["db_name"], site["database"]["user"]
        )
    return _Inputs(
        template_html=template_path.read_text(encoding="utf-8"),
        rendered_html=rendered,
        faker_template=varlist_path.read_text(encoding="utf-8"),
        rows=rows,
        source=f"db:{site_id} ({len(rows)} rows)",
        target_url=target_url,
        host_header=host_header,
        site_id=site_id,
    )


def _custom_inputs(url, csv_path=None):
    """Resolve an arbitrary URL: fetched page + CSV ground truth (no template)."""
    html = _fetch_html(url)
    if not html:
        raise GroundTruthError(f"Could not fetch the target page at {url}.")
    csv_file = csv_path or q_config.SAMPLE_GROUND_TRUTH
    rows = load_csv_rows(csv_file)
    return _Inputs(
        template_html=html,       # no {{ varN }} template exists for a foreign page
        rendered_html=html,
        faker_template="",
        rows=rows,
        source=f"csv:{csv_file} ({len(rows)} rows)",
        target_url=url,
    )


def _resolve_inputs(site_id=None, url=None, csv_path=None, scrape=True,
                    need_rows=True):
    if site_id:
        return _site_inputs(site_id, scrape=scrape, need_rows=need_rows)
    if url:
        return _custom_inputs(url, csv_path=csv_path)
    raise GroundTruthError("Neither a site nor a URL was given.")


def _new_run(kind, models, run_id=None):
    return {
        "run_id": run_id or _new_run_id(),
        "started_at": _now(),
        "finished_at": None,
        "status": "running",
        "kind": kind,                 # "detection" | "manual"
        "engine": "auto_query",
        "site_id": None,
        "target_url": None,
        "host_header": None,
        "models": list(models),
        "subject": None,
        "ground_truth_source": None,
        "role_prompt": None,
        "questions": [],
        "results": [],
        "summary": {},
        "error": None,
    }


def _map_results(run, raw_responses, evaluation, n_rows):
    """Fold the engine's evaluation output into the legacy-superset run record."""
    threshold = q_config.HIGH_RISK_THRESHOLD
    matches_found = 0
    best_overall = 0.0

    for item in raw_responses:
        model = item["Model"]
        answer = item.get("Responses", "")
        if item.get("Error") or not answer:
            run["results"].append({
                "model": model,
                "error": item.get("Error") or "No answer returned.",
                # Classified reason (auth / quota / rate_limit / ...) + the raw
                # provider message, so the UI can say what to do about it.
                "error_kind": item.get("ErrorKind"),
                "error_detail": item.get("ErrorDetail"),
            })
            continue

        profile = evaluation.get("attribution_profiles", {}).get(model, [])
        top = profile[0] if profile else None
        best_match = None
        leaked = False
        if top:
            # Legacy contract: best_match.{bot, matches, jaccard_score}. The
            # engine's score is coverage (matched / row canaries) — same 0..1
            # scale and meaning-compatible with the old exact-set Jaccard.
            best_match = {
                "bot": top["bot"],
                "matches": top["matches"],
                "jaccard_score": top["coverage"],
                "hit_count": top["hit_count"],
                "total_canaries": top["total_canaries"],
                "coverage": top["coverage"],
            }
            leaked = top["coverage"] >= threshold or top["hit_count"] >= STRONG_HIT_COUNT
            best_overall = max(best_overall, top["coverage"])
        if leaked:
            matches_found += 1

        run["results"].append({
            "model": model,
            "answer": answer,
            "extracted": evaluation["parsed_evidence"].get(model, []),
            "best_match": best_match,
            "leaked": leaked,
            # New: the full per-crawler attribution profile (every row with
            # evidence, deduped + sorted), not just the single best row.
            "attribution_profile": profile,
        })

    run["summary"] = {
        "models_tested": len(run["models"]),
        "matches_found": matches_found,
        "best_score": round(best_overall, 4),
        "ground_truth_rows": n_rows,
        "threshold": threshold,
        # New: the engine's cross-model ranking + human-readable summary.
        "ranking": evaluation["ranking"],
        "attribution_summary": evaluation["summary"],
    }
    run["schema"] = evaluation["schema"]


def run_detection(*, site_id=None, url=None, models, csv_path=None, persist=True,
                  run_id=None, progress=None):
    """Full automated investigation: prompt -> API query -> evaluation.

    ``models`` is a list of LiteLLM model ids (``mock/*`` ids run offline).
    ``run_id`` lets the background run manager pre-assign the id it redirects
    to; ``progress(event, data)`` receives live events (``stage``, ``prompt``,
    ``model_start``, ``model_done``, ``finished``) for the run page. Both are
    optional — a direct synchronous call behaves exactly as before.
    Returns the persisted run record.
    """
    run = _new_run("detection", models, run_id=run_id)
    run["site_id"] = site_id

    try:
        refresh_env()  # pick up keys saved to .env since the process started
        _emit(progress, "stage", {"stage": "resolving",
                                  "label": "Resolving the target site and ground truth…"})
        inputs = _resolve_inputs(site_id=site_id, url=url, csv_path=csv_path)
        run["target_url"] = inputs.target_url
        run["host_header"] = inputs.host_header
        run["ground_truth_source"] = inputs.source

        _emit(progress, "stage", {"stage": "prompt",
                                  "label": "Generating the retrieval prompt…"})
        artifacts = generate_prompt_pipeline(
            inputs.template_html, inputs.faker_template,
            rendered_html=inputs.rendered_html,
        )
        run["subject"] = artifacts["website_record"].get("main_idea")
        run["role_prompt"] = artifacts["role_prompt"]
        # The engine composes ONE retrieval prompt (attributes folded in),
        # not a sampled question list — stored in the same legacy slot.
        run["questions"] = [artifacts["prompt"]]
        _emit(progress, "prompt", {"subject": run["subject"],
                                   "role_prompt": run["role_prompt"],
                                   "prompt": artifacts["prompt"]})
        if persist:
            # Checkpoint so a page reload mid-run (or an interrupted run)
            # still shows the subject + the prompt that was used.
            save_run(run)

        # Leak context for the offline mock simulators (real models ignore it).
        context = {
            "subject": run["subject"],
            "leak_candidates": pick_leak_candidates(
                inputs.rows, prefer_user_agent=PROBE_USER_AGENT
            ),
        }
        _emit(progress, "stage", {"stage": "querying",
                                  "label": "Querying the target models…"})
        raw_responses = api_query_pipeline(
            artifacts, {mid: mid for mid in models}, context=context,
            on_query=lambda model: _emit(progress, "model_start", {"model": model}),
            on_result=lambda model, item: _emit(progress, "model_done", {
                "model": model,
                "ok": "Error" not in item,
                "answer": item.get("Responses", ""),
                "error": item.get("Error"),
                "error_kind": item.get("ErrorKind"),
                "error_detail": item.get("ErrorDetail"),
            }),
        )

        _emit(progress, "stage", {"stage": "evaluating",
                                  "label": "Extracting evidence and attributing crawlers…"})
        evaluation = evaluate_pipeline(
            raw_responses, inputs.faker_template, inputs.rows
        )
        _map_results(run, raw_responses, evaluation, len(inputs.rows))
        run["status"] = "completed"

    except GroundTruthError as exc:
        run["status"] = "failed"
        run["error"] = f"Ground truth unavailable: {exc}"
    except Exception as exc:  # surface the failure in the persisted record
        run["status"] = "failed"
        run["error"] = f"{type(exc).__name__}: {exc}"

    run["finished_at"] = _now()
    if persist:
        save_run(run)
    _emit(progress, "finished", {"status": run["status"], "error": run["error"]})
    return run


def run_manual_evaluation(*, site_id=None, url=None, csv_path=None, records,
                          persist=True, run_id=None, progress=None):
    """Evaluate manually collected responses exactly like API-acquired ones.

    ``records`` is the canonical ``[{"Model": ..., "Responses": ...}]`` list
    (see ``auto_query.manual_io`` for spreadsheet parsing). Both acquisition
    methods converge on the same representation, so the evaluation — and the
    persisted run shape — is identical to a detection run. ``run_id`` /
    ``progress`` work as in ``run_detection`` (no querying stage here: the
    responses already exist, so models jump straight to "collected").
    """
    normalized = manual_query_pipeline(records)
    run = _new_run("manual", [item["Model"] for item in normalized], run_id=run_id)
    run["site_id"] = site_id

    try:
        refresh_env()
        _emit(progress, "stage", {"stage": "resolving",
                                  "label": "Resolving the target site and ground truth…"})
        inputs = _resolve_inputs(site_id=site_id, url=url, csv_path=csv_path)
        run["target_url"] = inputs.target_url
        run["host_header"] = inputs.host_header
        run["ground_truth_source"] = inputs.source

        # Best-effort subject/prompt reconstruction, for the run-detail header.
        try:
            artifacts = generate_prompt_pipeline(
                inputs.template_html, inputs.faker_template,
                rendered_html=inputs.rendered_html,
            )
            run["subject"] = artifacts["website_record"].get("main_idea")
            run["role_prompt"] = artifacts["role_prompt"]
        except Exception:
            pass

        # The responses were collected by hand — report them as already in.
        for item in normalized:
            _emit(progress, "model_done", {
                "model": item["Model"], "ok": True,
                "answer": item.get("Responses", ""),
            })

        _emit(progress, "stage", {"stage": "evaluating",
                                  "label": "Extracting evidence and attributing crawlers…"})
        evaluation = evaluate_pipeline(
            normalized, inputs.faker_template, inputs.rows
        )
        _map_results(run, normalized, evaluation, len(inputs.rows))
        run["status"] = "completed"

    except GroundTruthError as exc:
        run["status"] = "failed"
        run["error"] = f"Ground truth unavailable: {exc}"
    except Exception as exc:
        run["status"] = "failed"
        run["error"] = f"{type(exc).__name__}: {exc}"

    run["finished_at"] = _now()
    if persist:
        save_run(run)
    _emit(progress, "finished", {"status": run["status"], "error": run["error"]})
    return run


def generate_prompt(*, site_id=None, url=None):
    """Prompt pipeline only — for the manual workflow's copy/download step.

    Returns ``{"subject", "role_prompt", "prompt", "attributes"}``. Raises on
    failure (no run record is written for a prompt preview).
    """
    inputs = _resolve_inputs(site_id=site_id, url=url, need_rows=False)
    artifacts = generate_prompt_pipeline(
        inputs.template_html, inputs.faker_template,
        rendered_html=inputs.rendered_html,
    )
    return {
        "subject": artifacts["website_record"].get("main_idea"),
        "role_prompt": artifacts["role_prompt"],
        "prompt": artifacts["prompt"],
        "attributes": artifacts["attributes"],
    }
