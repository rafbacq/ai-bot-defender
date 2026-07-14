"""Orchestrate one end-to-end LLM query run.

Flow:

    scrape page  ->  generate probes  ->  query target LLMs
                                              |
                              extract structured fields per answer
                                              |
                          match against ground-truth canary rows
                                              |
                                   persist a run record

The run record is returned and (by default) saved under ``querying/runs/`` so
the web app can show history and aggregate statistics.
"""

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import config
from .extractor import extract_info
from .ground_truth import (
    GroundTruthError,
    load_csv_rows,
    load_site_rows,
    pick_leak_candidates,
)
from .llm_client import llm_responses
from .matcher import matcher
from .parser import parser
from .prompt_generator import generate_probes
from .store import save_run

PROBE_USER_AGENT = "AIBotDefender-Probe/1.0"


@dataclass
class QueryRequest:
    """Inputs for a single query run."""

    target_url: str                       # URL to scrape (proxy URL for local sites)
    models: list                          # target model identifiers to test
    host_header: str = None               # Host override for local proxy routing
    verify_tls: bool = True               # accept self-signed proxy certs when False
    site_id: str = None                   # set for local-honeypot runs
    # Ground truth: a CSV path, or (for live sites) DB connection details.
    csv_path: str = None
    db_name: str = None
    db_user: str = None
    project_root: str = None
    max_questions: int = config.MAX_PROBES
    seed: int = None
    persist: bool = True
    extra: dict = field(default_factory=dict)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_run_id():
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{secrets.token_hex(2)}"


def _load_ground_truth(req):
    """Return (rows, source_label). Falls back to the bundled sample CSV."""
    if req.site_id and req.db_name and req.db_user:
        rows = load_site_rows(
            req.project_root or config.PROJECT_ROOT,
            req.site_id,
            req.db_name,
            req.db_user,
        )
        return rows, f"db:{req.site_id} ({len(rows)} rows)"
    csv_path = req.csv_path or config.SAMPLE_GROUND_TRUTH
    rows = load_csv_rows(csv_path)
    return rows, f"csv:{csv_path} ({len(rows)} rows)"


def run_query(req: QueryRequest):
    """Run the full pipeline for ``req`` and return the run record."""
    run = {
        "run_id": _new_run_id(),
        "started_at": _now(),
        "finished_at": None,
        "status": "running",
        "site_id": req.site_id,
        "target_url": req.target_url,
        "host_header": req.host_header,
        "models": req.models,
        "subject": None,
        "ground_truth_source": None,
        "role_prompt": None,
        "questions": [],
        "results": [],
        "summary": {},
        "error": None,
    }

    try:
        # 1. Scrape the page (assigns + stores a canary set on the honeypot).
        record = parser(req.target_url, host_header=req.host_header, verify=req.verify_tls)
        if not record or not record.get("main_idea"):
            raise RuntimeError(
                "Could not scrape a subject from the target page. "
                "Is the proxy up and the site deployed?"
            )
        subject = record["main_idea"]
        run["subject"] = subject

        # 2. Generate role prompt + retrieval questions.
        role_prompt, questions = generate_probes(record, req.max_questions, seed=req.seed)
        run["role_prompt"] = role_prompt
        run["questions"] = questions

        # 3. Load ground-truth canary rows (after scraping, so our own assigned
        #    set is already present for local sites).
        rows, source = _load_ground_truth(req)
        run["ground_truth_source"] = source

        # 4. Build mock-leak context (lets the offline 'scraper-sim' demonstrate
        #    a positive detection by leaking a stored canary set).
        leak = pick_leak_candidates(rows, prefer_user_agent=PROBE_USER_AGENT)
        context = {"subject": subject, "leak_candidates": leak}

        # 5. Query the target models.
        answers_by_model = llm_responses(req.models, (role_prompt, questions), context=context)

        # 6. Extract + match per model (best Jaccard across all questions/rows).
        matches_found = 0
        best_overall = 0.0
        for model, qa_list in answers_by_model.items():
            answers = [qa.get("answer", "") for qa in qa_list if qa.get("answer")]
            errors = [qa["error"] for qa in qa_list if "error" in qa]
            if not answers:
                run["results"].append({
                    "model": model,
                    "error": errors[0] if errors else "No answer returned.",
                })
                continue

            combined = "\n\n".join(answers)
            extracted = extract_info(combined)

            best_match = None
            best_score = -1.0
            for row in rows:
                result = matcher(extracted, row)
                if result["jaccard_score"] > best_score:
                    best_score = result["jaccard_score"]
                    best_match = result

            leaked = bool(best_match) and best_match["jaccard_score"] >= config.HIGH_RISK_THRESHOLD
            if leaked:
                matches_found += 1
            best_overall = max(best_overall, best_match["jaccard_score"] if best_match else 0.0)

            run["results"].append({
                "model": model,
                "answer": combined,
                "extracted": extracted,
                "best_match": best_match,
                "leaked": leaked,
            })

        run["summary"] = {
            "models_tested": len(req.models),
            "matches_found": matches_found,
            "best_score": round(best_overall, 4),
            "ground_truth_rows": len(rows),
            "threshold": config.HIGH_RISK_THRESHOLD,
        }
        run["status"] = "completed"

    except GroundTruthError as exc:
        run["status"] = "failed"
        run["error"] = f"Ground truth unavailable: {exc}"
    except Exception as exc:  # surface the failure in the persisted record
        run["status"] = "failed"
        run["error"] = f"{type(exc).__name__}: {exc}"

    run["finished_at"] = _now()
    if req.persist:
        save_run(run)
    return run
