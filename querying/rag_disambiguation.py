"""Distinguish training-memorization from live retrieval (AI Bot Defender — 6b).

A model can "know" a canary because it trained on it OR because it browsed to it
at query time (RAG). This harness separates them:

  1. Query the model with browsing OFF. If it still reproduces the canary, it
     MEMORIZED it (training) — decisive when the page has since been removed,
     because there is nothing left to fetch.
  2. Query with browsing ON as a control, and check the central all_visits log
     for a live fetch of the site during the query window — that is the
     signature of retrieval, not memory.

The serve-once-then-remove step is operational (take the honeypot page down via
the Site Configurator / ``docker compose down`` before running with
``--page-removed``); this module implements the query-side logic and the
all_visits correlation, and records whether the page was removed so the verdict
is interpreted correctly.
"""

import json
import subprocess
from concurrent.futures import CancelledError
from datetime import datetime, timezone

from . import config, ground_truth
from .extractor import extract_info
from .llm_client import llm_responses
from .matcher import matcher
from .parser import parser
from .prompt_generator import generate_probes

PROBE_USER_AGENT = "AIBotDefender-Probe/1.0"


def _logdb_json(sql):
    """Query the central logdb via docker compose exec (mirrors request_log)."""
    command = [
        "docker", "compose", "-f", str(config.PROJECT_ROOT / "docker-compose.proxy.yml"),
        "exec", "-T", "logdb",
        "psql", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1",
        "-U", "logger", "-d", "site_logs", "-c", sql,
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    out = result.stdout.strip()
    try:
        return json.loads(out) if out else None
    except json.JSONDecodeError:
        return None


def _live_fetches(site, since_iso):
    """Count requests to ``site`` since ``since_iso`` that are NOT our own probe.

    A non-probe request arriving during the query window is the fingerprint of a
    model browsing to the page live (retrieval), as opposed to answering from
    memory.
    """
    site_lit = "'" + (site or "").replace("'", "''") + "'"
    since_lit = "'" + since_iso.replace("'", "''") + "'"
    probe_lit = "'%" + PROBE_USER_AGENT.replace("'", "''") + "%'"
    sql = (
        "SELECT json_build_object("
        "'n', COUNT(*),"
        "'agents', COALESCE(json_agg(DISTINCT user_agent), '[]'::json)"
        f") FROM all_visits WHERE ts >= {since_lit} "
        f"AND (site = {site_lit} OR {site_lit} = '') "
        f"AND COALESCE(user_agent,'') NOT LIKE {probe_lit};"
    )
    data = _logdb_json(sql)
    if not data:
        return {"n": 0, "agents": []}
    return data


def _any_leak(combined, rows, threshold):
    """Best Jaccard of the answer vs. any canary row, and whether it crosses the threshold."""
    if not combined:
        return False, 0.0
    extracted = extract_info(combined)
    best = 0.0
    for row in rows:
        best = max(best, matcher(extracted, row)["jaccard_score"])
    return best >= threshold, round(best, 4)


def _query(model, role_prompt, questions, context, browsing, cancel_check=None):
    """One probing pass. Returns ``(combined_answer_text, [error, ...])`` —
    ``llm_responses`` isolates failures per question, so a provider problem
    surfaces here as errors + missing text, never as an exception."""
    answers = llm_responses([model], (role_prompt, questions), context=context,
                            options={"browsing": browsing},
                            cancel_check=cancel_check)
    qa = answers.get(model, [])
    combined = "\n\n".join(a["answer"] for a in qa if a.get("answer"))
    errors = [a["error"] for a in qa if "error" in a]
    return combined, errors


def disambiguate_model(model, role_prompt, questions, rows, context, *, site,
                       threshold, page_removed, cancel_check=None):
    """Run the browsing-off / browsing-on probes for one model and classify.

    Provider failures are *reported*, not swallowed: a pass that produced no
    text because every question errored is unknown, and an unknown pass must
    weaken the verdict (an all-error model is "provider error", an on-only
    leak with a failed off-pass is "inconclusive") rather than silently
    reading as "no evidence".
    """
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if cancel_check:
        cancel_check()
    off, errors_off = _query(
        model, role_prompt, questions, context, browsing=False,
        cancel_check=cancel_check,
    )
    leak_off, best_off = _any_leak(off, rows, threshold)

    if cancel_check:
        cancel_check()
    on, errors_on = _query(
        model, role_prompt, questions, context, browsing=True,
        cancel_check=cancel_check,
    )
    leak_on, best_on = _any_leak(on, rows, threshold)

    fetches = _live_fetches(site, started) if site else {"n": 0, "agents": []}
    live = fetches.get("n", 0) > 0

    off_failed = not off and bool(errors_off)
    on_failed = not on and bool(errors_on)
    error = None
    if off_failed and on_failed:
        verdict, confidence = "provider error", "n/a"
        error = (errors_off or errors_on)[0]
    elif leak_off:
        verdict = "memorized (training ingestion)"
        confidence = "high" if page_removed else "medium"
    elif off_failed and leak_on:
        # The leak might be memorization we couldn't test for — don't claim RAG.
        verdict, confidence = "inconclusive (browsing-off probe failed)", "n/a"
        error = errors_off[0]
    elif leak_on:
        verdict = "retrieved (live RAG)"
        confidence = "high" if live else "medium"
    else:
        verdict, confidence = "no evidence", "n/a"
        if off_failed or on_failed:
            error = (errors_off or errors_on)[0]

    return {
        "model": model,
        "leak_browsing_off": leak_off,
        "leak_browsing_on": leak_on,
        "best_score_off": best_off,
        "best_score_on": best_on,
        "live_fetch_detected": live,
        "live_fetch_count": fetches.get("n", 0),
        "live_fetch_agents": fetches.get("agents", [])[:10],
        "verdict": verdict,
        "confidence": confidence,
        "error": error,
    }


def run_rag_experiment(*, target_url, host_header=None, verify_tls=True, site_id=None,
                       db_name=None, db_user=None, project_root=None, models=None,
                       page_removed=False, max_questions=None, seed=None, persist=True,
                       run_id=None, cancel_check=None):
    """Run the RAG-vs-training experiment across models; persist + return the report.

    ``run_id`` lets a background caller pre-assign the id it redirects to."""
    from .provenance import new_run_id

    project_root = project_root or config.PROJECT_ROOT
    models = models or ["mock/scraper-sim", "mock/honest-llm"]
    run = {
        "run_id": run_id or new_run_id(),
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kind": "rag-disambiguation",
        "site_id": site_id,
        "target_url": target_url,
        "models": models,
        "page_removed": page_removed,
        "status": "running",
        "error": None,
    }
    try:
        if cancel_check:
            cancel_check()
        record = parser(target_url, host_header=host_header, verify=verify_tls)
        # The page may be intentionally removed; still proceed using the subject we
        # can recover (or a placeholder) so browsing-off probing can run.
        subject = (record or {}).get("main_idea") or "the requested subject"
        probe_record = record if (record and record.get("main_idea")) else {"main_idea": subject}
        role_prompt, questions = generate_probes(probe_record, max_questions or config.MAX_PROBES, seed=seed)
        if cancel_check:
            cancel_check()

        if site_id and db_name and db_user:
            rows = ground_truth.load_site_rows(project_root, site_id, db_name, db_user)
            site_host = host_header
        else:
            rows = ground_truth.load_csv_rows(config.SAMPLE_GROUND_TRUTH)
            site_host = None

        leak = ground_truth.pick_leak_candidates(rows, prefer_user_agent=PROBE_USER_AGENT)
        context = {"subject": subject, "leak_candidates": leak}

        results = []
        for model in models:
            if cancel_check:
                cancel_check()
            results.append(disambiguate_model(
                model, role_prompt, questions, rows, context,
                site=site_host, threshold=config.HIGH_RISK_THRESHOLD,
                page_removed=page_removed, cancel_check=cancel_check,
            ))
        run.update(subject=subject, results=results, status="completed")
    except CancelledError:
        run["status"] = "cancelled"
        run["error"] = None
    except Exception as exc:
        run["status"] = "failed"
        run["error"] = f"{type(exc).__name__}: {exc}"

    run["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if persist:
        # Atomic write (see provenance.save_report) — the report page's live
        # poller may read the file while the background worker replaces it.
        from .provenance import save_report

        run["report_path"] = str(save_report(run))
    return run


def main():
    import argparse

    ap = argparse.ArgumentParser(description="AI Bot Defender — RAG-vs-training disambiguation")
    ap.add_argument("--url", help="Target URL (custom mode).")
    ap.add_argument("--site", help="Local honeypot site_id (proxy mode).")
    ap.add_argument("--proxy-url", default="http://127.0.0.1/")
    ap.add_argument("--local-base-domain", default="dukecodeplus.localhost")
    ap.add_argument("--db-name")
    ap.add_argument("--db-user", default="user")
    ap.add_argument("--models", nargs="+", default=["mock/scraper-sim", "mock/honest-llm"])
    ap.add_argument("--page-removed", action="store_true",
                    help="set if the honeypot page has been taken down (strengthens the "
                         "memorization verdict)")
    ap.add_argument("--max-questions", type=int, default=config.MAX_PROBES)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if not args.url and not args.site:
        ap.error("provide either --url or --site.")

    if args.site:
        report = run_rag_experiment(
            target_url=args.proxy_url, host_header=f"{args.site}.{args.local_base_domain}",
            verify_tls=False, site_id=args.site, db_name=args.db_name, db_user=args.db_user,
            models=args.models, page_removed=args.page_removed,
            max_questions=args.max_questions, seed=args.seed,
        )
    else:
        report = run_rag_experiment(
            target_url=args.url, models=args.models, page_removed=args.page_removed,
            max_questions=args.max_questions, seed=args.seed,
        )
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
