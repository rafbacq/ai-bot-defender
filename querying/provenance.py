"""Training-data provenance & crawl-to-train latency (AI Bot Defender — 6b).

Answers "did model X train on my honeypot content, and *when*?" by probing
successive model versions and bounding ingestion from which versions reproduce a
canary set:

  * which model versions leak a given canary set (regurgitation, via the existing
    extractor + matcher), and
  * each version's knowledge cutoff (querying/model_timeline.py), plus
  * when the crawler that received that canary set first visited (mint/crawl time
    derived from the per-site new_visits log — no schema change).

If version V (cutoff C_V) leaks the set and an earlier version doesn't, ingestion
falls in (latest non-leaking cutoff, C_V], intersected with [crawl_time, .). The
crawl-to-train latency upper bound is C_V - crawl_time.

Caveats baked into the report: cutoffs are approximate, aligned models refuse to
regurgitate (use membership.py for those), and a leak could be live retrieval
rather than training — which rag_disambiguation.py separates.
"""

import json
import secrets
from datetime import date, datetime, timezone

from . import config, ground_truth, model_timeline
from .extractor import extract_info
from .llm_client import llm_responses
from .matcher import matcher
from .parser import parser
from .prompt_generator import generate_probes

PROBE_USER_AGENT = "AIBotDefender-Probe/1.0"


# ---------------------------------------------------------------------------
# Crawl / mint times from the per-site new_visits log
# ---------------------------------------------------------------------------
def _site_psql_json(project_root, site_id, db_name, db_user, sql):
    # Shared per-site DB runner (ground_truth.site_psql_json): direct psycopg2
    # when SITEDB_HOST is set (the AWS/RDS path), else docker compose exec into
    # the site stack's db container — the same dual-path contract as the central
    # logdb access in app/services/logdb.py and crawler_graph.ingest.db.
    return ground_truth.site_psql_json(project_root, site_id, db_name, db_user, sql, timeout=30)


def crawl_times(project_root, site_id, db_name, db_user):
    """Return ``{(user_agent, asn): {first_seen, last_seen, n}}`` from new_visits.

    The earliest visit by a (user_agent, asn) is when that visitor was first
    served its canary set — its mint/crawl time.
    """
    sql = (
        "SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM ("
        "SELECT user_agent, asn, min(timestamp) AS first_seen, "
        "max(timestamp) AS last_seen, count(*) AS n "
        "FROM new_visits GROUP BY user_agent, asn) t;"
    )
    rows = _site_psql_json(project_root, site_id, db_name, db_user, sql)
    out = {}
    for row in rows:
        out[(row.get("user_agent"), row.get("asn"))] = {
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "n": row.get("n"),
        }
    return out


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------
def _to_date(value):
    if not value:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Per-model leak detection
# ---------------------------------------------------------------------------
def _row_key(row):
    return (row.get("user_agent"), row.get("asn"))


def probe_models(role_prompt, questions, rows, models, context, threshold):
    """For each model, return which canary-set keys it leaked (+ best scores)."""
    leak_by_model = {}
    for model in models:
        try:
            answers = llm_responses([model], (role_prompt, questions), context=context)
        except Exception as exc:
            leak_by_model[model] = {"error": f"{type(exc).__name__}: {exc}"}
            continue
        qa = answers.get(model, [])
        combined = "\n\n".join(a["answer"] for a in qa if a.get("answer"))
        errors = [a["error"] for a in qa if "error" in a]
        if not combined:
            leak_by_model[model] = {"error": errors[0] if errors else "no answer"}
            continue
        extracted = extract_info(combined)
        leaked = {}
        best = 0.0
        for row in rows:
            res = matcher(extracted, row)
            best = max(best, res["jaccard_score"])
            if res["jaccard_score"] >= threshold:
                leaked["|".join(str(x) for x in _row_key(row))] = res["jaccard_score"]
        leak_by_model[model] = {"leaked": leaked, "best_score": round(best, 4),
                                "n_leaked": len(leaked)}
    return leak_by_model


# ---------------------------------------------------------------------------
# Ingestion-window inference
# ---------------------------------------------------------------------------
def infer_windows(leak_by_model, crawl, models):
    """Bound the ingestion window + crawl-to-train latency for each leaked set."""
    entries = {e["id"]: e for e in model_timeline.timeline()}

    def real_cutoff(model):
        e = entries.get(model)
        if not e or e.get("provider") == "Mock":
            return None  # mock sims don't carry real cutoffs
        return e.get("cutoff_date")

    keys = set()
    for info in leak_by_model.values():
        keys |= set(info.get("leaked", {}).keys())

    results = []
    for key in sorted(keys):
        leaking = [m for m in models if key in leak_by_model.get(m, {}).get("leaked", {})]
        non_leaking = [
            m for m in models
            if m in leak_by_model and "error" not in leak_by_model[m]
            and key not in leak_by_model[m].get("leaked", {})
        ]
        leak_cut = sorted(c for c in (real_cutoff(m) for m in leaking) if c)
        nonleak_cut = sorted(c for c in (real_cutoff(m) for m in non_leaking) if c)

        ua, asn = (key.split("|", 1) + [None])[:2]
        ct = crawl.get((ua, asn)) or crawl.get((ua, None)) or {}
        crawl_date = _to_date(ct.get("first_seen"))

        earliest_leak = leak_cut[0] if leak_cut else None
        lower = crawl_date
        if earliest_leak:
            below = [c for c in nonleak_cut if c < earliest_leak]
            if below:
                cand = max(below)
                lower = max([d for d in (crawl_date, cand) if d], default=cand)
        latency_days = None
        if earliest_leak and crawl_date:
            latency_days = (earliest_leak - crawl_date).days

        results.append({
            "canary_set": key,
            "user_agent": ua,
            "asn": asn,
            "crawl_first_seen": ct.get("first_seen"),
            "leaking_models": leaking,
            "non_leaking_models": non_leaking,
            "ingestion_window": {
                "earliest": lower.isoformat() if lower else None,
                "latest": earliest_leak.isoformat() if earliest_leak else None,
            },
            "crawl_to_train_latency_days_upper_bound": latency_days,
            "bounded_by_real_models": bool(leak_cut),
        })
    return results


# ---------------------------------------------------------------------------
# Orchestration + persistence
# ---------------------------------------------------------------------------
def _runs_dir():
    config.PROVENANCE_DIR.mkdir(parents=True, exist_ok=True)
    return config.PROVENANCE_DIR


def new_run_id():
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2)


def save_report(report):
    """Write a report **atomically** (temp + ``os.replace``): reports are now
    checkpointed while a background probe runs, and the report page's live
    poller must never observe a half-written file."""
    import os

    runs_dir = _runs_dir()
    path = runs_dir / f"{report['run_id']}.json"
    tmp = runs_dir / f".{report['run_id']}.json.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=str)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    return path


def list_reports():
    reports = []
    for path in _runs_dir().glob("*.json"):
        try:
            with open(path, encoding="utf-8") as handle:
                reports.append(json.load(handle))
        except (OSError, json.JSONDecodeError):
            continue
    reports.sort(key=lambda r: r.get("started_at", ""), reverse=True)
    return reports


def load_report(run_id):
    path = _runs_dir() / f"{run_id}.json"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        # Treated as "not available yet" rather than crashing a live poller.
        return None


def run_provenance(*, target_url, host_header=None, verify_tls=True, site_id=None,
                   db_name=None, db_user=None, project_root=None, models=None,
                   max_questions=None, seed=None, persist=True, run_id=None):
    """Run the provenance probe across a model timeline and return the report.

    ``run_id`` lets a background caller pre-assign the id it redirects to
    (mirrors the detection adapter's contract); omitted = a fresh id.
    """
    project_root = project_root or config.PROJECT_ROOT
    models = models or [e["id"] for e in model_timeline.timeline() if e.get("available")]
    run = {
        "run_id": run_id or new_run_id(),
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kind": "provenance",
        "site_id": site_id,
        "target_url": target_url,
        "models": models,
        "threshold": config.HIGH_RISK_THRESHOLD,
        "status": "running",
        "error": None,
    }
    try:
        record = parser(target_url, host_header=host_header, verify=verify_tls)
        if not record or not record.get("main_idea"):
            raise RuntimeError("Could not scrape a subject from the target page.")
        subject = record["main_idea"]
        role_prompt, questions = generate_probes(record, max_questions or config.MAX_PROBES, seed=seed)

        if site_id and db_name and db_user:
            rows = ground_truth.load_site_rows(project_root, site_id, db_name, db_user)
            crawl = crawl_times(project_root, site_id, db_name, db_user)
        else:
            rows = ground_truth.load_csv_rows(config.SAMPLE_GROUND_TRUTH)
            crawl = {}

        leak = ground_truth.pick_leak_candidates(rows, prefer_user_agent=PROBE_USER_AGENT)
        context = {"subject": subject, "leak_candidates": leak}

        leak_by_model = probe_models(
            role_prompt, questions, rows, models, context, config.HIGH_RISK_THRESHOLD
        )
        windows = infer_windows(leak_by_model, crawl, models)

        run.update(
            subject=subject,
            role_prompt=role_prompt,
            probes=questions,
            timeline=[
                {"id": e["id"], "provider": e.get("provider"),
                 "knowledge_cutoff": e.get("knowledge_cutoff")}
                for e in model_timeline.sorted_by_cutoff(models)
            ],
            leak_by_model=leak_by_model,
            provenance=windows,
            # The mint/crawl times themselves — when each (UA, ASN) visitor was
            # first/last served its canary set. The raw evidence the windows rest on.
            crawlers=sorted(
                ({"user_agent": ua, "asn": asn, **info}
                 for (ua, asn), info in crawl.items()),
                key=lambda c: str(c.get("first_seen") or ""),
            ),
            n_canary_sets=len(rows),
            n_crawlers=len(crawl),
            summary={
                "models_tested": len(models),
                "sets_with_evidence": len(windows),
                "sets_bounded_by_real_models": sum(1 for w in windows if w["bounded_by_real_models"]),
            },
            status="completed",
        )
    except Exception as exc:
        run["status"] = "failed"
        run["error"] = f"{type(exc).__name__}: {exc}"

    run["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if persist:
        run["report_path"] = str(save_report(run))
    return run


# ---------------------------------------------------------------------------
# CLI:  python -m querying.provenance --site site-001 --db-name scraper1-db ...
# ---------------------------------------------------------------------------
def main():
    import argparse

    ap = argparse.ArgumentParser(description="AI Bot Defender — training-data provenance probe")
    ap.add_argument("--url", help="Target URL to scrape (custom mode).")
    ap.add_argument("--site", help="Local honeypot site_id (proxy mode).")
    ap.add_argument("--proxy-url", default="http://127.0.0.1/")
    ap.add_argument("--local-base-domain", default="dukecodeplus.localhost")
    ap.add_argument("--db-name", help="Per-site DB name, e.g. scraper1-db.")
    ap.add_argument("--db-user", default="user")
    ap.add_argument("--models", nargs="+", default=None,
                    help="Model ids to probe (default: the available timeline).")
    ap.add_argument("--max-questions", type=int, default=config.MAX_PROBES)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if not args.url and not args.site:
        ap.error("provide either --url (custom) or --site (local honeypot).")

    if args.site:
        report = run_provenance(
            target_url=args.proxy_url, host_header=f"{args.site}.{args.local_base_domain}",
            verify_tls=False, site_id=args.site, db_name=args.db_name, db_user=args.db_user,
            models=args.models, max_questions=args.max_questions, seed=args.seed,
        )
    else:
        report = run_provenance(
            target_url=args.url, models=args.models,
            max_questions=args.max_questions, seed=args.seed,
        )
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
