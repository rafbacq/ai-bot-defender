"""Bridge between the web app and the ``querying`` provenance layer (6b).

Runs the training-data provenance probe, the RAG-vs-training experiment, and an
offline membership-inference demo, and exposes their persisted reports to the
/provenance page. Local-site parameters are derived the same way the Query
Console does (``merged_site_config`` + ``PROXY_HTTP_ENTRY``).

Provenance/RAG runs execute **in the background** (same rationale as the
detection ``run_manager``: probing several real model versions takes many
seconds each, and a synchronous POST would hang the browser). ``start_*``
persists a ``running`` placeholder report, spawns a worker thread, and returns
the run id at once; the report detail page polls ``status()`` and reloads when
the worker finishes. A report stuck on ``running`` with no live worker (the app
restarted mid-probe) is reported as **interrupted** so the page never spins
forever.
"""

import threading
from datetime import datetime, timezone

from querying import config as q_config
from querying import membership as mem
from querying import model_timeline, provenance, rag_disambiguation

from .. import config
from .querying_service import PROXY_HTTP_ENTRY
from .sites import merged_site_config

# In-process registry of live probe workers, keyed by run_id. Guarded by _LOCK.
_ACTIVE = {}
_LOCK = threading.Lock()


def timeline():
    """Model-version timeline (id, provider, cutoff) for the picker + display."""
    return [
        {"id": e["id"], "provider": e.get("provider"),
         "knowledge_cutoff": e.get("knowledge_cutoff"), "available": e.get("available", True)}
        for e in model_timeline.sorted_by_cutoff()
    ]


def default_models():
    return [e["id"] for e in model_timeline.timeline() if e.get("available")]


def provider_status():
    return {
        "anthropic": bool(q_config.ANTHROPIC_API_KEY),
        "openrouter": bool(q_config.OPENROUTER_API_KEY),
        "membership_backend": q_config.MEMBERSHIP_BACKEND,
    }


def list_reports():
    return provenance.list_reports()


def load_report(run_id):
    return provenance.load_report(run_id)


def _site_kwargs(mode, site_id, url):
    """Resolve where the probe scrapes. Local-site resolution happens *before*
    the worker spawns, so a bad site id fails the POST immediately."""
    if mode == "local" and site_id:
        site = merged_site_config(site_id)
        return {
            "target_url": f"{PROXY_HTTP_ENTRY}/", "host_header": site["local_hostname"],
            "verify_tls": False, "site_id": site_id, "db_name": site["db_name"],
            "db_user": site["database"]["user"],
            "project_root": str(config.PROJECT_ROOT),
        }
    return {"target_url": url or "http://127.0.0.1/"}


def _spawn(run_id, kind, fn, kwargs):
    """Persist a ``running`` placeholder for ``run_id`` and run ``fn`` on a
    daemon thread. The worker function persists the final report itself (it
    traps its own errors into a ``failed`` record); the belt-and-braces except
    covers anything outside that trap so the placeholder never sticks."""
    provenance.save_report({
        "run_id": run_id,
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kind": kind,
        "site_id": kwargs.get("site_id"),
        "target_url": kwargs.get("target_url"),
        "models": list(kwargs.get("models") or []),
        "status": "running",
        "error": None,
    })

    def worker():
        try:
            fn(run_id=run_id, **kwargs)
        except Exception as exc:
            report = provenance.load_report(run_id) or {"run_id": run_id}
            report.update(status="failed", error=f"{type(exc).__name__}: {exc}")
            provenance.save_report(report)
        finally:
            with _LOCK:
                _ACTIVE.pop(run_id, None)

    thread = threading.Thread(target=worker, name=f"prov-{run_id}", daemon=True)
    with _LOCK:
        _ACTIVE[run_id] = thread
    thread.start()
    return {"run_id": run_id, "status": "running"}


def start_provenance(mode, site_id, url, models, max_questions=3, seed=None):
    """Kick off a provenance probe in the background; returns ``{run_id, ...}``."""
    kwargs = dict(_site_kwargs(mode, site_id, url), models=models,
                  max_questions=max_questions, seed=seed)
    return _spawn(provenance.new_run_id(), "provenance",
                  provenance.run_provenance, kwargs)


def start_rag(mode, site_id, url, models, page_removed=False, max_questions=3, seed=None):
    """Kick off a RAG-vs-training experiment in the background."""
    kwargs = dict(_site_kwargs(mode, site_id, url), models=models,
                  page_removed=page_removed, max_questions=max_questions, seed=seed)
    return _spawn(provenance.new_run_id(), "rag-disambiguation",
                  rag_disambiguation.run_rag_experiment, kwargs)


def status(run_id):
    """Merged live + persisted status for the report page's poller.

    ``interrupted`` = the persisted report still says ``running`` but no live
    worker exists in this process (an app restart killed it mid-probe)."""
    report = load_report(run_id)
    with _LOCK:
        alive = run_id in _ACTIVE and _ACTIVE[run_id].is_alive()
    if report is None:
        return {"run_id": run_id, "present": False, "status": "missing",
                "done": not alive, "interrupted": False}
    running = report.get("status") == "running"
    interrupted = running and not alive
    return {
        "run_id": run_id,
        "present": True,
        "status": "failed" if interrupted else report.get("status"),
        "done": (not running) or interrupted,
        "interrupted": interrupted,
    }


def membership_demo(n=24, seed=None):
    """Offline demonstration of the membership-inference method (mock backend).

    Generates served + control watermark docs, simulates a model that memorized
    the served set, and runs the Min-K% hypothesis test — showing the served set
    tests as 'member' (low p) and the control set does not. Real use sets
    QUERY_MEMBERSHIP_BACKEND=hf|openai and scores actually-served watermarks.
    """
    wm = mem.generate_watermarks(n=n, seed=seed)
    scorer = mem.get_scorer()  # honors QUERY_MEMBERSHIP_BACKEND
    if isinstance(scorer, mem.MockScorer):
        scorer = mem.MockScorer(memorized=wm["served"], seed=seed or 0)
    result = mem.run_membership(wm["served"], wm["control"], scorer=scorer)
    result["backend"] = q_config.MEMBERSHIP_BACKEND
    result["n_docs"] = n
    return result
