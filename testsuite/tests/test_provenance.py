"""Training-data provenance (Direction 6b): when/whether a model ingested a page.

Covers the four provenance sub-capabilities, all offline:

  * ``model_timeline`` — the model-id -> knowledge-cutoff registry the windows rest on.
  * ``provenance.infer_windows`` — bounding the ingestion window + crawl-to-train
    latency from which model versions leak a canary set and their cutoffs.
  * ``membership`` — Min-K%/Min-K%++ membership inference separating served
    watermarks from never-served controls into a calibrated p-value.
  * ``rag_disambiguation`` — telling training-memorization from live retrieval
    (browsing off vs. on + live-fetch correlation).
"""

from __future__ import annotations

from datetime import date

import pytest

CANARY_VALUES = [
    "Maribel Quince", "North Alder", "1888", "West Cobalt", "Ravenfield Institute",
    "Lake Vesper", "Copper Manor", "Juniper Archive", "Orchid Bridge", "Silver Lantern",
]


def _canary_row(user_agent="AIBotDefender-Probe/1.0", asn="20473"):
    row = {"user_agent": user_agent, "asn": asn}
    for i, value in enumerate(CANARY_VALUES, 1):
        row[f"var{i}"] = value
    return row


# --- model timeline --------------------------------------------------------
def test_model_timeline_exposes_cutoffs_and_sorts_oldest_first():
    from querying import model_timeline

    entries = {e["id"]: e for e in model_timeline.timeline()}
    assert "mock/scraper-sim" in entries and "mock/honest-llm" in entries
    # Every entry parses its cutoff into a real date.
    assert all(e["cutoff_date"] is None or isinstance(e["cutoff_date"], date)
               for e in entries.values())

    real = [e for e in model_timeline.timeline()
            if e.get("provider") not in ("Mock", None) and e.get("cutoff_date")]
    assert real, "expected some real-provider models with cutoffs"
    ids = [e["id"] for e in real]
    ordered = model_timeline.sorted_by_cutoff(ids)
    cutoffs = [e["cutoff_date"] for e in ordered]
    assert cutoffs == sorted(cutoffs), "sorted_by_cutoff must be oldest-first"


# --- ingestion-window inference --------------------------------------------
def test_ingestion_window_is_bounded_by_model_cutoffs_and_crawl_time(monkeypatch):
    """If a newer model leaks a set an older one doesn't, ingestion is bounded to
    (older cutoff or crawl-time, newer cutoff], and latency = newer cutoff - crawl."""
    from querying import model_timeline, provenance

    timeline = [
        {"id": "model/old", "provider": "Provider", "knowledge_cutoff": "2024-01",
         "cutoff_date": date(2024, 1, 1), "available": True},
        {"id": "model/new", "provider": "Provider", "knowledge_cutoff": "2025-01",
         "cutoff_date": date(2025, 1, 1), "available": True},
    ]
    monkeypatch.setattr(model_timeline, "timeline", lambda: timeline)

    leak_by_model = {
        "model/old": {"leaked": {}, "best_score": 0.0, "n_leaked": 0},
        "model/new": {"leaked": {"AIBotDefender-Probe/1.0|20473": 0.8}, "best_score": 0.8, "n_leaked": 1},
    }
    crawl = {("AIBotDefender-Probe/1.0", "20473"): {
        "first_seen": "2024-06-15T12:00:00+00:00", "last_seen": "2024-06-16T12:00:00+00:00", "n": 3}}

    windows = provenance.infer_windows(leak_by_model, crawl, ["model/old", "model/new"])
    assert len(windows) == 1
    win = windows[0]
    assert win["ingestion_window"] == {"earliest": "2024-06-15", "latest": "2025-01-01"}
    assert win["crawl_to_train_latency_days_upper_bound"] == 200
    assert win["bounded_by_real_models"] is True
    assert win["leaking_models"] == ["model/new"] and win["non_leaking_models"] == ["model/old"]


# --- membership inference ---------------------------------------------------
def test_membership_statistics_separate_served_from_control():
    """The Min-K%++ statistic + Mann-Whitney test flag the memorized (served) set."""
    from querying import membership as mem

    wm = mem.generate_watermarks(n=24, seed=4)
    assert len(wm["served"]) == 24 and len(wm["control"]) == 24
    assert not (set(wm["served"]) & set(wm["control"])), "served/control must be disjoint"

    scorer = mem.MockScorer(memorized=wm["served"], seed=4)
    result = mem.run_membership(wm["served"], wm["control"], scorer=scorer)
    assert result["is_member"] is True
    assert result["auc"] > 0.95
    assert result["served_mean"] > result["control_mean"]
    assert result["statistic"] == "min_k++"
    assert result["p_value"] is not None and result["p_value"] < result["alpha"]


def test_membership_demo_reports_member_for_served_watermarks():
    """The /provenance membership demo wires the statistic through end to end."""
    from app.services import provenance_service

    result = provenance_service.membership_demo(n=20, seed=4)
    assert result["backend"] == "mock"
    assert result["n_docs"] == 20
    assert result["is_member"] is True
    assert result["auc"] > 0.95
    assert result["statistic"] == "min_k++"


# --- RAG vs. training disambiguation ---------------------------------------
def test_rag_disambiguation_classifies_browsing_off_leak_as_memorized(monkeypatch):
    """A canary reproduced with browsing OFF (and the page removed) is memorized
    (training ingestion), not live retrieval."""
    from querying import rag_disambiguation

    row = _canary_row()
    monkeypatch.setattr(rag_disambiguation, "_live_fetches", lambda site, since: {"n": 0, "agents": []})

    result = rag_disambiguation.disambiguate_model(
        "mock/scraper-sim", "role", ["question"], [row],
        {"subject": "Jennifer Balef", "leak_candidates": CANARY_VALUES},
        site="site-001.dukecodeplus.localhost", threshold=0.3, page_removed=True,
    )
    assert result["leak_browsing_off"] is True
    assert result["verdict"] == "memorized (training ingestion)"
    assert result["confidence"] == "high"


def test_rag_disambiguation_reports_no_evidence_for_honest_model(monkeypatch):
    """A model that never reproduces the canary (browsing off or on) yields no evidence."""
    from querying import rag_disambiguation

    monkeypatch.setattr(rag_disambiguation, "_live_fetches", lambda site, since: {"n": 0, "agents": []})
    result = rag_disambiguation.disambiguate_model(
        "mock/honest-llm", "role", ["question"], [_canary_row()],
        {"subject": "Jennifer Balef", "leak_candidates": CANARY_VALUES},
        site=None, threshold=0.3, page_removed=False,
    )
    assert result["leak_browsing_off"] is False and result["leak_browsing_on"] is False
    assert result["verdict"] == "no evidence"


# --- provider routing: no silent mock fallback -------------------------------
def test_unknown_provider_ids_error_instead_of_mock_leaking(monkeypatch):
    """The launcher's shared pool includes LiteLLM ids (gemini/*, openai/*).
    The legacy client used to fall back to the *leak-simulating* mock for any
    unrecognized prefix — fabricating ingestion evidence for a real model. Now
    those ids route to the LiteLLM path, and a failure there surfaces as a
    per-question error, never as a canary-bearing answer."""
    from querying import llm_client

    routed = []

    def _failing_litellm(model_id, role_prompt, question, timeout, browsing=False):
        routed.append(model_id)
        raise RuntimeError("simulated provider failure")

    monkeypatch.setattr(llm_client, "_litellm_answer", _failing_litellm)
    context = {"subject": "Jennifer Balef", "leak_candidates": CANARY_VALUES}
    out = llm_client.llm_responses(
        ["gemini/gemini-2.5-flash", "openai/gpt-5-search-api"],
        ("role", ["q1"]), context=context,
    )
    assert routed == ["gemini/gemini-2.5-flash", "openai/gpt-5-search-api"]
    for model, results in out.items():
        assert "error" in results[0], f"{model} must error, not answer"
        blob = str(results)
        assert not any(v in blob for v in CANARY_VALUES), \
            f"{model} must never emit mock canaries"


def test_probe_models_records_provider_errors_without_false_leaks(monkeypatch):
    """A provenance probe over a mix of mock + failing live models keeps the
    real leak evidence and reports the failure — no cross-contamination."""
    from querying import llm_client, provenance

    monkeypatch.setattr(
        llm_client, "_litellm_answer",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no key")))
    leaks = provenance.probe_models(
        "role", ["q"], [_canary_row()],
        ["mock/scraper-sim", "gemini/gemini-2.5-flash"],
        {"subject": "Jennifer Balef", "leak_candidates": CANARY_VALUES},
        threshold=0.3,
    )
    assert leaks["mock/scraper-sim"]["n_leaked"] == 1
    assert "error" in leaks["gemini/gemini-2.5-flash"]
    assert "leaked" not in leaks["gemini/gemini-2.5-flash"]


# --- full provenance probe, offline end to end -------------------------------
def test_run_provenance_end_to_end_offline(monkeypatch, tmp_path):
    """The whole orchestration — scrape -> probes -> ground truth -> leak
    matrix -> ingestion windows -> persisted report — on the offline mocks."""
    from querying import config as q_config
    from querying import provenance

    monkeypatch.setattr(q_config, "PROVENANCE_DIR", tmp_path / "prov")
    monkeypatch.setattr(provenance, "parser",
                        lambda url, host_header=None, verify=True: {
                            "main_idea": "Jennifer Balef", "top_anchors": []})
    monkeypatch.setattr(provenance.ground_truth, "load_csv_rows",
                        lambda path: [_canary_row()])

    report = provenance.run_provenance(
        target_url="http://example.test/",
        models=["mock/scraper-sim", "mock/honest-llm"],
        max_questions=2, seed=7, run_id="prov-e2e",
    )
    assert report["status"] == "completed" and report["run_id"] == "prov-e2e"
    assert report["leak_by_model"]["mock/scraper-sim"]["n_leaked"] == 1
    assert report["leak_by_model"]["mock/honest-llm"]["n_leaked"] == 0

    assert report["provenance"], "the leaked set must yield a window entry"
    win = report["provenance"][0]
    assert win["leaking_models"] == ["mock/scraper-sim"]
    assert win["non_leaking_models"] == ["mock/honest-llm"]
    assert win["bounded_by_real_models"] is False  # mock cutoffs never bound

    # Persisted (atomically) and loadable through the same store.
    assert provenance.load_report("prov-e2e")["status"] == "completed"


# --- full RAG experiment, offline end to end ---------------------------------
def test_run_rag_experiment_end_to_end_offline(monkeypatch, tmp_path):
    from querying import config as q_config
    from querying import provenance
    from querying import rag_disambiguation as rag

    monkeypatch.setattr(q_config, "PROVENANCE_DIR", tmp_path / "prov")
    monkeypatch.setattr(rag, "parser",
                        lambda url, host_header=None, verify=True: {
                            "main_idea": "Jennifer Balef"})
    monkeypatch.setattr(rag.ground_truth, "load_csv_rows",
                        lambda path: [_canary_row()])
    monkeypatch.setattr(rag, "_live_fetches",
                        lambda site, since: {"n": 0, "agents": []})

    report = rag.run_rag_experiment(
        target_url="http://example.test/",
        models=["mock/scraper-sim", "mock/honest-llm"],
        page_removed=True, max_questions=2, seed=7, run_id="rag-e2e",
    )
    assert report["status"] == "completed" and report["run_id"] == "rag-e2e"
    by_model = {r["model"]: r for r in report["results"]}
    assert by_model["mock/scraper-sim"]["verdict"] == "memorized (training ingestion)"
    assert by_model["mock/scraper-sim"]["confidence"] == "high"  # page removed
    assert by_model["mock/honest-llm"]["verdict"] == "no evidence"
    assert provenance.load_report("rag-e2e")["kind"] == "rag-disambiguation"


def test_rag_reports_provider_errors_not_no_evidence(monkeypatch):
    """A model whose provider fails on every question is 'provider error' —
    the old behavior silently read as 'no evidence'."""
    from querying import llm_client
    from querying import rag_disambiguation as rag

    monkeypatch.setattr(
        llm_client, "_litellm_answer",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no key")))
    monkeypatch.setattr(rag, "_live_fetches", lambda site, since: {"n": 0, "agents": []})

    result = rag.disambiguate_model(
        "gemini/gemini-2.5-flash", "role", ["q"], [_canary_row()],
        {"subject": "Jennifer Balef", "leak_candidates": CANARY_VALUES},
        site=None, threshold=0.3, page_removed=False,
    )
    assert result["verdict"] == "provider error"
    assert result["error"] and "no key" in result["error"]


# --- background execution through the service --------------------------------
def test_provenance_service_runs_probes_in_the_background(monkeypatch, tmp_path):
    """start_provenance persists a running placeholder, returns at once, and the
    worker completes the report; status() tracks the transition."""
    import time

    pytest.importorskip("fastapi")  # app.services siblings import it transitively
    from app.services import provenance_service as ps
    from querying import config as q_config
    from querying import provenance

    monkeypatch.setattr(q_config, "PROVENANCE_DIR", tmp_path / "prov")
    monkeypatch.setattr(provenance, "parser",
                        lambda url, host_header=None, verify=True: {
                            "main_idea": "Jennifer Balef"})
    monkeypatch.setattr(provenance.ground_truth, "load_csv_rows",
                        lambda path: [_canary_row()])

    run = ps.start_provenance("custom", "", "http://example.test/",
                              ["mock/scraper-sim", "mock/honest-llm"],
                              max_questions=2, seed=7)
    run_id = run["run_id"]
    assert run["status"] == "running"

    deadline = time.time() + 20
    while time.time() < deadline and not ps.status(run_id)["done"]:
        time.sleep(0.05)
    final = ps.status(run_id)
    assert final["done"] and final["status"] == "completed"
    assert final["interrupted"] is False
    report = ps.load_report(run_id)
    assert report["leak_by_model"]["mock/scraper-sim"]["n_leaked"] == 1


def test_provenance_status_flags_interrupted_runs(monkeypatch, tmp_path):
    """A report stuck on 'running' with no live worker (app restarted) is
    reported interrupted/done so the page never polls forever."""
    pytest.importorskip("fastapi")
    from app.services import provenance_service as ps
    from querying import config as q_config
    from querying import provenance

    monkeypatch.setattr(q_config, "PROVENANCE_DIR", tmp_path / "prov")
    provenance.save_report({"run_id": "stuck-1", "status": "running"})
    s = ps.status("stuck-1")
    assert s["interrupted"] is True and s["done"] is True
    assert s["status"] == "failed"

    missing = ps.status("never-existed")
    assert missing["present"] is False and missing["done"] is True
