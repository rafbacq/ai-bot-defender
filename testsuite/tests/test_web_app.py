"""The unified FastAPI web application (app/main.py).

Exercises every route a user can reach — the landing page, the Site Configurator,
the consolidated **Crawler Analytics** (``/logs`` -> analytics.html) and **LLM
Forensics** (``/query`` -> forensics.html) pages, the Template Generator, the run/
report detail pages, the JSON stats + CSV export endpoints, the back-compat
redirects, and the form POST handlers.

The service layer is mocked (it has its own tests) and ``TemplateResponse`` is
stubbed so the focus is the route layer: correct template + context wiring,
status codes, validation, clamping, and redirects. This is the test that pins the
app's public surface after the analytics/forensics page consolidation.
"""

from __future__ import annotations

import pytest


def _sample_run():
    return {
        "run_id": "run-1", "status": "completed", "subject": "Jennifer Balef",
        "target_url": "http://127.0.0.1/", "host_header": "site-001.dukecodeplus.localhost",
        "ground_truth_source": "synthetic", "started_at": "2026-06-01T00:00:00+00:00",
        "models": ["mock/scraper-sim"], "questions": ["q"], "role_prompt": "role",
        "summary": {"models_tested": 2, "matches_found": 1, "best_score": 0.8,
                    "threshold": 0.3, "ground_truth_rows": 1},
        "results": [{"model": "mock/scraper-sim", "leaked": True, "answer": "a",
                     "extracted": {"unique_phrases": ["canary"]},
                     "best_match": {"jaccard_score": 0.8, "matches": ["canary"], "bot": "bot"}}],
    }


def _sample_report():
    return {
        "run_id": "prov-1", "status": "completed", "kind": "provenance", "site_id": "site-001",
        "started_at": "2026-06-01T00:00:00+00:00", "models": ["mock/scraper-sim"],
        "subject": "Jennifer Balef", "role_prompt": "role", "probes": ["q"],
        "timeline": [{"id": "mock/scraper-sim", "knowledge_cutoff": "2099-12"}],
        "leak_by_model": {"mock/scraper-sim": {"n_leaked": 1, "best_score": 0.8}},
        "provenance": [], "crawlers": [],
    }


@pytest.fixture
def app_main(monkeypatch):
    """Import app.main with every service seam + TemplateResponse mocked."""
    pytest.importorskip("fastapi")
    from fastapi.responses import HTMLResponse
    from app import main

    rendered = []
    monkeypatch.setattr(main.templates, "TemplateResponse",
                        lambda request, name, context: rendered.append((name, context)) or HTMLResponse(f"tmpl:{name}"))

    # stats / sites
    monkeypatch.setattr(main.stats, "landing_stats", lambda: {
        "sites_live": 1, "sites_configured": 2, "llm_models": 4, "queries_completed": 3,
        "matches_found": 1, "best_score": 0.8, "query_runs": 2, "requests_logged": 25,
        "campaigns": 4, "disguised": 1, "device_fingerprints": 12, "unique_devices": 10,
        "contradictions": 1})
    site_row = {"site_id": "site-001", "hostname": "site-001.example",
                "local_hostname": "site-001.localhost", "scraper_version": 1,
                "website": {"port": 8080, "genmode": True},
                "database": {"host_port": 5432, "user": "user"},
                "db_name": "scraper1-db", "deployed": False}
    monkeypatch.setattr(main.sites, "available_scraper_versions", lambda: [1, 2])
    monkeypatch.setattr(main.sites, "list_sites", lambda: [site_row])
    monkeypatch.setattr(main.sites, "active_proxy_sites", lambda: ["site-001.example"])
    monkeypatch.setattr(main.sites, "get_website_dir", lambda: "/tmp/site")
    monkeypatch.setattr(main.sites, "suggest_ports", lambda: {"web_port": 8081, "db_host_port": 5433})
    monkeypatch.setattr(main.sites, "template_source", lambda v: "<html>{{ var1 }}</html>")
    monkeypatch.setattr(main.sites, "merged_site_config", lambda sid: dict(site_row, site_id=sid))

    # request log + fingerprint summary
    monkeypatch.setattr(main.request_log, "fetch_filter_options", lambda: {"sites": ["site-001"], "methods": ["GET"]})
    monkeypatch.setattr(main.request_log, "fetch_requests", lambda **k: {
        "total": 1, "last_24h": 1, "latest_ts": "2026-06-01T00:00:00+00:00",
        "rows": [{"id": 1, "ts": "2026-06-01T00:00:00+00:00", "site": "site-001",
                  "client_ip": "203.0.113.1", "method": "GET", "uri": "/",
                  "user_agent": "Chrome", "headers": {}}]})
    monkeypatch.setattr(main.request_log, "site_status_map", lambda: {"site-001"})
    monkeypatch.setattr(main.request_log, "requests_to_csv", lambda rows: "id,ts\n1,x\n")
    monkeypatch.setattr(main.fingerprint_service, "summary_counts",
                        lambda: {"fingerprints": 12, "unique_devices": 10, "tcp_fingerprints": 5})
    monkeypatch.setattr(main.fingerprint_service, "disguise_summary",
                        lambda **kw: {"total_devices": 3, "disguised": 1, "devices": [
                            {"fp_id": "dev-9", "beacons": 5, "n_ua": 2, "n_ip": 2, "n_net": 2,
                             "uas": ["UA-a", "UA-b"], "ips": ["1.1.1.1", "2.2.2.2"],
                             "sites": ["site-001"]}]})

    # graph intel
    monkeypatch.setattr(main.graph_intel, "available", lambda: True)
    monkeypatch.setattr(main.graph_intel, "gnn_available", lambda: False)
    monkeypatch.setattr(main.graph_intel, "gnn_status", lambda: None)
    monkeypatch.setattr(main.graph_intel, "viz_path", lambda: None)
    monkeypatch.setattr(main.graph_intel, "interactive_viz_path", lambda: None)
    monkeypatch.setattr(main.graph_intel, "load_report", lambda: {
        "generated_at": "2026-06-01T00:00:00+00:00",
        "findings": {"n_campaigns": 1, "n_disguised": 0, "n_agentic": 0,
                     "n_contradiction": 0, "n_vm_cohort": 0},
        "meta": {"n_visits": 1, "community_method": "louvain", "graph": {}, "gnn": {}},
        "campaigns": []})

    # querying + provenance
    monkeypatch.setattr(main.querying_service, "available_models", lambda: ["mock/scraper-sim", "mock/honest-llm"])
    monkeypatch.setattr(main.querying_service, "provider_status", lambda: {
        "mock": True, "engine": "auto_query", "openai_internal": False,
        "extractor_provider": "heuristic", "providers_ready": {"gemini": False, "openai": False},
        "openrouter": False, "anthropic": False, "openai_extractor": False,
        "target_provider": "litellm"})
    monkeypatch.setattr(main.querying_service, "runs_summary", lambda: {
        "total_runs": 1, "queries_completed": 2, "matches_found": 1,
        "models_used": ["mock/scraper-sim"], "best_score": 0.8})
    monkeypatch.setattr(main.querying_service, "list_runs", lambda: [_sample_run()])
    monkeypatch.setattr(main.querying_service, "load_run", lambda rid: _sample_run())
    # Provider API-key management + background run manager (their own tests
    # cover the real logic; here we only need the route wiring to work).
    monkeypatch.setattr(main.keys_service, "provider_rows", lambda: [
        {"id": "openai_internal", "kind": "internal", "label": "OpenAI — internal",
         "purpose": "GPT-4.1 processing", "env_var": "OPENAI_API_KEY_INTERNAL",
         "console": "https://example.com", "configured": False, "active_var": None, "masked": ""}])
    monkeypatch.setattr(main.run_manager, "status", lambda rid: {
        "run_id": rid, "present": True, "done": True, "status": "completed",
        "stage": "finished", "stage_label": "Done", "subject": "Jennifer Balef",
        "kind": "detection", "models": [{"model": "mock/scraper-sim", "state": "done"}],
        "error": None, "interrupted": False})
    monkeypatch.setattr(main.provenance_service, "timeline", lambda: [
        {"id": "mock/scraper-sim", "provider": "Mock", "knowledge_cutoff": "2099-12", "available": True}])
    monkeypatch.setattr(main.provenance_service, "default_models", lambda: ["mock/scraper-sim"])
    monkeypatch.setattr(main.provenance_service, "provider_status",
                        lambda: {"anthropic": False, "openrouter": False, "membership_backend": "mock"})
    monkeypatch.setattr(main.provenance_service, "list_reports", lambda: [_sample_report()])
    monkeypatch.setattr(main.provenance_service, "load_report", lambda rid: _sample_report())

    # template generator
    monkeypatch.setattr(main.template_gen, "available_types",
                        lambda: [{"id": "towns", "label": "Towns", "description": "d"}])
    monkeypatch.setattr(main.template_gen, "list_website_templates",
                        lambda: [{"version": 1, "filename": "scraper1.html", "category": "towns"}])
    monkeypatch.setattr(main.template_gen, "current_interpreter", lambda: "python3")

    return main, rendered


def test_all_pages_render_with_the_current_template_set(app_main):
    """Every GET page route returns 200 and renders its current template."""
    main, rendered = app_main
    request = object()

    pages = [
        main.index(request), main.sites_page(request), main.logs_page(request),
        main.query_page(request), main.query_run_detail(request, "run-1"),
        main.provenance_run_detail(request, "prov-1"), main.generator_page(request),
    ]
    assert all(getattr(r, "status_code", 200) == 200 for r in pages)

    names = {name for name, _ in rendered}
    assert names == {
        "index.html", "sites.html", "analytics.html", "forensics.html",
        "run_detail.html", "provenance_detail.html", "generator.html",
    }, f"unexpected template set: {names}"


def test_logs_page_wires_in_traffic_fingerprints_and_campaigns(app_main):
    """The consolidated analytics page carries request rows, the fingerprint KPI
    strip, and the campaign report together."""
    main, rendered = app_main
    main.logs_page(object())
    ctx = dict(rendered)["analytics.html"]
    assert ctx["active_section"] == "traffic"
    assert ctx["data"]["rows"] and ctx["fp"]["fingerprints"] == 12
    assert ctx["available"] is True and ctx["report"]["findings"]["n_campaigns"] == 1
    # The disguise panel's summary rides along on the same page.
    assert ctx["disguise"]["disguised"] == 1


def test_logs_page_clamps_pagination_to_the_service_bounds(app_main, monkeypatch):
    """Hand-edited pagination cannot desync displayed counts from served rows."""
    main, rendered = app_main
    calls = []

    def fetch_requests(**kwargs):
        calls.append(kwargs)
        return {
            "total": 501,
            "last_24h": 1,
            "latest_ts": "2026-06-01T00:00:00+00:00",
            "rows": [],
        }

    monkeypatch.setattr(main.request_log, "fetch_requests", fetch_requests)
    main.logs_page(object(), page=-9, page_size=9999)
    ctx = rendered[-1][1]

    assert calls[0]["page"] == 1 and calls[0]["page_size"] == 500
    assert ctx["filters"]["page"] == 1 and ctx["filters"]["page_size"] == 500
    assert ctx["page_count"] == 2
    assert main._css_version("stale-template-arg") >= 0


def test_forensics_page_merges_detection_and_provenance(app_main):
    """The consolidated forensics page exposes the shared model pool and recent
    detection + provenance investigations."""
    main, rendered = app_main
    main.query_page(object())
    ctx = dict(rendered)["forensics.html"]
    assert ctx["active_section"] == "forensics"
    assert any(m["id"] == "mock/scraper-sim" for m in ctx["models_pool"])
    kinds = {item["kind"] for item in ctx["recent"]}
    assert "Detection" in kinds and ("Provenance" in kinds or "RAG" in kinds)


def test_json_stats_and_csv_export_endpoints(app_main):
    """/api/stats is JSON and /logs/export.csv is CSV with a download disposition."""
    main, _ = app_main
    stats = main.api_stats()
    assert stats.body and stats.media_type == "application/json"
    assert stats.headers["cache-control"] == "no-store, no-cache, must-revalidate, max-age=0"
    assert stats.headers["pragma"] == "no-cache"
    assert stats.headers["expires"] == "0"

    csv_resp = main.logs_export()
    assert csv_resp.media_type == "text/csv"
    assert "attachment" in csv_resp.headers["content-disposition"]

    tmpl = main.site_template(1)
    assert tmpl == "<html>{{ var1 }}</html>"


def test_back_compat_routes_redirect_to_the_merged_pages(app_main):
    """The old standalone pages now redirect into /logs and /query."""
    main, _ = app_main
    assert main.fingerprints_redirect().status_code == 307
    assert main.fingerprints_redirect().headers["location"] == "/logs"
    assert main.intel_redirect().headers["location"] == "/logs"
    assert main.provenance_redirect().headers["location"] == "/query"


def test_deploy_validates_then_redirects(app_main, monkeypatch):
    """Deploy rejects empty required fields and otherwise writes config + redirects."""
    main, _ = app_main

    invalid = main.deploy(site_id="", port="", db_host_port="")
    assert invalid.status_code == 303 and invalid.headers["location"] == "/sites?ok=0"

    calls = []
    monkeypatch.setattr(main.sites, "write_site_config", lambda *a, **k: calls.append((a, k)))
    monkeypatch.setattr(main.sites, "deploy_site", lambda sid, reset_db=False: (True, "ok"))
    ok = main.deploy(site_id="site-x", scraper_version="1", port="8090", genmode="true",
                     db_user="", db_password="", db_host_port="5440", reset_db="")
    assert ok.status_code == 303 and ok.headers["location"] == "/sites?deployed=site-x&ok=1"
    assert calls, "a valid deploy must write the site config"


def test_query_run_starts_a_background_run_and_redirects(app_main, monkeypatch):
    """Submitting a detection run starts it in the background and redirects to
    its live run page (the page then polls /status)."""
    main, _ = app_main
    calls = []
    monkeypatch.setattr(main.run_manager, "start_detection",
                        lambda **k: calls.append(k) or "bg-1")
    resp = main.query_run(mode="custom", url="https://example.com",
                          models=["mock/honest-llm"], max_questions=3, seed="abc")
    assert resp.status_code == 303 and resp.headers["location"] == "/query/runs/bg-1"
    assert calls and calls[0]["models"] == ["mock/honest-llm"]


def test_query_run_status_endpoint_returns_json(app_main):
    """The run page's poller endpoint returns the run_manager status as JSON."""
    main, _ = app_main
    resp = main.query_run_status("bg-1")
    assert resp.media_type == "application/json" and resp.body


def test_query_run_key_mode_gates_live_models(app_main, monkeypatch):
    """The launcher's querying-mode toggle governs which models run: offline
    never touches a provider (live ids fall back to the simulators), and the
    api mode without any key-ready selection is rejected with a banner
    instead of starting a run."""
    main, rendered = app_main
    calls = []
    monkeypatch.setattr(main.run_manager, "start_detection",
                        lambda **k: calls.append(k) or "bg-2")
    monkeypatch.setattr(main.querying_service, "model_ready",
                        lambda m: m.startswith("mock/"))

    # Offline: a submitted live id is dropped; the mock simulators run instead.
    resp = main.query_run(mode="custom", url="https://example.com",
                          models=["openai/gpt-5-search-api"], key_mode="offline",
                          max_questions=3, seed="")
    assert resp.headers["location"] == "/query/runs/bg-2"
    assert calls[0]["models"] == ["mock/scraper-sim", "mock/honest-llm"]

    # API mode with no key-ready model: no run starts, back to the launcher.
    before = len(calls)
    resp = main.query_run(mode="custom", url="https://example.com",
                          models=["openai/gpt-5-search-api"], key_mode="api",
                          max_questions=3, seed="")
    assert resp.status_code == 303 and resp.headers["location"] == "/query#launch"
    assert len(calls) == before, "a rejected model choice must not start a run"

    # ...and the error banner rides the redirect into the page context (once).
    main.query_page(object())
    ctx = rendered[-1][1]
    assert ctx["run_error"] and "API key" in ctx["run_error"]
    main.query_page(object())
    assert rendered[-1][1]["run_error"] is None

    # API mode with a key-ready mix keeps only queryable models.
    resp = main.query_run(mode="custom", url="https://example.com",
                          models=["mock/scraper-sim", "openai/gpt-5-search-api"],
                          key_mode="api", max_questions=3, seed="")
    assert resp.headers["location"] == "/query/runs/bg-2"
    assert calls[-1]["models"] == ["mock/scraper-sim"]


def test_provenance_run_starts_background_probe_and_redirects(app_main, monkeypatch):
    """The provenance/RAG buttons start a background probe and redirect to its
    report page (which polls the status endpoint); the key-mode gate applies."""
    main, _ = app_main
    calls = []
    monkeypatch.setattr(main.provenance_service, "start_provenance",
                        lambda *a, **k: calls.append(("prov", a, k)) or {"run_id": "prov-9"})
    monkeypatch.setattr(main.provenance_service, "start_rag",
                        lambda *a, **k: calls.append(("rag", a, k)) or {"run_id": "rag-9"})

    resp = main.provenance_run(kind="provenance", mode="custom", site_id="",
                               url="https://example.com",
                               models=["mock/scraper-sim"], key_mode="offline",
                               page_removed="", max_questions=3, seed="")
    assert resp.status_code == 303 and resp.headers["location"] == "/provenance/runs/prov-9"
    assert calls[0][0] == "prov" and calls[0][1][3] == ["mock/scraper-sim"]

    resp = main.provenance_run(kind="rag", mode="custom", site_id="",
                               url="https://example.com",
                               models=["mock/scraper-sim"], key_mode="offline",
                               page_removed="1", max_questions=3, seed="")
    assert resp.headers["location"] == "/provenance/runs/rag-9"
    assert calls[1][0] == "rag" and calls[1][2]["page_removed"] is True

    # The report page's poller endpoint returns the service status as JSON.
    monkeypatch.setattr(main.provenance_service, "status", lambda rid: {
        "run_id": rid, "present": True, "status": "running",
        "done": False, "interrupted": False})
    status = main.provenance_run_status("prov-9")
    assert status.media_type == "application/json" and b'"running"' in status.body


def test_run_artifact_download_endpoint(app_main, monkeypatch):
    """/query/runs/{id}/download/{artifact} serves the final results (json/csv)
    and the intermediate stages (prompt, raw responses, extraction) as
    attachments, and 404s for unknown artifacts or runs."""
    main, _ = app_main

    resp = main.query_run_download("run-1", "results")
    assert resp.status_code == 200 and resp.media_type == "application/json"
    assert "attachment" in resp.headers["content-disposition"]
    assert b'"run_id": "run-1"' in resp.body

    csv_resp = main.query_run_download("run-1", "results.csv")
    assert csv_resp.media_type == "text/csv"
    assert b"mock/scraper-sim" in csv_resp.body and b"leak" in csv_resp.body

    prompt = main.query_run_download("run-1", "prompt")
    assert prompt.media_type.startswith("text/plain")
    assert b"ROLE PROMPT" in prompt.body

    raw = main.query_run_download("run-1", "raw_responses")
    ext = main.query_run_download("run-1", "extraction")
    assert raw.status_code == 200 and b"Responses" in raw.body
    assert ext.status_code == 200 and b"extracted_evidence" in ext.body

    assert main.query_run_download("run-1", "bogus").status_code == 404
    monkeypatch.setattr(main.querying_service, "load_run", lambda rid: None)
    assert main.query_run_download("missing", "results").status_code == 404


def test_provider_key_save_and_clear_redirect(app_main, monkeypatch):
    """Saving / clearing a provider key routes through keys_service and redirects."""
    main, _ = app_main
    saved = []
    monkeypatch.setattr(main.keys_service, "set_key", lambda var, val: saved.append((var, val)) or "AI…6789")
    resp = main.query_keys(action="save", env_var="GEMINI_API_KEY", value="secret-key-value")
    assert resp.status_code == 303 and resp.headers["location"] == "/query#keys"
    assert saved == [("GEMINI_API_KEY", "secret-key-value")]

    cleared = []
    monkeypatch.setattr(main.keys_service, "clear_key", lambda var: cleared.append(var))
    main.query_keys(action="clear", env_var="GEMINI_API_KEY", value="")
    assert cleared == ["GEMINI_API_KEY"]


def test_generator_run_starts_background_job_and_redirects(app_main, monkeypatch):
    """The generator route starts a background job (generation runs on a worker
    thread so the page can show a live progress bar) and redirects to its view."""
    main, _ = app_main
    calls = []
    monkeypatch.setattr(main.template_gen, "start_generation",
                        lambda t: calls.append(t) or "job-abc123")
    resp = main.generator_run(template_type="towns")
    assert resp.status_code == 303 and resp.headers["location"] == "/generator?job=job-abc123"
    assert calls == ["towns"]


def test_generator_status_reports_progress_and_stashes_result_on_done(app_main, monkeypatch):
    """The status endpoint returns live progress JSON, and when the job finishes
    copies the full result into _LAST_GEN so the page can reload into the notice."""
    import json
    main, _ = app_main

    # In flight: progress passes through; nothing stashed yet.
    monkeypatch.setattr(main.template_gen, "generation_status", lambda jid: {
        "id": jid, "type": "towns", "status": "running", "done": False,
        "percent": 42.0, "stage": "generating", "label": "[towns] wrote History (1/3)",
        "category": "towns", "output": "line1\nline2", "installed": []})
    main._LAST_GEN.clear()
    body = json.loads(main.generator_status("job-1").body)
    assert body["done"] is False and body["percent"] == 42.0 and body["ok"] is False
    assert body["stage"] == "generating" and body["log"] == "line1\nline2"
    assert main._LAST_GEN == {}, "an in-flight job must not stash a result"

    # Done: type/output/installed are copied out for the ?ok=N reload.
    installed = [{"version": 9, "filename": "scraper9.html", "category": "towns"}]
    monkeypatch.setattr(main.template_gen, "generation_status", lambda jid: {
        "id": jid, "type": "towns", "status": "ok", "done": True, "percent": 100,
        "stage": "done", "label": "Installed 1 template.", "category": "towns",
        "output": "full log", "installed": installed})
    body = json.loads(main.generator_status("job-1").body)
    assert body["done"] is True and body["ok"] is True and body["installed"] == 1
    assert main._LAST_GEN["installed"] == installed and main._LAST_GEN["output"] == "full log"


def test_generator_status_unknown_job_is_terminal(app_main, monkeypatch):
    """An unknown/expired job id returns a terminal 'missing' status so the page
    stops polling instead of spinning forever."""
    import json
    main, _ = app_main
    monkeypatch.setattr(main.template_gen, "generation_status", lambda jid: None)
    body = json.loads(main.generator_status("nope").body)
    assert body["present"] is False and body["done"] is True and body["status"] == "missing"


def test_generator_edit_saves_and_redirects(app_main, monkeypatch):
    """POST /generator/edit routes through save_template, stashes the result for
    the page notice, and redirects back to the editor anchor."""
    main, rendered = app_main
    calls = []
    monkeypatch.setattr(main.template_gen, "save_template",
                        lambda v, html: calls.append((v, html)) or (
                            True, "Saved scraper2.html.",
                            {"version": 2, "filename": "scraper2.html",
                             "canary_slots": [1, 2], "beacon_present": True}))

    resp = main.generator_edit(version=2, html="<html><head></head><body>{{ var1 }}</body></html>")
    # version rides the redirect so the editor reopens on the template just saved.
    assert resp.status_code == 303 and resp.headers["location"] == "/generator?saved=1&version=2#edit"
    assert calls and calls[0][0] == 2

    # The result rides the redirect into the page context (edit_ok/msg/info).
    main.generator_page(object())
    ctx = dict(rendered)["generator.html"]
    assert ctx["edit_ok"] is True and "scraper2.html" in ctx["edit_msg"]
    assert ctx["edit_info"]["canary_slots"] == [1, 2]


def test_generator_edit_failure_redirects_with_saved_zero(app_main, monkeypatch):
    """A rejected edit (bad syntax, unknown version, ...) redirects with saved=0."""
    main, _ = app_main
    monkeypatch.setattr(main.template_gen, "save_template",
                        lambda v, html: (False, "Template has a Jinja syntax error.", {}))
    resp = main.generator_edit(version=1, html="<body>{{ var1 </body>")
    assert resp.status_code == 303 and resp.headers["location"] == "/generator?saved=0&version=1#edit"
