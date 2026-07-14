"""Live API querying support: key management, error classification, background runs.

Covers the pieces added so the app can query real models via LiteLLM with keys
managed from the dashboard, report provider failures clearly, and run
investigations in the background with a live-updating run page — all offline:

  * ``classify_error`` — maps provider exceptions to auth / quota (credits) /
    rate-limit / model-not-found / network / generic kinds with hints.
  * ``refresh_env`` — fills unset/empty env vars from the project ``.env`` so a
    saved key is picked up with no restart (a set shell value still wins).
  * ``keys_service`` — round-trips a key through the git-ignored ``.env`` +
    process env, masks it, and refuses non-allowlisted variables.
  * ``run_manager`` — starts a run on a worker thread, exposes live per-model
    progress, persists via ``querying.store``, and flags interrupted runs.
  * ``api_query_pipeline`` — fires the live-progress callbacks and attaches a
    classified error to a failed model.
  * ``store.save_run`` — is atomic (no half-written file for a concurrent reader).
"""

from __future__ import annotations

import time

import pytest


# --- error classification ---------------------------------------------------
def test_classify_error_buckets_provider_failures():
    from auto_query.src.llm_client_litellm import ERROR_KIND_LABELS, classify_error

    cases = {
        "auth": Exception("AuthenticationError: Incorrect API key provided"),
        "quota": Exception("Error code: 429 - insufficient_quota: exceeded your current quota"),
        "rate_limit": Exception("RateLimitError: Rate limit reached, try again later"),
        "model_not_found": Exception("NotFoundError: The model `gemini/x` does not exist"),
        "network": Exception("APIConnectionError: Connection timed out"),
        "provider_error": Exception("something entirely unexpected"),
    }
    for expected_kind, exc in cases.items():
        kind, hint = classify_error(exc)
        assert kind == expected_kind, (expected_kind, kind, exc)
        assert hint and isinstance(hint, str)
        assert kind in ERROR_KIND_LABELS

    # Quota beats rate-limit even though both are 429 — "out of credits" is the
    # actionable answer.
    assert classify_error(Exception("429 insufficient_quota rate limit"))[0] == "quota"


# --- .env refresh -----------------------------------------------------------
def test_refresh_env_fills_unset_and_empty_vars(tmp_path, monkeypatch):
    from auto_query.config import models as aq_models

    env = tmp_path / ".env"
    env.write_text("GEMINI_API_KEY=from-dotenv\nOPENAI_API_KEY=should-not-win\n")
    monkeypatch.setenv("PROJECT_ROOT", str(tmp_path))

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "shell-wins")  # genuinely set → preserved
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")         # present but empty → filled? no file entry

    aq_models.refresh_env()
    import os
    assert os.environ["GEMINI_API_KEY"] == "from-dotenv"   # was unset → filled
    assert os.environ["OPENAI_API_KEY"] == "shell-wins"    # set → not overwritten


# --- keys_service -----------------------------------------------------------
@pytest.fixture
def keys(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from app import config as app_config
    from app.services import keys_service

    monkeypatch.setattr(app_config, "PROJECT_ROOT", tmp_path)
    # Start from a clean environment for the managed vars.
    for var in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY_INTERNAL"):
        monkeypatch.delenv(var, raising=False)
    return keys_service, tmp_path


def test_keys_service_round_trips_through_dotenv(keys, monkeypatch):
    import os

    keys_service, root = keys
    masked = keys_service.set_key("GEMINI_API_KEY", "gemini-secret-1234567")
    assert "…" in masked and "gemini-secret-1234567" not in masked
    env_text = (root / ".env").read_text()
    assert "GEMINI_API_KEY=gemini-secret-1234567" in env_text
    assert os.environ["GEMINI_API_KEY"] == "gemini-secret-1234567"  # live env updated

    rows = {r["id"]: r for r in keys_service.provider_rows()}
    assert rows["gemini"]["configured"] is True and rows["gemini"]["masked"] == masked

    # Editing another key preserves the first.
    keys_service.set_key("OPENAI_API_KEY_INTERNAL", "sk-internal-abcdefgh")
    env_text = (root / ".env").read_text()
    assert "GEMINI_API_KEY=gemini-secret-1234567" in env_text
    assert "OPENAI_API_KEY_INTERNAL=sk-internal-abcdefgh" in env_text

    keys_service.clear_key("GEMINI_API_KEY")
    assert "GEMINI_API_KEY" not in (root / ".env").read_text()
    assert os.environ.get("GEMINI_API_KEY") is None
    # The unrelated key is untouched.
    assert "OPENAI_API_KEY_INTERNAL=sk-internal-abcdefgh" in (root / ".env").read_text()


def test_keys_service_rejects_unlisted_vars_and_bad_values(keys):
    keys_service, _ = keys
    with pytest.raises(keys_service.KeyError_):
        keys_service.set_key("PATH", "/evil")               # not a provider key var
    with pytest.raises(keys_service.KeyError_):
        keys_service.set_key("GEMINI_API_KEY", "line1\nline2")  # multi-line
    with pytest.raises(keys_service.KeyError_):
        keys_service.set_key("GEMINI_API_KEY", "")           # empty → use clear instead


# --- api_query_pipeline callbacks + classified error ------------------------
def test_api_query_pipeline_reports_progress_and_classified_errors(monkeypatch):
    from auto_query.pipelines import api_query_pipeline as aqp

    def fake_query_model(model, role, prompt, context=None):
        if "bad" in model:
            return {"question": prompt, "answer": "", "error": "API key problem (openai): fix it",
                    "error_kind": "auth", "error_detail": "AuthenticationError"}
        return {"question": prompt, "answer": "ok"}

    monkeypatch.setattr(aqp, "query_model", fake_query_model)

    started, done = [], []
    raw = aqp.api_query_pipeline(
        {"role_prompt": "r", "prompt": "p"},
        {"good": "openai/good", "bad": "openai/bad"},
        on_query=lambda m: started.append(m),
        on_result=lambda m, item: done.append((m, "Error" in item)),
    )
    assert started == ["good", "bad"]
    assert done == [("good", False), ("bad", True)]
    by_model = {r["Model"]: r for r in raw}
    assert by_model["good"]["Responses"] == "ok" and "Error" not in by_model["good"]
    assert by_model["bad"]["ErrorKind"] == "auth"
    assert by_model["bad"]["ErrorDetail"] == "AuthenticationError"


# --- store atomicity --------------------------------------------------------
def test_save_run_is_atomic(tmp_path, monkeypatch):
    from querying import config as q_config
    from querying import store

    monkeypatch.setattr(q_config, "RUNS_DIR", tmp_path / "runs")
    run = {"run_id": "r-1", "status": "completed", "results": []}
    path = store.save_run(run)
    assert path.exists()
    # No temp/partial files linger, and the round-trip is clean.
    assert list((tmp_path / "runs").glob("*.tmp")) == []
    assert store.load_run("r-1")["status"] == "completed"
    # A missing / unreadable file yields None, never raises.
    assert store.load_run("does-not-exist") is None


# --- run_manager background lifecycle ---------------------------------------
def test_run_manager_runs_in_background_with_live_progress(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from app.services import auto_query_adapter as aqa
    from app.services import run_manager
    from querying import config as q_config

    monkeypatch.setattr(q_config, "RUNS_DIR", tmp_path / "runs")

    TEMPLATE_HTML = ("<html><head><title>About Jennifer Balef</title></head>"
                     "<body><h1>About Jennifer Balef</h1>"
                     "<p>Born in {{ var2 }} in {{ var3 }}.</p></body></html>")
    faker = "\n".join(["fake.first_name_female()", "fake.city()", "fake.year()"])
    row = {"user_agent": "AIBotDefender-Probe/1.0",
           **{f"var{i}": v for i, v in enumerate(
               ["Maribel Quince", "North Alder", "1888", "West Cobalt", "Ravenfield Institute",
                "Lake Vesper", "Copper Manor", "Juniper Archive", "Orchid Bridge", "Silver Lantern"], 1)}}
    inputs = aqa._Inputs(template_html=TEMPLATE_HTML, rendered_html=TEMPLATE_HTML,
                         faker_template=faker, rows=[row], source="synthetic:1",
                         target_url="http://proxy/", host_header="h", site_id="site-001")
    monkeypatch.setattr(aqa, "_resolve_inputs", lambda **kw: inputs)

    run_id = run_manager.start_detection(
        site_id="site-001", models=["mock/scraper-sim", "mock/honest-llm"])
    assert run_id

    # Poll like the run page does.
    for _ in range(100):
        status = run_manager.status(run_id)
        if status["done"]:
            break
        time.sleep(0.05)
    assert status["present"] and status["done"] and status["status"] == "completed"
    model_states = {m["model"]: m["state"] for m in status["models"]}
    assert model_states == {"mock/scraper-sim": "done", "mock/honest-llm": "done"}

    # Persisted through querying.store with the full results.
    from querying.store import load_run
    record = load_run(run_id)
    assert record["status"] == "completed"
    assert {r["model"] for r in record["results"]} == {"mock/scraper-sim", "mock/honest-llm"}


def test_run_manager_flags_an_interrupted_run(tmp_path, monkeypatch):
    """A persisted record still marked 'running' with no live worker (the app
    restarted mid-run) is reported done+interrupted, so the page won't spin."""
    pytest.importorskip("fastapi")
    from app.services import run_manager
    from querying import config as q_config
    from querying.store import save_run

    monkeypatch.setattr(q_config, "RUNS_DIR", tmp_path / "runs")
    save_run({"run_id": "stuck-1", "status": "running", "models": ["mock/scraper-sim"],
              "subject": "X", "results": []})
    status = run_manager.status("stuck-1")
    assert status["present"] and status["done"] and status["interrupted"]
    assert status["status"] == "failed"


def test_run_manager_missing_run_is_reported_absent(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from app.services import run_manager
    from querying import config as q_config

    monkeypatch.setattr(q_config, "RUNS_DIR", tmp_path / "runs")
    status = run_manager.status("nope")
    assert status["present"] is False and status["done"] is True
