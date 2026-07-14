"""auto_query detection engine: prompt -> query -> evaluate -> attribute.

Verifies the vendored attribution framework end to end on its offline paths
(no API keys, no LiteLLM, no network) and the dashboard adapter's run-record
mapping the web app depends on:

  * ``matcher_v4`` — exact, containment, and fuzzy (>=95) matching against
    ``var1``..``var10`` rows, per-crawler attribution profiles.
  * mock simulators through ``api_query_pipeline`` — ``mock/scraper-sim``
    leaks the canary set (positive detection), ``mock/honest-llm`` stays clean.
  * ``evaluate_pipeline`` — schema, extraction, profile compression, cross-
    model ranking, and a summary that is built even when nothing matched.
  * offline fallbacks — deterministic schema/attribute/extraction heuristics
    when ``OPENAI_API_KEY_INTERNAL`` is unset, spaCy-free subject parsing.
  * ``auto_query_adapter`` — maps the engine output onto the legacy-superset
    run record (``results[].best_match.{bot,matches,jaccard_score}``,
    ``summary.{models_tested,matches_found,best_score,ground_truth_rows,
    threshold}``) and persists via ``querying.store``.
  * ``manual_io`` + ``manual_query_pipeline`` — spreadsheet/CSV uploads
    normalize into the same raw_responses shape and evaluate identically.
"""

from __future__ import annotations

import io

import pytest

pytest.importorskip("rapidfuzz", reason="auto_query needs rapidfuzz")

CANARY_VALUES = [
    "Maribel Quince", "North Alder", "1888", "West Cobalt", "Ravenfield Institute",
    "Lake Vesper", "Copper Manor", "Juniper Archive", "Orchid Bridge", "Silver Lantern",
]

FAKER_TEMPLATE = "\n".join([
    "fake.first_name_female() + ' ' + fake.last_name()",
    "fake.city()",
    "fake.year()",
    "fake.city()",
    "fake.institution_name()",
    "fake.city()",
    "fake.last_name() + '-' + fake.last_name()",
    "fake.last_name() + '-' + fake.last_name()",
    "fake.last_name() + '-' + fake.last_name()",
    "fake.last_name() + '-' + fake.last_name()",
])

TEMPLATE_HTML = """<html><head><title>About Jennifer Balef</title></head>
<body><h1>About Jennifer Balef</h1>
<p>Jennifer was born in {{ var2 }} in {{ var3 }}.</p>
<h2>Education</h2><p>She studied at {{ var5 }}, near {{ var4 }}.</p>
<p>Her partner {{ var1 }} lives in {{ var6 }}.</p>
<p>Works: {{ var7 }}, {{ var8 }}, {{ var9 }}, {{ var10 }}.</p>
</body></html>"""


def _canary_row(user_agent="AIBotDefender-Probe/1.0", **overrides):
    row = {"user_agent": user_agent}
    for i, value in enumerate(CANARY_VALUES, 1):
        row[f"var{i}"] = value
    row.update(overrides)
    return row


@pytest.fixture(autouse=True)
def _no_internal_key(monkeypatch):
    """Force the offline heuristics: the internal GPT-4.1 key must be unset."""
    monkeypatch.delenv("OPENAI_API_KEY_INTERNAL", raising=False)


# --- matcher_v4 --------------------------------------------------------------
def test_matcher_scores_exact_containment_and_fuzzy_matches():
    """Exact, containment (canary inside a longer string) and >=95 fuzzy
    variants all count as recovered canaries; unrelated rows produce nothing."""
    from auto_query.src.matcher_v4 import compare_row_v4, matcher_v4

    row = _canary_row()
    evidence = [
        "Maribel Quince",                       # exact
        "the Ravenfield Institute main campus", # containment
        "Lake Vespers",                         # fuzzy (1 char off, ratio >= 95)
        "Paris",                                # noise
    ]
    result = compare_row_v4(evidence, row)
    assert result["hit_count"] == 3
    assert "maribel quince" in result["matches"]
    assert "ravenfield institute" in result["matches"]
    assert "lake vesper" in result["matches"]
    assert result["coverage"] == pytest.approx(0.3)
    assert result["bot"] == "AIBotDefender-Probe/1.0"

    # The profile keeps every row with evidence, best first — and drops
    # zero-hit rows entirely.
    other = _canary_row(user_agent="OtherBot/2.0", var1="Zinnia Falworth")
    clean = {"user_agent": "CleanBot/3.0", **{f"var{i}": f"unrelated {i}" for i in range(1, 11)}}
    profile = matcher_v4(evidence, [other, row, clean])
    assert [p["bot"] for p in profile] == ["AIBotDefender-Probe/1.0", "OtherBot/2.0"]

    # A row with zero hits assigns no bot.
    assert compare_row_v4(["nothing relevant"], row)["bot"] is None


# --- mock simulators through the API query pipeline -------------------------
def test_mock_models_leak_vs_stay_clean_through_the_pipeline():
    """scraper-sim regurgitates the leak candidates; honest-llm never does —
    all without litellm or any key."""
    from auto_query.pipelines.api_query_pipeline import api_query_pipeline

    artifacts = {"role_prompt": "role", "prompt": "Tell me about Jennifer Balef."}
    context = {"subject": "Jennifer Balef", "leak_candidates": CANARY_VALUES}
    raw = api_query_pipeline(
        artifacts,
        {"mock/scraper-sim": "mock/scraper-sim", "mock/honest-llm": "mock/honest-llm"},
        context=context,
    )
    by_model = {item["Model"]: item["Responses"] for item in raw}
    leaked = [v for v in CANARY_VALUES if v in by_model["mock/scraper-sim"]]
    assert len(leaked) >= 5, "scraper-sim should regurgitate most canary tokens"
    assert not any(v in by_model["mock/honest-llm"] for v in CANARY_VALUES)


# --- offline fallbacks (prompt pipeline) -------------------------------------
def test_prompt_pipeline_builds_a_subject_targeted_prompt_offline():
    """No spaCy/keys needed: the subject comes from the title/h1 heuristic, the
    template analysis finds all 10 variables, and the composed prompt carries
    the subject + inferred attribute categories."""
    from auto_query.pipelines.prompt_pipeline import generate_prompt_pipeline

    artifacts = generate_prompt_pipeline(TEMPLATE_HTML, FAKER_TEMPLATE)
    assert artifacts["website_record"]["main_idea"] == "Jennifer Balef"
    assert artifacts["template_analysis"]["variable_count"] == 10
    assert artifacts["attributes"], "offline attribute heuristic must yield categories"
    assert "Jennifer Balef" in artifacts["prompt"]
    assert artifacts["faker_template"] == FAKER_TEMPLATE

    # Deterministic: same inputs, same outputs.
    again = generate_prompt_pipeline(TEMPLATE_HTML, FAKER_TEMPLATE)
    assert again["attributes"] == artifacts["attributes"]
    assert again["prompt"] == artifacts["prompt"]


def test_prompt_pipeline_uses_rendered_html_for_var_titled_templates():
    """A template whose title is a {{ varN }} placeholder has no subject; the
    rendered page (as a visitor sees it) supplies it instead."""
    from auto_query.pipelines.prompt_pipeline import generate_prompt_pipeline
    from auto_query.src.prompt_generator import generate_probes

    var_titled = TEMPLATE_HTML.replace("About Jennifer Balef", "{{ var1 }}")
    rendered = TEMPLATE_HTML.replace("About Jennifer Balef", "Maribel Quince")

    artifacts = generate_prompt_pipeline(var_titled, FAKER_TEMPLATE, rendered_html=rendered)
    assert artifacts["website_record"]["main_idea"] == "Maribel Quince"

    with pytest.raises(ValueError):
        generate_probes({"main_idea": None}, ["location"])


# --- evaluation pipeline ------------------------------------------------------
def test_evaluation_attributes_the_leaky_model_and_ranks_it_first():
    from auto_query.pipelines.evaluation_pipeline import evaluate_pipeline

    leak_answer = "\n".join(f"- {v}" for v in CANARY_VALUES[:8])
    raw = [
        {"Model": "leaky", "Responses": leak_answer},
        {"Model": "honest", "Responses": "I have no verified records about this subject."},
    ]
    result = evaluate_pipeline(raw, FAKER_TEMPLATE, [_canary_row()])

    # Offline schema: one entry per faker expression.
    assert len(result["schema"]["variables"]) == 10

    leaky = result["attribution_profiles"]["leaky"]
    assert leaky and leaky[0]["hit_count"] == 8
    assert leaky[0]["coverage"] == pytest.approx(0.8)
    assert result["attribution_profiles"]["honest"] == []

    assert [entry["model"] for entry in result["ranking"]] == ["leaky", "honest"]
    assert result["ranking"][0]["hits"] == 8
    assert result["ranking"][1]["top_bot"] is None

    assert "ATTRIBUTION SUMMARY" in result["summary"]
    assert "Strong Attribution" in result["summary"]


def test_evaluation_survives_a_run_with_no_matches_at_all():
    """The summary is still produced when no model recovered anything (this
    exact case left ``summary`` unbound on the branch)."""
    from auto_query.pipelines.evaluation_pipeline import evaluate_pipeline

    raw = [{"Model": "honest", "Responses": "Nothing relevant here."}]
    result = evaluate_pipeline(raw, FAKER_TEMPLATE, [_canary_row()])
    assert result["attribution_profiles"]["honest"] == []
    assert result["ranking"][0]["coverage"] == 0
    assert "ATTRIBUTION SUMMARY" in result["summary"]


# --- manual workflow ----------------------------------------------------------
def test_manual_responses_load_from_csv_and_xlsx_and_evaluate_identically():
    """Spreadsheet rows normalize into the canonical raw_responses shape and
    run through the same evaluation as API-acquired responses."""
    from auto_query.manual_io import ManualResponsesError, load_manual_responses
    from auto_query.pipelines.evaluation_pipeline import evaluate_pipeline
    from auto_query.pipelines.manual_query_pipeline import manual_query_pipeline

    leak_answer = "; ".join(CANARY_VALUES[:4])
    csv_bytes = (
        "Model,Responses\nERNIE,\"" + leak_answer + "\"\nKimi,No idea.\n"
    ).encode()
    records = load_manual_responses(csv_bytes, "responses.csv")
    assert [r["Model"] for r in records] == ["ERNIE", "Kimi"]

    openpyxl = pytest.importorskip("openpyxl", reason="xlsx path needs openpyxl")
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.append(["Model", "Responses"])
    sheet.append(["ERNIE", leak_answer])
    buffer = io.BytesIO()
    workbook.save(buffer)
    xlsx_records = load_manual_responses(buffer.getvalue(), "responses.xlsx")
    assert xlsx_records[0] == {"Model": "ERNIE", "Responses": leak_answer}

    result = evaluate_pipeline(
        manual_query_pipeline(records), FAKER_TEMPLATE, [_canary_row()]
    )
    assert result["attribution_profiles"]["ERNIE"][0]["hit_count"] == 4
    assert result["attribution_profiles"]["Kimi"] == []

    with pytest.raises(ManualResponsesError):
        load_manual_responses(b"Wrong,Columns\na,b\n", "bad.csv")
    with pytest.raises(ManualResponsesError):
        load_manual_responses(b"", "empty.csv")


# --- dashboard adapter --------------------------------------------------------
@pytest.fixture
def adapter(monkeypatch, tmp_path):
    """The adapter with its host seams stubbed: no site config, DB, or proxy.

    Ground truth and page HTML are synthesized; runs persist into a temp dir so
    ``querying.store`` round-trips are exercised for real.
    """
    pytest.importorskip("fastapi")  # app.services siblings import it transitively
    from app.services import auto_query_adapter as aqa
    from querying import config as q_config

    rendered = TEMPLATE_HTML  # scraper1-style: concrete title, so no scrape needed
    inputs = aqa._Inputs(
        template_html=TEMPLATE_HTML,
        rendered_html=rendered,
        faker_template=FAKER_TEMPLATE,
        rows=[_canary_row()],
        source="synthetic:1 row",
        target_url="http://proxy/",
        host_header="site-001.localhost",
        site_id="site-001",
    )
    monkeypatch.setattr(aqa, "_resolve_inputs", lambda **kw: inputs)
    monkeypatch.setattr(q_config, "RUNS_DIR", tmp_path / "runs")
    return aqa


def test_adapter_produces_a_legacy_superset_run_record(adapter):
    """The persisted record keeps every key the UI/stats read from the old
    engine and adds the attribution profile / ranking / summary on top."""
    from querying.store import load_run

    run = adapter.run_detection(
        site_id="site-001", models=["mock/scraper-sim", "mock/honest-llm"]
    )

    assert run["status"] == "completed"
    assert run["kind"] == "detection" and run["engine"] == "auto_query"
    assert run["subject"] == "Jennifer Balef"
    assert run["role_prompt"] and len(run["questions"]) == 1

    by_model = {r["model"]: r for r in run["results"]}
    sim = by_model["mock/scraper-sim"]
    honest = by_model["mock/honest-llm"]

    # Legacy contract: best_match.{bot, matches, jaccard_score} + leaked.
    assert sim["leaked"] is True
    assert sim["best_match"]["bot"] == "AIBotDefender-Probe/1.0"
    assert sim["best_match"]["jaccard_score"] >= 0.3
    assert sim["best_match"]["matches"]
    assert honest["leaked"] is False and honest["best_match"] is None

    # New: the full per-crawler attribution profile rides along.
    assert sim["attribution_profile"][0]["hit_count"] >= 2
    assert honest["attribution_profile"] == []

    summary = run["summary"]
    assert summary["models_tested"] == 2
    assert summary["matches_found"] == 1
    assert summary["best_score"] >= 0.3
    assert summary["ground_truth_rows"] == 1
    assert summary["threshold"] == pytest.approx(0.3)
    assert summary["ranking"][0]["model"] == "mock/scraper-sim"
    assert "ATTRIBUTION SUMMARY" in summary["attribution_summary"]

    # Persisted through querying.store, so history/stats see it.
    assert load_run(run["run_id"])["run_id"] == run["run_id"]


def test_adapter_manual_evaluation_matches_the_api_path(adapter):
    records = [
        {"Model": "ERNIE", "Responses": "\n".join(f"- {v}" for v in CANARY_VALUES[:6])},
        {"Model": "Meta AI", "Responses": "Nothing to report."},
    ]
    run = adapter.run_manual_evaluation(site_id="site-001", records=records)

    assert run["status"] == "completed" and run["kind"] == "manual"
    assert run["models"] == ["ERNIE", "Meta AI"]
    by_model = {r["model"]: r for r in run["results"]}
    assert by_model["ERNIE"]["leaked"] is True
    assert by_model["Meta AI"]["leaked"] is False
    assert run["summary"]["matches_found"] == 1


def test_adapter_reports_ground_truth_failures_in_the_run_record(adapter, monkeypatch):
    """A missing site/DB fails the run with an explanatory error, not a crash."""
    from querying.ground_truth import GroundTruthError

    def _boom(**kwargs):
        raise GroundTruthError("Site 'site-404' is not deployed.")

    monkeypatch.setattr(adapter, "_resolve_inputs", _boom)
    run = adapter.run_detection(site_id="site-404", models=["mock/scraper-sim"])
    assert run["status"] == "failed"
    assert "not deployed" in run["error"]


def test_adapter_runs_feed_the_existing_stats_aggregation(adapter):
    """querying.store.runs_summary (the landing-page stats source) aggregates
    the new records without modification."""
    from querying.store import runs_summary

    adapter.run_detection(site_id="site-001",
                          models=["mock/scraper-sim", "mock/honest-llm"])
    summary = runs_summary()
    assert summary["total_runs"] == 1
    assert summary["queries_completed"] == 2
    assert summary["matches_found"] == 1
    assert summary["best_score"] >= 0.3
    assert "mock/scraper-sim" in summary["models_used"]


# --- querying_service: key-mode model choice + downloadable artifacts ----------
def test_resolve_model_choice_gates_live_models_on_keys(monkeypatch):
    """The launcher's querying-mode toggle: offline never touches a provider
    (live ids are dropped, mocks are the fallback); api keeps mock ids plus
    key-ready live ids and errors when nothing queryable remains."""
    pytest.importorskip("fastapi")  # app.services siblings import it transitively
    from app.services import querying_service as qs

    monkeypatch.setattr(qs, "model_ready",
                        lambda m: qs.is_mock(m) or m == "gemini/with-key")

    chosen, err = qs.resolve_model_choice("offline", ["gemini/with-key", "mock/honest-llm"])
    assert err is None and chosen == ["mock/honest-llm"]

    chosen, err = qs.resolve_model_choice("offline", ["gemini/with-key"])
    assert err is None and chosen == ["mock/scraper-sim", "mock/honest-llm"]

    chosen, err = qs.resolve_model_choice(
        "api", ["gemini/with-key", "openai/no-key", "mock/scraper-sim"])
    assert err is None and chosen == ["gemini/with-key", "mock/scraper-sim"]

    chosen, err = qs.resolve_model_choice("api", ["openai/no-key"])
    assert chosen == [] and "API key" in err

    chosen, err = qs.resolve_model_choice("api", [])
    assert chosen == [] and err


def test_run_artifacts_expose_finals_and_intermediates(adapter):
    """run_artifact() serves the final results (full record json + per-model
    csv) and the intermediate stages (prompt, raw responses, extraction) that
    the run page keeps out of the inline view — from a real adapter record."""
    import json

    from app.services import querying_service as qs

    run = adapter.run_detection(
        site_id="site-001", models=["mock/scraper-sim", "mock/honest-llm"]
    )

    name, media, content = qs.run_artifact(run, "results")
    assert name.endswith("-results.json") and media == "application/json"
    assert json.loads(content)["run_id"] == run["run_id"]

    name, media, content = qs.run_artifact(run, "results.csv")
    assert name.endswith("-results.csv") and media == "text/csv"
    assert "mock/scraper-sim" in content and ",leak," in content

    name, media, content = qs.run_artifact(run, "prompt")
    assert name.endswith("-prompt.txt")
    assert "ROLE PROMPT" in content and run["questions"][0] in content

    name, media, content = qs.run_artifact(run, "raw_responses")
    items = json.loads(content)
    assert {i["Model"] for i in items} == {"mock/scraper-sim", "mock/honest-llm"}
    assert all("Responses" in i for i in items)

    name, media, content = qs.run_artifact(run, "extraction")
    payload = json.loads(content)
    assert "schema" in payload and "extracted_evidence" in payload
    assert payload["extracted_evidence"]["mock/scraper-sim"]

    assert qs.run_artifact(run, "not-an-artifact") is None
    # A manual run has no generated prompt to offer — that artifact is absent.
    manual = adapter.run_manual_evaluation(
        site_id="site-001",
        records=[{"Model": "ERNIE", "Responses": "Nothing to report."}],
    )
    manual.pop("role_prompt", None)
    manual["questions"] = []
    assert qs.run_artifact(manual, "prompt") is None
    assert qs.run_artifact(manual, "results") is not None
