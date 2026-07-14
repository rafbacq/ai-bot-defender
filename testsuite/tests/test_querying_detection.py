"""LLM detection pipeline (querying/): scrape -> probe -> extract -> match.

Verifies the end-to-end offline detection path and each of its stages:

  * ``llm_client`` mock providers — ``scraper-sim`` regurgitates the page's canary
    tokens (a positive detection), ``honest-llm`` never does (the negative control).
  * ``prompt_generator`` — builds a seeded, reproducible role prompt + probes from
    the scraped subject.
  * ``extractor`` + ``matcher`` — normalize an answer into evidence and score the
    exact-set Jaccard against ``var1``..``var10``, ignoring ``"Null"`` slots.
  * ``ground_truth`` — load the bundled CSV + pick a leak candidate row.
  * ``pipeline.run_query`` — ties it together and reports the leak verdict.

All offline: ``parser``/ground-truth are stubbed so no network or DB is touched.
"""

from __future__ import annotations

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


# --- llm_client mock providers ---------------------------------------------
def test_mock_providers_leak_vs_stay_clean():
    """scraper-sim weaves the leak candidates into its answer; honest-llm does not."""
    from querying.llm_client import llm_responses

    context = {"subject": "Jennifer Balef", "leak_candidates": CANARY_VALUES}
    answers = llm_responses(["mock/scraper-sim", "mock/honest-llm"],
                            ("role prompt", ["Tell me everything about Jennifer Balef."]),
                            context=context)
    sim = answers["mock/scraper-sim"][0]["answer"]
    honest = answers["mock/honest-llm"][0]["answer"]

    leaked = [v for v in CANARY_VALUES if v in sim]
    assert len(leaked) >= 5, "scraper-sim should regurgitate most canary tokens"
    assert not any(v in honest for v in CANARY_VALUES), "honest-llm must not leak canaries"


# --- prompt_generator ------------------------------------------------------
def test_probe_generation_is_subject_specific_and_reproducible():
    from querying.prompt_generator import generate_probes

    record = {"main_idea": "Jennifer Balef", "top_anchors": ["Biography"]}
    role1, probes1 = generate_probes(record, max_questions=4, seed=11)
    role2, probes2 = generate_probes(record, max_questions=4, seed=11)

    assert (role1, probes1) == (role2, probes2), "same seed must be reproducible"
    assert len(probes1) == 4
    assert all("Jennifer Balef" in q for q in probes1), "probes must target the subject"

    with pytest.raises(ValueError):
        generate_probes({"top_anchors": []}, max_questions=2)


# --- extractor + matcher ---------------------------------------------------
def test_extractor_and_matcher_score_overlap_correctly():
    from querying.extractor import extract_info
    from querying.matcher import flatten_row, matcher

    row = _canary_row()
    # An answer that bullets out 8 of the 10 canary values.
    answer = "\n".join(f"- {v}" for v in CANARY_VALUES[:8])
    extracted = extract_info(answer)
    result = matcher(extracted, row)

    # 8 evidence items, all in the 10-value row -> Jaccard = 8 / 10.
    assert result["jaccard_score"] == pytest.approx(0.8)
    assert len(result["matches"]) == 8
    assert result["jaccard_score"] >= 0.3  # crosses the leak threshold

    # A disjoint answer scores zero.
    clean = matcher(extract_info("- Paris\n- London\n- 2024"), row)
    assert clean["jaccard_score"] == 0.0

    # "Null" canary slots never count as evidence.
    nulled = dict(row, var3="Null", var4="null")
    assert "null" not in flatten_row(nulled)


# --- ground_truth ----------------------------------------------------------
def test_ground_truth_loads_bundled_csv_and_picks_leak_candidates():
    from querying import config as q_config
    from querying.ground_truth import load_csv_rows, pick_leak_candidates

    rows = load_csv_rows(q_config.SAMPLE_GROUND_TRUTH)
    assert rows, "bundled sample ground-truth CSV should have rows"
    assert all("var1" in r for r in rows), "rows must carry var columns"

    candidates = pick_leak_candidates([_canary_row()], prefer_user_agent="AIBotDefender-Probe/1.0")
    assert candidates == CANARY_VALUES  # exact var1..var10, no Nulls
    assert pick_leak_candidates([]) == []


# --- Full pipeline ---------------------------------------------------------
def test_pipeline_detects_a_leak_and_clears_the_negative_control(monkeypatch):
    """End to end: scraper-sim is reported as a confirmed leak, honest-llm is not."""
    from querying import pipeline

    row = _canary_row()
    monkeypatch.setattr(pipeline, "parser",
                        lambda *a, **k: {"main_idea": "Jennifer Balef", "top_anchors": ["Bio"]})
    monkeypatch.setattr(pipeline, "_load_ground_truth", lambda req: ([row], "synthetic:1 row"))

    run = pipeline.run_query(pipeline.QueryRequest(
        target_url="http://127.0.0.1/",
        models=["mock/scraper-sim", "mock/honest-llm"],
        max_questions=4, seed=11, persist=False,
    ))

    assert run["status"] == "completed"
    assert run["subject"] == "Jennifer Balef"
    assert run["summary"]["models_tested"] == 2
    assert run["summary"]["matches_found"] == 1
    by_model = {r["model"]: r for r in run["results"]}
    assert by_model["mock/scraper-sim"]["leaked"] is True
    assert by_model["mock/scraper-sim"]["best_match"]["jaccard_score"] >= 0.3
    assert by_model["mock/honest-llm"]["leaked"] is False


def test_pipeline_records_a_failure_when_the_page_cannot_be_scraped(monkeypatch):
    """A page that yields no subject fails the run with an explanatory error, not a crash."""
    from querying import pipeline

    monkeypatch.setattr(pipeline, "parser", lambda *a, **k: {})
    run = pipeline.run_query(pipeline.QueryRequest(
        target_url="http://127.0.0.1/", models=["mock/scraper-sim"], persist=False,
    ))
    assert run["status"] == "failed"
    assert "scrape" in (run["error"] or "").lower()
