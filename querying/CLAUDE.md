# `querying/` — LLM querying pipeline

## Purpose

This package tests whether a target LLM can reproduce the **canary tokens**
(`var1`..`var10`) a honeypot site assigned to its visitors. If a model's answer
overlaps a stored canary set, that is evidence the model ingested the page.

It is the integrated, refactored successor to the old standalone
`auto-querying/` prototype (which was hardcoded to a single Duke profile, used
LangChain, printed to stdout, and persisted nothing). It is an importable
package and runnable as a CLI.

> **Status:** the web app's `/query` detection UI now runs on the vendored
> **`auto_query/`** engine (see the root `CLAUDE.md`), driven by
> `app/services/auto_query_adapter.py`. This package remains load-bearing for
> the **provenance/membership layer** (Direction 6b), the **run store**
> (`store.py` — auto_query runs persist through it, as a superset of the run
> record described below) and the **ground-truth loaders** (`ground_truth.py`)
> the adapter reuses, plus this CLI. Do not delete or repurpose those seams.

> Authorized testing only — run against systems, models, pages, and datasets you
> are permitted to test.

## Run it

From the **repository root** (so `querying` imports as a package):

```bash
# Offline demo — no API keys. Scrape any URL, match against the bundled sample CSV:
python -m querying.main --url https://example.com/ --models mock/scraper-sim mock/honest-llm

# Against a locally-deployed honeypot site, through the reverse proxy:
python -m querying.main --site site-001 --db-name scraper1-db --db-user user \
    --models mock/scraper-sim
```

## Pipeline (`pipeline.run_query`)

```
parser.parser(url, host_header)   scrape page (1 request; optional Host header for proxy
        |                          routing; spaCy NER if installed, else title/heading heuristic)
        v
prompt_generator.generate_probes  adversarial role prompt + retrieval questions (seedable)
        v
ground_truth.load_*               canary rows from the site DB (docker) or a CSV
        v
llm_client.llm_responses          query each target model (provider chosen by id prefix)
        v
extractor.extract_info            normalize each answer into list-valued evidence fields
        v
matcher.matcher                   exact-set Jaccard of evidence vs. var1..var10 per row
        v
store.save_run                    persist one JSON per run under querying/runs/ (git-ignored)
```

## Providers (offline-safe)

Target models are routed by **id prefix** — no API key needed for the mock path:

| Model id | Behaviour |
|---|---|
| `mock/scraper-sim` | Simulates a model that ingested the page: leaks the site's canary tokens (a positive detection). |
| `mock/honest-llm` | Simulates a model that never saw the page: generic answer, no leak. |
| `openrouter/<model>` | OpenRouter's OpenAI-compatible API (`OPENROUTER_API_KEY`). |
| `anthropic/<model>` | Anthropic Messages API (`ANTHROPIC_API_KEY`); default model `claude-fable-5`. |
| any other `<provider>/<model>` | Routed through **LiteLLM** (the auto_query registry ids, e.g. `gemini/...`, `openai/...`) with that provider's standard env-var key. A failure **raises into a per-question error — never falls back to the mock**, because the leak-simulating mock answer would fabricate ingestion evidence for a real model. |

The **extractor** is a separate role (`QUERY_EXTRACTOR_PROVIDER` = `mock` / `openai` /
`anthropic`). Keep the target-vs-extractor distinction.

## Contracts to preserve

- Matching scores only **list-valued** extractor fields against **`var1`..`var10`**.
- `parser` returns at least `main_idea` (+ `top_anchors`); `generate_probes` needs `main_idea`.
- `llm_responses` returns `{model: [{"question","answer"} | {"question","error"}]}`.
- A run record (see `store.py`) is the unit the web app reads for history + stats.

## Files

| File | Role |
|---|---|
| `pipeline.py` | Orchestrator + `QueryRequest` dataclass. |
| `parser.py` | Scrape a page → structured record (spaCy optional). |
| `prompt_generator.py` | Role prompt + elicitation questions. |
| `llm_client.py` | Query target models (mock / openrouter / anthropic). |
| `extractor.py` | Normalize answers into structured evidence. |
| `matcher.py` | Jaccard match of evidence vs. canary tokens. |
| `ground_truth.py` | Load canary rows from a site DB (docker) or CSV. |
| `store.py` | Persist / list runs; aggregate stats. |
| `config.py` | Paths, providers, defaults (all env-overridable). |
| `main.py` | CLI entry point. |
| `model_timeline.py` | Model id → knowledge-cutoff registry (Direction 6b); override via `configs/model_timeline.yaml`. |
| `provenance.py` | Crawl-to-train latency / ingestion-window analyzer + CLI (`python -m querying.provenance`). |
| `membership.py` | Min-K%/Min-K%++ membership inference: served vs. never-served watermark controls → p-value (backends: mock / hf / openai). |
| `rag_disambiguation.py` | Training-memorization vs. live-retrieval experiment (browsing off/on + `all_visits` correlation) + CLI. |
| `jeniffer.csv`, `21.csv`, `21.xlsx` | Bundled sample ground-truth datasets. |
| `create_csv.py` | Regenerates `21.csv` from `21.xlsx` (import has a side effect — don't import it). |

## Dependencies

`querying/requirements.txt`: `requests`, `beautifulsoup4`, `httpx`. spaCy is **optional**
(`pip install spacy && python -m spacy download en_core_web_sm`) — without it the parser
derives the subject from the page title/headings instead of NER.
