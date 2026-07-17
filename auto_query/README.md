# `auto_query/` — the detection engine

The engine behind the LLM Forensics page's detection runs: given a honeypot
page and its canary ground truth, compose a retrieval prompt, query target
LLMs, and score their answers for leaked canary tokens.

Vendored from the team's `auto-query-integrate` branch, which was designed to
be embedded in a host application: HTML, the faker template text, and
ground-truth rows are **supplied by the caller**, never loaded from this
package's own disk layout. The host-side caller here is
`app/services/auto_query_adapter.py`.

## Pipelines (`pipelines/`)

```
generate_prompt_pipeline(html, faker_template [, rendered_html])
        |                                  one composed retrieval prompt
        v
api_query_pipeline(artifacts, models)   OR   manual_query_pipeline(records)
        |  LiteLLM per model; mock/* ids       normalize hand-collected
        |  answered by an offline simulator    Model/Responses records
        v
evaluate_pipeline(raw_responses, faker_template, database_rows)
           schema -> LLM content extraction -> matcher_v4 (RapidFuzz)
           -> attribution profiles -> cross-model ranking -> summary
```

## Two LLM roles, both offline-safe

- **Target models** go through LiteLLM (`src/llm_client_litellm.py`): any
  provider = its standard API-key env var + one line in `config/models.py`.
  `mock/scraper-sim` / `mock/honest-llm` are handled by a built-in simulator,
  so the positive/negative demo works with no keys. Provider failures are
  classified (`classify_error`) into auth / quota / rate_limit /
  model_not_found / network / provider_error with human-readable hints.
- **Internal processing** (attribute generation, schema generation, content
  extraction) runs on GPT-4.1 via `src/openai_client.py`
  (`OPENAI_API_KEY_INTERNAL`); with no key each step falls back to a
  deterministic heuristic — which is what the offline test suite exercises.

## Notes

- Run records persist through `querying.store.save_run` as a superset of the
  legacy run format, so the UI, stats, and testsuite keep working unchanged.
- A model counts as a **leak** at coverage ≥ 0.3 (`HIGH_RISK_THRESHOLD`) or ≥2
  canaries recovered from one crawler row.
- Deps (`litellm`, `openai`, `rapidfuzz`, `openpyxl`) install from
  `app/requirements-autoquery.txt` as a late Docker layer.
- Why does `querying/` still exist alongside this package? See
  [`querying/README.md`](../querying/README.md) — it hosts the provenance
  layer, the run store, and the ground-truth loaders this engine reuses.
