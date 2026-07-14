"""auto_query — the retrieval-attribution querying framework (vendored).

Vendored from the ``auto-query-integrate`` branch (commit e2d055dd), which was
designed to be embedded in a host application: HTML, the faker template text,
and ground-truth database rows are supplied by the caller rather than loaded
from disk. This package replaces the detection path of the older ``querying``
package; ``querying`` stays in place for the provenance/membership layer
(Direction 6b), its run store, and its ground-truth loaders, which the app's
adapter (``app/services/auto_query_adapter.py`` — the host-application analogue
of the branch's ``adapters/local_adapter.py``) reuses.

Layout mirrors the branch:

    config/models.py       model registry (display name -> LiteLLM model id)
    pipelines/             the four independent pipelines:
                           prompt -> (api_query | manual_query) -> evaluation
    src/                   parsing, template analysis, attribute/schema
                           generation, LiteLLM + internal-OpenAI clients,
                           extraction, and the RapidFuzz attribution matcher
    manual_io.py           spreadsheet/CSV -> raw_responses normalization
                           (openpyxl-based; replaces convert_manual_responses.py)

Deviations from the branch, all additive / offline-safety:

- imports rewritten to ``auto_query.*`` so the package coexists with
  ``querying`` at the repo root;
- every external LLM call (LiteLLM target querying, internal GPT-4.1
  attribute/schema/extraction) gains a deterministic offline fallback so the
  app demos with no API keys and the testsuite stays offline;
- ``mock/scraper-sim`` / ``mock/honest-llm`` model ids reproduce the
  ``querying.llm_client`` simulators through the new engine;
- spaCy is optional in ``src/parser.py`` (title/heading heuristic otherwise);
- the latent bugs called out during integration are fixed (``gpt-4.1`` model
  id, ``schema_generator`` NameError, ``evaluation_pipeline`` unbound
  ``summary`` when ranking is empty).

The branch's legacy ``src/pipeline.py`` monolith (superseded by ``pipelines/``)
and its disk-layout demo driver (``main.py`` / ``adapters/local_adapter.py``)
are intentionally not vendored.
"""
