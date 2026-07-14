"""AI Bot Defender — LLM querying pipeline.

Scrapes a honeypot page, generates information-retrieval probes, queries one or
more target LLMs, extracts structured fields from their answers, and compares
those fields against the canary tokens (var1..var10) recorded for the site to
detect whether a model has ingested the page.

The package is import-safe with no API keys configured: the ``mock`` provider
runs the whole pipeline offline so the flow can be demonstrated and tested.
"""

from .pipeline import run_query, QueryRequest  # noqa: F401
from .store import list_runs, load_run, save_run, runs_summary  # noqa: F401
