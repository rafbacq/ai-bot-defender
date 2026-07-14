"""Model-version timeline: model id -> knowledge-cutoff date.

The provenance analyzer probes successive model versions and, from *which*
versions reproduce a canary, bounds when the content entered training. That needs
each queryable model's knowledge cutoff.

The built-in defaults below are **approximate and self-reported** by the
providers — knowledge cutoff is not the same as the data-collection cutoff, and
models are sometimes trained on later data. Treat the inferred ingestion windows
as bounds, not points. Override / extend the list with a YAML or JSON file at
``configs/model_timeline.yaml`` (or ``$QUERY_MODEL_TIMELINE``); entries there are
merged over the defaults by model id.

Each entry: ``{id, provider, knowledge_cutoff: "YYYY-MM", release: "YYYY-MM",
available: bool, notes}``. ``id`` uses the same provider-prefixed form the
querying ``llm_client`` routes on and the auto_query registry uses
(``anthropic/...``, ``gemini/...``, ``mock/...``).
"""

import os
from datetime import date
from pathlib import Path

from . import config

# Approximate, provider-reported knowledge cutoffs. EDIT/extend via the override
# file — these are seed values, deliberately conservative, and clearly fuzzy.
DEFAULT_TIMELINE = [
    {"id": "mock/honest-llm", "provider": "Mock", "knowledge_cutoff": "2023-01",
     "release": "2024-01", "available": True, "notes": "offline simulator (never ingests)"},
    {"id": "mock/scraper-sim", "provider": "Mock", "knowledge_cutoff": "2099-12",
     "release": "2024-01", "available": True, "notes": "offline simulator (always 'ingested')"},

    # The auto_query detection registry's ids (the launcher shares one model
    # pool), so a provenance probe over those models can bound windows too, and
    # the model picker shows each provider + cutoff. Cutoffs are approximate and
    # provider-reported — override via configs/model_timeline.yaml. An older
    # Claude version is kept alongside the current one for version-probing.
    {"id": "anthropic/claude-3-5-sonnet-20241022", "provider": "Anthropic",
     "knowledge_cutoff": "2024-04", "release": "2024-10", "available": True,
     "notes": "approximate cutoff; kept for provenance version-probing"},
    {"id": "anthropic/claude-sonnet-4-5-20250929", "provider": "Anthropic",
     "knowledge_cutoff": "2025-03", "release": "2025-09", "available": True,
     "notes": "approximate cutoff"},
    {"id": "openai/gpt-5-search-api", "provider": "OpenAI",
     "knowledge_cutoff": "2024-09", "release": "2025-08", "available": True,
     "notes": "approximate cutoff; search-enabled — answers may include live "
              "retrieval (see the RAG experiment)"},
    {"id": "gemini/gemini-2.5-flash", "provider": "Google",
     "knowledge_cutoff": "2025-01", "release": "2025-06", "available": True,
     "notes": "approximate cutoff"},
    {"id": "xai/grok-3", "provider": "xAI",
     "knowledge_cutoff": "2024-11", "release": "2025-02", "available": True,
     "notes": "approximate cutoff"},
    {"id": "deepseek/deepseek-chat", "provider": "DeepSeek",
     "knowledge_cutoff": "2024-07", "release": "2024-12", "available": True,
     "notes": "approximate cutoff"},
    {"id": "mistral/mistral-large-latest", "provider": "Mistral",
     "knowledge_cutoff": "2024-07", "release": "2024-11", "available": True,
     "notes": "approximate cutoff"},
    {"id": "perplexity/sonar", "provider": "Perplexity",
     "knowledge_cutoff": "2024-10", "release": "2025-01", "available": True,
     "notes": "approximate cutoff; search-enabled — answers may include live retrieval"},
    {"id": "dashscope/qwen-plus", "provider": "Alibaba",
     "knowledge_cutoff": "2024-09", "release": "2025-01", "available": True,
     "notes": "approximate cutoff"},
    {"id": "meta_llama/Llama-3.3-70B-Instruct", "provider": "Meta",
     "knowledge_cutoff": "2024-12", "release": "2024-12", "available": True,
     "notes": "approximate cutoff"},
    {"id": "moonshot/moonshot-v1-8k", "provider": "Moonshot AI",
     "knowledge_cutoff": "2024-06", "release": "2024-08", "available": True,
     "notes": "approximate cutoff"},
    {"id": "zai/glm-4.7", "provider": "Z.AI",
     "knowledge_cutoff": "2024-10", "release": "2025-04", "available": True,
     "notes": "approximate cutoff"},
    {"id": "amazon_nova/nova-pro-v1", "provider": "Amazon",
     "knowledge_cutoff": "2024-10", "release": "2024-12", "available": True,
     "notes": "approximate cutoff"},
]


def _cutoff_date(value):
    """Parse a 'YYYY-MM' (or 'YYYY-MM-DD') cutoff to a date (first of month)."""
    if not value:
        return None
    parts = str(value).split("-")
    try:
        year = int(parts[0])
        month = int(parts[1]) if len(parts) > 1 else 1
        day = int(parts[2]) if len(parts) > 2 else 1
        return date(year, month, day)
    except (ValueError, IndexError):
        return None


def _load_overrides():
    """Load the optional override file ({id: {...}} or a list of entries)."""
    path = Path(os.environ.get("QUERY_MODEL_TIMELINE", "")) or None
    if not path:
        path = config.PROJECT_ROOT / "configs" / "model_timeline.yaml"
    if not path.exists():
        alt = config.PROJECT_ROOT / "configs" / "model_timeline.json"
        path = alt if alt.exists() else path
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            import yaml  # pyyaml or ruamel both expose safe_load via this name? use ruamel
            try:
                from ruamel.yaml import YAML
                data = YAML(typ="safe").load(text)
            except Exception:
                import yaml as _pyyaml
                data = _pyyaml.safe_load(text)
        else:
            import json
            data = json.loads(text)
    except Exception:
        return []
    if isinstance(data, dict):
        return [{"id": k, **(v or {})} for k, v in data.items()]
    return data or []


def timeline():
    """Return the merged timeline (defaults + overrides), each with a parsed date."""
    merged = {entry["id"]: dict(entry) for entry in DEFAULT_TIMELINE}
    for entry in _load_overrides():
        if not entry.get("id"):
            continue
        merged.setdefault(entry["id"], {}).update(entry)
    out = []
    for entry in merged.values():
        entry["cutoff_date"] = _cutoff_date(entry.get("knowledge_cutoff"))
        out.append(entry)
    return out


def cutoff_for(model_id):
    for entry in timeline():
        if entry["id"] == model_id:
            return entry.get("cutoff_date")
    return None


def sorted_by_cutoff(model_ids=None):
    """Return timeline entries (optionally filtered to ``model_ids``), oldest cutoff first."""
    entries = timeline()
    if model_ids is not None:
        wanted = set(model_ids)
        entries = [e for e in entries if e["id"] in wanted]
    return sorted(entries, key=lambda e: (e.get("cutoff_date") or date.max))
