"""Model registry for the auto_query engine.

``KEY_PROVIDERS`` below is the **single source of truth**: one row per provider
the LLM Forensics page knows about (the internal-processing key + the client's
22 studied chatbots). ``MODELS`` (display name -> LiteLLM ``<provider>/<model>``
id), ``PROVIDER_KEY_VARS`` (provider prefix -> unlocking env vars) and
``WRITABLE_KEY_VARS`` are all **derived** from it, so a chatbot's model id, the
key its card writes, the readiness badge, and the variable LiteLLM reads can
never drift apart. Adding a chatbot = one ``KEY_PROVIDERS`` row.
See https://docs.litellm.ai/docs/providers for each provider's id + key var.

The two ``mock/*`` entries are an integration addition: they are handled by the
offline simulator in ``src/llm_client_litellm.py`` (never sent to LiteLLM) so
the whole engine runs with no API keys — ``mock/scraper-sim`` leaks the site's
canary tokens (a positive detection end to end), ``mock/honest-llm`` does not.

Key loading: LiteLLM and the internal OpenAI client both read their keys from
the process environment (each provider's standard variable name). In the
containerized app the compose file passes those variables through — but they
are declared with empty defaults, so a key that arrives *after* the container
started (or that lives only in the project ``.env``) would be invisible.
``refresh_env()`` closes that gap: it re-reads the project-root ``.env`` and
fills any variable that is unset **or empty** (a genuinely-set shell/compose
value still wins). It is called before every provider-readiness check and
before every real model query, so keys saved to ``.env`` while the app is
running take effect immediately — no restart.
"""

import os
from pathlib import Path

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]   # auto_query/


def _project_root():
    return Path(os.environ.get("PROJECT_ROOT", _PACKAGE_ROOT.parent))


def refresh_env():
    """Fill unset-or-empty env vars from the project-root ``.env`` (if any).

    Mirrors the semantics documented in ``querying/config.py``: compose injects
    declared-but-empty variables, and python-dotenv's default ``load_dotenv``
    refuses to replace a present var — so we parse the file ourselves and only
    fill variables whose current value is missing or empty.
    """
    env_path = _project_root() / ".env"
    if not env_path.is_file():
        return
    try:
        from dotenv import dotenv_values

        for key, value in dotenv_values(env_path).items():
            if value and not os.environ.get(key):
                os.environ[key] = value
    except Exception:
        pass  # optional convenience — shell/compose env still works without it


# The offline positive/negative controls — always available, never keyed.
MOCK_MODELS = {
    "Mock scraper (offline)": "mock/scraper-sim",
    "Mock honest LLM (offline)": "mock/honest-llm",
}

# Everything the key-management UI + live model picker need, per provider. This
# is the source of truth for the LLM Forensics "Provider API keys" card AND the
# model registry. Each row carries:
#   ``id``        stable slug (used by tests + the row key)
#   ``kind``      "internal" = the engine's own GPT-4.1 processing steps ·
#                 "target"   = a chatbot we probe for canary leaks
#   ``access``    "internal" · "api" (a key unlocks live querying; the row is
#                 registered in MODELS) · "manual" (no public API — evaluated by
#                 hand on the Manual evaluation card; no key field, not in MODELS)
#   ``chatbot`` / ``publisher``   the client's Table-1 naming (also the picker label)
#   ``prefix`` / ``model``   the LiteLLM ``<prefix>/<model>`` id (api rows only)
#   ``env_var`` / ``alt_vars``    the variable(s) written / counted as configured
#                 (LiteLLM's standard names, so readiness == live-query auth)
#   ``console``   where to obtain the key
# Additive: to register a new chatbot, add a row — MODELS + PROVIDER_KEY_VARS
# pick it up automatically.
#
# NOTE on the two OpenAI rows: they are intentionally distinct. ``openai_internal``
# (OPENAI_API_KEY_INTERNAL) powers the engine's internal extraction; ``openai``
# (OPENAI_API_KEY) is the ChatGPT *target* model. They may hold the same or
# different keys — the UI groups them apart so they don't look like a duplicate.
#
# ``verified`` marks providers confirmed against LiteLLM's provider docs (native
# prefix + key var). ``best-effort`` rows are wired the same way, but LiteLLM's
# native support / single-key auth is unconfirmed — a live query may return a
# classified "model unavailable" until the id/creds are adjusted here.
KEY_PROVIDERS = [
    # --- Detection engine (internal processing) -----------------------------
    {
        "id": "openai_internal", "kind": "internal", "access": "internal",
        "chatbot": "Internal processing (GPT-4.1)", "publisher": "OpenAI",
        "label": "OpenAI — internal processing", "prefix": "", "model": "",
        "purpose": "Powers attribute/schema generation + evidence extraction. "
                   "Without it, deterministic offline heuristics run instead.",
        "env_var": "OPENAI_API_KEY_INTERNAL", "alt_vars": [],
        "console": "https://platform.openai.com/api-keys",
    },

    # --- Target chatbots with a direct API (verified against LiteLLM docs) ---
    {
        "id": "openai", "kind": "target", "access": "api",
        "chatbot": "ChatGPT", "publisher": "OpenAI", "label": "ChatGPT",
        "prefix": "openai", "model": "gpt-5-search-api",
        "purpose": "OpenAI ChatGPT / GPT search target models.",
        "env_var": "OPENAI_API_KEY", "alt_vars": [],
        "console": "https://platform.openai.com/api-keys",
    },
    {
        "id": "anthropic", "kind": "target", "access": "api",
        "chatbot": "Claude", "publisher": "Anthropic", "label": "Claude",
        "prefix": "anthropic", "model": "claude-sonnet-4-5-20250929",
        "purpose": "Anthropic Claude target models (also the provenance layer).",
        "env_var": "ANTHROPIC_API_KEY", "alt_vars": [],
        "console": "https://console.anthropic.com/settings/keys",
    },
    {
        "id": "gemini", "kind": "target", "access": "api",
        "chatbot": "Gemini", "publisher": "Google", "label": "Gemini",
        "prefix": "gemini", "model": "gemini-2.5-flash",
        "purpose": "Google Gemini target models.",
        "env_var": "GEMINI_API_KEY", "alt_vars": ["GOOGLE_API_KEY"],
        "console": "https://aistudio.google.com/apikey",
    },
    {
        "id": "xai", "kind": "target", "access": "api",
        "chatbot": "Grok", "publisher": "xAI", "label": "Grok",
        "prefix": "xai", "model": "grok-3",
        "purpose": "xAI Grok target models.",
        "env_var": "XAI_API_KEY", "alt_vars": [],
        "console": "https://console.x.ai",
    },
    {
        "id": "deepseek", "kind": "target", "access": "api",
        "chatbot": "Deepseek", "publisher": "DeepSeek", "label": "Deepseek",
        "prefix": "deepseek", "model": "deepseek-chat",
        "purpose": "DeepSeek target models.",
        "env_var": "DEEPSEEK_API_KEY", "alt_vars": [],
        "console": "https://platform.deepseek.com/api_keys",
    },
    {
        "id": "mistral", "kind": "target", "access": "api",
        "chatbot": "Mistral", "publisher": "Mistral", "label": "Mistral",
        "prefix": "mistral", "model": "mistral-large-latest",
        "purpose": "Mistral AI target models.",
        "env_var": "MISTRAL_API_KEY", "alt_vars": [],
        "console": "https://console.mistral.ai/api-keys",
    },
    {
        "id": "perplexity", "kind": "target", "access": "api",
        "chatbot": "Perplexity", "publisher": "Perplexity", "label": "Perplexity",
        "prefix": "perplexity", "model": "sonar",
        "purpose": "Perplexity Sonar target models.",
        "env_var": "PERPLEXITYAI_API_KEY", "alt_vars": ["PERPLEXITY_API_KEY"],
        "console": "https://www.perplexity.ai/account/api/keys",
    },
    {
        "id": "qwen", "kind": "target", "access": "api",
        "chatbot": "Qwen", "publisher": "Alibaba", "label": "Qwen",
        "prefix": "dashscope", "model": "qwen-plus",
        "purpose": "Alibaba Qwen (DashScope) target models.",
        "env_var": "DASHSCOPE_API_KEY", "alt_vars": [],
        "console": "https://bailian.console.alibabacloud.com/",
    },
    {
        "id": "meta", "kind": "target", "access": "api",
        "chatbot": "Llama", "publisher": "Meta", "label": "Llama",
        "prefix": "meta_llama", "model": "Llama-3.3-70B-Instruct",
        "purpose": "Meta Llama API target models.",
        "env_var": "LLAMA_API_KEY", "alt_vars": [],
        "console": "https://llama.developer.meta.com/",
    },
    {
        "id": "moonshot", "kind": "target", "access": "api",
        "chatbot": "Kimi", "publisher": "Moonshot AI", "label": "Kimi",
        "prefix": "moonshot", "model": "moonshot-v1-8k",
        "purpose": "Moonshot AI Kimi target models.",
        "env_var": "MOONSHOT_API_KEY", "alt_vars": [],
        "console": "https://platform.moonshot.ai/console/api-keys",
    },
    {
        "id": "zai", "kind": "target", "access": "api",
        "chatbot": "GLM", "publisher": "Z.AI", "label": "GLM",
        "prefix": "zai", "model": "glm-4.7",
        "purpose": "Z.AI / Zhipu GLM target models.",
        "env_var": "ZAI_API_KEY", "alt_vars": ["ZHIPUAI_API_KEY"],
        "console": "https://z.ai/manage-apikey/apikey-list",
    },
    {
        "id": "amazon", "kind": "target", "access": "api",
        "chatbot": "Nova", "publisher": "Amazon", "label": "Nova",
        "prefix": "amazon_nova", "model": "nova-pro-v1",
        "purpose": "Amazon Nova target models.",
        "env_var": "AMAZON_NOVA_API_KEY", "alt_vars": [],
        "console": "https://console.aws.amazon.com/bedrock/",
    },

    # --- Target chatbots wired best-effort (LiteLLM support unconfirmed) -----
    {
        "id": "upstage", "kind": "target", "access": "api",
        "chatbot": "Solar", "publisher": "Upstage", "label": "Solar",
        "prefix": "upstage", "model": "solar-pro",
        "purpose": "Upstage Solar target models.",
        "env_var": "UPSTAGE_API_KEY", "alt_vars": [],
        "console": "https://console.upstage.ai/api-keys",
    },
    {
        "id": "reka", "kind": "target", "access": "api",
        "chatbot": "Reka", "publisher": "Reka", "label": "Reka",
        "prefix": "reka", "model": "reka-core",
        "purpose": "Reka AI target models.",
        "env_var": "REKA_API_KEY", "alt_vars": [],
        "console": "https://platform.reka.ai/",
    },
    {
        "id": "baidu", "kind": "target", "access": "api",
        "chatbot": "ERNIE", "publisher": "Baidu", "label": "ERNIE",
        "prefix": "baidu", "model": "ernie-4.0-8k",
        "purpose": "Baidu ERNIE (Qianfan) target models.",
        "env_var": "BAIDU_API_KEY", "alt_vars": [],
        "console": "https://console.bce.baidu.com/qianfan/",
    },
    {
        "id": "ibm", "kind": "target", "access": "api",
        "chatbot": "Granite", "publisher": "IBM", "label": "Granite",
        "prefix": "watsonx", "model": "ibm/granite-3-8b-instruct",
        "purpose": "IBM Granite via watsonx.ai (also needs WATSONX_URL + project).",
        "env_var": "WATSONX_APIKEY", "alt_vars": [],
        "console": "https://cloud.ibm.com/iam/apikeys",
    },
    {
        "id": "tencent", "kind": "target", "access": "api",
        "chatbot": "Hunyuan", "publisher": "Tencent", "label": "Hunyuan",
        "prefix": "hunyuan", "model": "hunyuan-pro",
        "purpose": "Tencent Hunyuan target models.",
        "env_var": "HUNYUAN_API_KEY", "alt_vars": [],
        "console": "https://console.cloud.tencent.com/hunyuan",
    },
    {
        "id": "liquid", "kind": "target", "access": "api",
        "chatbot": "Liquid", "publisher": "Liquid AI", "label": "Liquid",
        "prefix": "liquid", "model": "lfm-40b",
        "purpose": "Liquid AI (LFM) target models.",
        "env_var": "LIQUID_API_KEY", "alt_vars": [],
        "console": "https://platform.liquid.ai/",
    },
    {
        "id": "stepfun", "kind": "target", "access": "api",
        "chatbot": "Step-3", "publisher": "StepFun", "label": "Step-3",
        "prefix": "stepfun", "model": "step-2-16k",
        "purpose": "StepFun Step target models.",
        "env_var": "STEPFUN_API_KEY", "alt_vars": [],
        "console": "https://platform.stepfun.com/",
    },
    {
        "id": "venice", "kind": "target", "access": "api",
        "chatbot": "Venice", "publisher": "Venice", "label": "Venice",
        "prefix": "venice", "model": "venice-uncensored",
        "purpose": "Venice AI target models.",
        "env_var": "VENICE_API_KEY", "alt_vars": [],
        "console": "https://venice.ai/settings/api",
    },

    # --- Target chatbots without a public API (Manual evaluation only) -------
    {
        "id": "copilot", "kind": "target", "access": "manual",
        "chatbot": "Copilot", "publisher": "Microsoft", "label": "Copilot",
        "prefix": "", "model": "",
        "purpose": "No public consumer API — run it on the Manual evaluation card.",
        "env_var": "", "alt_vars": [],
        "console": "https://copilot.microsoft.com/",
    },
    {
        "id": "duckai", "kind": "target", "access": "manual",
        "chatbot": "Duck.ai", "publisher": "DuckDuckGo", "label": "Duck.ai",
        "prefix": "", "model": "",
        "purpose": "No public API — run it on the Manual evaluation card.",
        "env_var": "", "alt_vars": [],
        "console": "https://duck.ai/",
    },
]


# --- Derived registries (do not hand-edit; change KEY_PROVIDERS instead) -----

# Display name -> LiteLLM id. Mock simulators first (offline controls), then
# every API-access chatbot in KEY_PROVIDERS order.
MODELS = dict(MOCK_MODELS)
for _p in KEY_PROVIDERS:
    if _p["access"] == "api" and _p["prefix"] and _p["model"]:
        MODELS[_p["chatbot"]] = f'{_p["prefix"]}/{_p["model"]}'

# LiteLLM provider prefix -> the env var(s) that unlock it. Derived so the
# readiness badge always reflects the exact variable the key card writes and
# LiteLLM reads. ``mock`` needs no key. (Unknown-prefix ids -> ``provider_ready``
# returns None, i.e. "may work, no local key gate".)
PROVIDER_KEY_VARS = {"mock": []}
for _p in KEY_PROVIDERS:
    if _p["access"] == "api" and _p["prefix"]:
        PROVIDER_KEY_VARS[_p["prefix"]] = [
            v for v in [_p["env_var"], *_p["alt_vars"]] if v
        ]

# The only env vars the key-management endpoint is allowed to write. Manual-only
# chatbots contribute no variable (their ``env_var`` is empty).
WRITABLE_KEY_VARS = sorted(
    {p["env_var"] for p in KEY_PROVIDERS if p["env_var"]}
    | {var for p in KEY_PROVIDERS for var in p["alt_vars"]}
    | {"OPENAI_API_BASE_INTERNAL"}
)


def provider_of(model_id):
    """The LiteLLM provider prefix of a model id (``gemini/x`` -> ``gemini``)."""
    return model_id.split("/", 1)[0] if "/" in model_id else model_id


def provider_ready(model_id):
    """True when the model's provider needs no key or one of its keys is set."""
    refresh_env()
    key_vars = PROVIDER_KEY_VARS.get(provider_of(model_id))
    if key_vars is None:
        return None  # unknown provider — LiteLLM may still support it
    return not key_vars or any(os.environ.get(var) for var in key_vars)
