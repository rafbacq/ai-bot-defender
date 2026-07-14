"""Provider API-key management for the auto_query engine.

The industry-standard way keys reach the containerized app is environment
variables: ``docker-compose.app.yml`` passes each one through, and Docker
Compose natively substitutes them from the **project-root ``.env``** (which is
git-ignored). This service makes that file manageable from the dashboard:

- ``provider_rows()`` reports, per provider, whether a key is configured (and
  a masked preview) — after a ``refresh_env()`` so a key dropped into ``.env``
  by hand shows up without a restart.
- ``set_key`` / ``clear_key`` edit the root ``.env`` **and** the live process
  environment, so a saved key takes effect on the very next run. The engine
  additionally re-reads ``.env`` before every real query (``refresh_env``),
  which also covers multi-process setups.

Only the allowlisted provider variables (``WRITABLE_KEY_VARS``) can be
written — the endpoint can never be used to set arbitrary environment
variables. Values are single-line and stored only in the git-ignored file.
"""

import os
import re
import stat

from auto_query.config.models import (
    KEY_PROVIDERS,
    WRITABLE_KEY_VARS,
    refresh_env,
)

from .. import config


class KeyError_(ValueError):
    """Raised for invalid key-management requests (bad var name / value)."""


def _env_path():
    return config.PROJECT_ROOT / ".env"


def mask(value):
    """A safe preview of a secret: first 3 + last 4 chars for long keys."""
    if not value:
        return ""
    value = str(value)
    if len(value) <= 8:
        return "•" * len(value)
    return f"{value[:3]}…{value[-4:]}"


def provider_rows():
    """Per-provider status rows for the Provider API keys card."""
    refresh_env()
    rows = []
    for provider in KEY_PROVIDERS:
        active_var = None
        # Manual-only chatbots have no env_var; skip the falsy entry so
        # ``os.environ.get`` is never handed an empty/None key.
        for var in [provider["env_var"], *provider["alt_vars"]]:
            if var and os.environ.get(var):
                active_var = var
                break
        rows.append({
            "id": provider["id"],
            "kind": provider["kind"],
            "access": provider.get("access", "api"),
            "chatbot": provider.get("chatbot", provider["label"]),
            "publisher": provider.get("publisher", ""),
            "label": provider["label"],
            "purpose": provider["purpose"],
            "env_var": provider["env_var"],
            "console": provider["console"],
            "configured": active_var is not None,
            "active_var": active_var,
            "masked": mask(os.environ.get(active_var, "")) if active_var else "",
        })
    return rows


def _validate(env_var, value=None):
    if env_var not in WRITABLE_KEY_VARS:
        raise KeyError_(f"'{env_var}' is not a recognized provider key variable.")
    if value is not None:
        if "\n" in value or "\r" in value:
            raise KeyError_("API keys must be a single line.")
        if len(value) > 512:
            raise KeyError_("That value is too long to be an API key.")


def _write_env_lines(lines):
    path = _env_path()
    text = "\n".join(lines).rstrip("\n")
    path.write_text(text + "\n" if text else "", encoding="utf-8")
    try:  # keys file: owner read/write only (best-effort on bind mounts)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _upsert_line(env_var, value):
    """Replace the ``VAR=...`` line in .env (or append), preserving the rest."""
    path = _env_path()
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    pattern = re.compile(rf"^\s*(export\s+)?{re.escape(env_var)}\s*=")
    replaced = False
    out = []
    for line in lines:
        if pattern.match(line):
            if value is not None and not replaced:
                out.append(f"{env_var}={value}")
                replaced = True
            # value None (clear) or a duplicate line: drop it
            continue
        out.append(line)
    if value is not None and not replaced:
        out.append(f"{env_var}={value}")
    _write_env_lines(out)


def set_key(env_var, value):
    """Save a provider key to the project .env and the live environment."""
    value = (value or "").strip()
    _validate(env_var, value)
    if not value:
        raise KeyError_("The key value is empty — use Clear to remove a key.")
    _upsert_line(env_var, value)
    os.environ[env_var] = value
    return mask(value)


def clear_key(env_var):
    """Remove a provider key from the project .env and the live environment."""
    _validate(env_var)
    _upsert_line(env_var, None)
    os.environ.pop(env_var, None)
