"""Shared fixtures + helpers for the AI Bot Defender test suite.

Every test runs **offline** and **deterministically**: no Docker daemon, no
Postgres, no model API keys, no network. External seams (the host Docker CLI, the
logdb/site psql calls, the Ansible playbook, model providers) are monkeypatched,
and traffic is synthesized in-process (see ``synthetic.py``). The only "real"
things exercised are the project's own modules — the canary generators, the
User-Agent parser, the crawler-graph clustering pipeline, the consistency engine,
the querying/provenance logic, and the FastAPI routes.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

# Repository root = two levels up from this file (testsuite/tests/conftest.py).
# Deliberately NOT resolved through symlinks: this environment is a WSL/Docker
# bind mount whose canonical hash path can rotate, so we keep the path the suite
# was invoked through and make every layer agree on it.
REPO_ROOT = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
WEBSITE_DIR = REPO_ROOT / "website"

# Make the project importable (app / querying / crawler_graph live at the root)
# and keep the app's PROJECT_ROOT on the same path the imports resolve through.
for _path in (str(REPO_ROOT),):
    if _path not in sys.path:
        sys.path.insert(0, _path)
os.environ.setdefault("PROJECT_ROOT", str(REPO_ROOT))


def load_module_from_path(name: str, path: Path):
    """Import a standalone .py file (e.g. the proxy collectors) by absolute path."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def website_on_path():
    """Put ``website/`` on sys.path so its top-level modules import like server.py
    does (``from user_agent_info import parse_user_agent``)."""
    added = False
    if str(WEBSITE_DIR) not in sys.path:
        sys.path.insert(0, str(WEBSITE_DIR))
        added = True
    try:
        yield WEBSITE_DIR
    finally:
        if added and str(WEBSITE_DIR) in sys.path:
            sys.path.remove(str(WEBSITE_DIR))


@pytest.fixture
def isolated_app_config(tmp_path, monkeypatch):
    """Point ``app.config`` at a throwaway project tree.

    Lets the site-configurator and template-generator services read/write config,
    render templates, and append history without ever touching the real
    ``configs/sites`` / ``ansible/group_vars/all.yml`` / ``website/templates``.
    """
    from app import config

    root = tmp_path / "project"
    ansible = root / "ansible"
    website = root / "website"
    templates = website / "templates"
    proxy_conf = root / "proxy" / "conf.d"
    sites_cfg = root / "configs" / "sites"
    history = root / "configs" / "history"
    generator = root / "template_generator"

    for path in (ansible / "group_vars", templates, proxy_conf, sites_cfg, history, generator):
        path.mkdir(parents=True, exist_ok=True)

    all_yml = ansible / "group_vars" / "all.yml"
    all_yml.write_text(
        """
scraper_version: 1
website:
  port: 8080
  genmode: true
database:
  user: user
  password: password
  host_port: 5432
proxy:
  base_domain: dukecodeplus.example
  local_base_domain: dukecodeplus.localhost
""".lstrip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(config, "PROJECT_ROOT", root)
    monkeypatch.setattr(config, "ANSIBLE_DIR", ansible)
    monkeypatch.setattr(config, "ALL_YML", all_yml)
    monkeypatch.setattr(config, "WEBSITE_DIR", website)
    monkeypatch.setattr(config, "TEMPLATES_DIR", templates)
    monkeypatch.setattr(config, "TEMPLATE_GENERATOR_DIR", generator)
    monkeypatch.setattr(config, "PROXY_COMPOSE", root / "docker-compose.proxy.yml")
    monkeypatch.setattr(config, "PROXY_CONF_D", proxy_conf)
    monkeypatch.setattr(config, "CONFIGS_DIR", root / "configs")
    monkeypatch.setattr(config, "SITES_CONFIG_DIR", sites_cfg)
    monkeypatch.setattr(config, "HISTORY_DIR", history)
    monkeypatch.setattr(config, "USERS_DB", root / "configs" / "users.db")

    return {
        "root": root,
        "ansible": ansible,
        "website": website,
        "templates": templates,
        "proxy_conf": proxy_conf,
        "sites_cfg": sites_cfg,
        "history": history,
        "users_db": root / "configs" / "users.db",
        "generator": generator,
        "all_yml": all_yml,
    }


# --- Test doubles for the database / HTTP seams ----------------------------
class DummyCursor:
    """Records every ``execute(sql, params)`` call for assertions."""

    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))


class DummyConn:
    """A psycopg2-shaped connection whose cursor records calls into ``calls``."""

    closed = False

    def __init__(self, calls):
        self.calls = calls

    def cursor(self):
        return DummyCursor(self.calls)

    def close(self):
        self.closed = True


class FakeURL:
    def __init__(self, path, query=""):
        self.path = path
        self.query = query


class FakeRequest:
    """Minimal Starlette-Request stand-in for the proxy collector handlers."""

    def __init__(self, *, method="GET", path="/", query="", headers=None, body=b""):
        self.method = method
        self.url = FakeURL(path, query)
        self.headers = headers or {}
        self._body = body

    async def body(self):
        return self._body
