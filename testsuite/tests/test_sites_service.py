"""Site Configurator + deployment service (app.services.sites).

Drives the per-site config read/write/merge logic and the Ansible deploy shim
against a throwaway project tree (``isolated_app_config``), so nothing touches
the real ``configs/sites`` or ``ansible/group_vars/all.yml``. The ``ansible-playbook``
subprocess is stubbed — we assert the exact command and recorded history.
"""

from __future__ import annotations

import subprocess


def _seed_site(paths):
    (paths["templates"] / "scraper1.html").write_text("<h1>{{ var1 }}</h1>", encoding="utf-8")
    (paths["templates"] / "scraper3.html").write_text("<h1>{{ var3 }}</h1>", encoding="utf-8")
    (paths["sites_cfg"] / "site-001.yaml").write_text(
        """
scraper_version: "3"
website:
  port: "8090"
  genmode: "false"
database:
  user: alice
  password: secret
  host_port: "5440"
proxy:
  server_name: custom.example
""".lstrip(),
        encoding="utf-8",
    )
    (paths["proxy_conf"] / "site-001.conf").write_text(
        "server { server_name custom.example other.example; set $site_name custom.example; }",
        encoding="utf-8",
    )


def test_scraper_versions_and_template_source(isolated_app_config):
    """Available flavors are discovered from website/templates and source is readable."""
    from app.services import sites

    paths = isolated_app_config
    _seed_site(paths)
    assert sites.available_scraper_versions() == [1, 3]
    assert sites.template_source(1) == "<h1>{{ var1 }}</h1>"
    assert sites.template_source(99) is None


def test_site_config_merges_overrides_over_defaults(isolated_app_config):
    """Per-site YAML overrides global defaults; derived fields (db_name, hostnames) follow."""
    from app.services import sites

    paths = isolated_app_config
    _seed_site(paths)
    merged = sites.merged_site_config("site-001")

    assert merged["site_id"] == "site-001"
    assert merged["scraper_version"] == 3
    assert merged["db_name"] == "scraper3-db"
    assert merged["hostname"] == "custom.example"                       # proxy.server_name override
    assert merged["local_hostname"] == "site-001.dukecodeplus.localhost"
    assert merged["website"]["port"] == "8090"
    assert merged["database"]["user"] == "alice"
    # The canonical route is read from the rendered nginx block's $site_name.
    assert sites.active_proxy_sites() == ["custom.example"]


def test_write_config_and_suggest_non_colliding_ports(isolated_app_config):
    """Writing a new site persists its YAML and the port suggester avoids collisions."""
    from app.services import sites

    paths = isolated_app_config
    _seed_site(paths)
    written = sites.write_site_config("site-002", scraper_version="1", port="8091",
                                      genmode=True, db_user="bob", db_password="pw", db_host_port="5441")
    assert written["website"]["genmode"] == "true"
    assert sites.merged_site_config("site-002")["database"]["host_port"] == "5441"

    suggestion = sites.suggest_ports()
    # site-001 used 8090; site-002 used 8091 -> the suggester walks to the first free web port.
    assert suggestion["web_port"] not in {8090, 8091}
    assert suggestion["db_host_port"] not in {5440, 5441}


def test_write_config_embeds_generated_canary_tokens(isolated_app_config):
    """A generator-authored flavor's varList (configs/generated_templates.json)
    is embedded as a per-site canary_tokens override; hand-made flavors are not."""
    import json

    from app.services import sites

    paths = isolated_app_config
    _seed_site(paths)
    tokens = [f"fake.city()  # {i}" for i in range(10)]
    (paths["root"] / "configs" / "generated_templates.json").write_text(
        json.dumps({"7": {"category": "movies", "canary_tokens": tokens}}), encoding="utf-8")

    with_tokens = sites.write_site_config("site-007", scraper_version="7", port="8097",
                                          genmode=True, db_user="", db_password="", db_host_port="5447")
    assert with_tokens["canary_tokens"] == tokens

    without = sites.write_site_config("site-008", scraper_version="1", port="8098",
                                      genmode=True, db_user="", db_password="", db_host_port="5448")
    assert "canary_tokens" not in without


def test_deploy_invokes_ansible_and_records_history(isolated_app_config, monkeypatch):
    """Deploy shells the right ansible-playbook command and appends to the apply log."""
    from app.services import sites

    paths = isolated_app_config
    _seed_site(paths)
    calls = []

    def fake_run(cmd, cwd, capture_output, text, timeout):
        calls.append((cmd, cwd, timeout))
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(sites.subprocess, "run", fake_run)
    ok, output = sites.deploy_site("site-001", reset_db=True, timeout=5)

    assert ok is True and output == "ok"
    assert calls[0][0] == ["ansible-playbook", "site.yml", "-e", "site_id=site-001", "-e", "reset_db=true"]
    history = (paths["history"] / "applies.jsonl").read_text(encoding="utf-8")
    assert "site-001" in history and '"status": "ok"' in history


def test_deploy_reports_missing_ansible_cleanly(isolated_app_config, monkeypatch):
    """A missing ansible-playbook binary yields a friendly message, not a stack trace."""
    from app.services import sites

    def raise_fnf(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(sites.subprocess, "run", raise_fnf)
    ok, output = sites.deploy_site("site-001")
    assert ok is False and "ansible-playbook not found" in output


def test_background_deploy_registers_a_cancellable_process_group(
    isolated_app_config, monkeypatch,
):
    """The web deployment path attaches/detaches its own-session child."""
    from app.services import sites

    calls = {}

    class FakeProcess:
        returncode = 0

        def communicate(self, timeout):
            calls["timeout"] = timeout
            return "deployed", None

    fake = FakeProcess()

    def fake_popen(cmd, **kwargs):
        calls["cmd"] = cmd
        calls["kwargs"] = kwargs
        return fake

    class Task:
        cancelled = False

        def check_cancelled(self):
            assert not self.cancelled

        def attach_process(self, proc):
            calls["attached"] = proc

        def detach_process(self, proc):
            calls["detached"] = proc

        def update(self, **fields):
            calls["label"] = fields["label"]

    monkeypatch.setattr(sites.subprocess, "Popen", fake_popen)
    ok, output = sites.deploy_site("site-001", reset_db=True, timeout=9, task=Task())

    assert ok is True and output == "deployed"
    assert calls["kwargs"]["start_new_session"] is True
    assert calls["attached"] is fake and calls["detached"] is fake
    assert calls["cmd"][-2:] == ["-e", "reset_db=true"]
