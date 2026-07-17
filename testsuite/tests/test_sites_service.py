"""Site Configurator + deployment service (app.services.sites).

Drives the per-site config read/write/merge logic and the Ansible deploy shim
against a throwaway project tree (``isolated_app_config``), so nothing touches
the real ``configs/sites`` or ``ansible/group_vars/all.yml``. The ``ansible-playbook``
subprocess is stubbed — we assert the exact command and recorded history.
"""

from __future__ import annotations

import subprocess
from concurrent.futures import CancelledError

import pytest


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
    assert merged["published_hostname"] == "custom.example"
    assert merged["routed"] is True and merged["deployed"] is True
    assert merged["compose_rendered"] is False
    assert merged["local_hostname"] == "site-001.dukecodeplus.localhost"
    assert merged["website"]["port"] == "8090"
    assert merged["database"]["user"] == "alice"
    # The canonical route is read from the rendered nginx block's $site_name.
    assert sites.active_proxy_sites() == ["custom.example"]


def test_custom_proxy_conf_dir_is_rejected_before_false_live_state(
    isolated_app_config,
):
    from app.services import sites

    paths = isolated_app_config
    _seed_site(paths)
    custom_routes = paths["root"] / "custom/sites-enabled"
    custom_routes.mkdir(parents=True)
    (paths["proxy_conf"] / "site-001.conf").replace(
        custom_routes / "site-001.conf"
    )
    with paths["all_yml"].open("a", encoding="utf-8") as handle:
        handle.write('  conf_dir: "{{ project_root }}/custom/sites-enabled"\n')

    with pytest.raises(ValueError, match="nginx-mounted directory"):
        sites.merged_site_config("site-001")
    with pytest.raises(ValueError, match="nginx-mounted directory"):
        sites._publication_artifact_paths("site-001")


def test_write_config_and_suggest_non_colliding_ports(isolated_app_config, monkeypatch):
    """Writing a new site persists its YAML and the port suggester avoids collisions."""
    from app.services import sites

    paths = isolated_app_config
    _seed_site(paths)
    monkeypatch.setattr(sites, "_running_container_statuses", lambda: {})
    written = sites.write_site_config("site-002", scraper_version="1", port="8091",
                                      genmode=True, db_user="bob", db_password="pw", db_host_port="5441")
    assert written["website"]["genmode"] == "true"
    assert sites.merged_site_config("site-002")["database"]["host_port"] == "5441"

    suggestion = sites.suggest_ports()
    # site-001 used 8090; site-002 used 8091 -> the suggester walks to the first free web port.
    assert suggestion["web_port"] not in {8090, 8091}
    assert suggestion["db_host_port"] not in {5440, 5441}


def test_site_state_separates_route_runtime_and_rendered_artifacts(
    isolated_app_config, monkeypatch,
):
    """A file rendered during a cancelled deployment is never called live."""
    from app.services import sites

    paths = isolated_app_config
    _seed_site(paths)
    # Rendered Compose alone used to produce the misleading "Deployed" badge.
    compose = paths["website"] / "sites" / "site-001" / "docker-compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text("services: {}\n", encoding="utf-8")

    monkeypatch.setattr(
        sites, "_running_container_statuses",
        lambda: {"proxy-nginx": None, "site-001-web-1": "healthy"},
    )
    live = sites.list_sites()[0]
    assert live["state"] == "live"
    assert live["live"] is True and live["web_running"] is True
    assert live["web_health"] == "healthy"
    assert live["compose_rendered"] is True

    monkeypatch.setattr(
        sites, "_running_container_statuses",
        lambda: {"proxy-nginx": None, "site-001-web-1": "unhealthy"},
    )
    unhealthy = sites.list_sites()[0]
    assert unhealthy["state"] == "unhealthy"
    assert unhealthy["live"] is False

    monkeypatch.setattr(
        sites, "_running_container_statuses",
        lambda: {"proxy-nginx": None, "site-001-web-1": None},
    )
    health_unknown = sites.list_sites()[0]
    assert health_unknown["state"] == "health_unknown"
    assert health_unknown["live"] is False

    monkeypatch.setattr(
        sites, "_running_container_statuses", lambda: {"proxy-nginx": None}
    )
    offline = sites.list_sites()[0]
    assert offline["state"] == "offline"
    assert offline["routed"] is True and offline["live"] is False

    (paths["proxy_conf"] / "site-001.conf").unlink()
    monkeypatch.setattr(
        sites, "_running_container_statuses",
        lambda: {"proxy-nginx": None, "site-001-web-1": "healthy"},
    )
    unrouted = sites.list_sites()[0]
    assert unrouted["state"] == "unrouted"
    assert unrouted["deployed"] is False

    monkeypatch.setattr(sites, "_running_container_statuses", lambda: {})
    stopped = sites.list_sites()[0]
    # Unpublished + not running, but a rendered stack exists: a take-down or a
    # deployment that never finished. The stale Compose artifact stays visible
    # for diagnosis, but never changes publication/deployment truth.
    assert stopped["state"] == "stopped"
    assert stopped["compose_rendered"] is True
    assert stopped["live"] is False
    assert stopped["deployed"] is False

    # Only a site with nothing rendered at all is config-only.
    compose.unlink()
    config_only = sites.list_sites()[0]
    assert config_only["state"] == "config_only"
    assert config_only["compose_rendered"] is False
    assert config_only["live"] is False


def test_site_state_is_unknown_when_docker_cannot_be_inspected(
    isolated_app_config, monkeypatch,
):
    from app.services import sites

    _seed_site(isolated_app_config)
    monkeypatch.setattr(sites, "_running_container_statuses", lambda: None)
    row = sites.list_sites()[0]

    assert row["state"] == "unknown"
    assert row["web_running"] is None
    assert row["proxy_running"] is None
    assert row["live"] is None

    (isolated_app_config["proxy_conf"] / "site-001.conf").unlink()
    still_unknown = sites.list_sites()[0]
    assert still_unknown["state"] == "unknown"
    assert still_unknown["routed"] is False


def test_docker_status_parser_distinguishes_health_from_running(
    isolated_app_config, monkeypatch,
):
    from app.services import sites

    output = "\n".join((
        "site-ok-web-1\tUp 20 seconds (healthy)",
        "site-bad-web-1\tUp 20 seconds (unhealthy)",
        "site-new-web-1\tUp 2 seconds (health: starting)",
        "proxy-nginx\tUp 3 days",
    ))
    monkeypatch.setattr(
        sites.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, output, ""),
    )

    assert sites._running_container_statuses() == {
        "site-ok-web-1": "healthy",
        "site-bad-web-1": "unhealthy",
        "site-new-web-1": "starting",
        "proxy-nginx": None,
    }


def test_rollback_reports_prometheus_reload_failure(
    isolated_app_config, monkeypatch,
):
    from app.services import sites

    monkeypatch.setattr(sites, "_proxy_defaults", lambda: {"container": "proxy-nginx"})
    monkeypatch.setattr(
        sites,
        "_monitoring_defaults",
        lambda: {
            "prometheus_container": "mon-prometheus",
            "rules_dir": isolated_app_config["root"] / "monitoring/alerts.d",
            "targets_dir": isolated_app_config["root"] / "monitoring/targets.d",
        },
    )
    monkeypatch.setattr(
        sites,
        "load_all_yml",
        lambda: {"proxy": {"tls_auto_expand": False}},
    )
    results = iter((
        subprocess.CompletedProcess([], 0, "", ""),
        subprocess.CompletedProcess([], 0, "", ""),
        subprocess.CompletedProcess([], 1, "", "reload refused"),
    ))
    monkeypatch.setattr(sites.subprocess, "run", lambda *a, **k: next(results))

    warnings = sites._reload_after_publication_rollback()

    assert warnings == ["Prometheus rejected the restored-rule reload"]


def test_publication_role_runs_after_compose_and_is_rollback_safe(repo_root):
    """Routes/targets appear only in the post-deploy publication role."""
    site_play = (repo_root / "ansible" / "site.yml").read_text(encoding="utf-8")
    validation = (
        repo_root / "ansible" / "tasks" / "validate-site.yml"
    ).read_text(encoding="utf-8")
    configure = (
        repo_root / "ansible" / "roles" / "configure" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")
    publish = (
        repo_root / "ansible" / "roles" / "publish" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")
    deploy = (
        repo_root / "ansible" / "roles" / "deploy" / "tasks" / "main.yml"
    ).read_text(encoding="utf-8")
    compose_template = (
        repo_root / "ansible" / "roles" / "configure" / "templates"
        / "docker-compose.yml.j2"
    ).read_text(encoding="utf-8")

    assert site_play.index("name: deploy") < site_play.index("name: publish")
    assert "Publish per-site nginx" not in configure
    assert ".{{ site_id }}.candidate" in publish
    assert "Validate complete nginx configuration" in publish
    assert "Restore previous nginx route" in publish
    assert "Remove failed new nginx route" in publish
    assert "Reconcile trusted certificate with restored routes" in publish
    assert "Require an existing published route for render-only" in publish
    assert "Require the reverse proxy before route publication" in publish
    assert "Publish generated route while proxy is offline" not in publish
    assert "site-targets.yml.j2" in publish
    assert "abd_http" in (
        repo_root / "ansible" / "roles" / "configure" / "templates"
        / "site-targets.yml.j2"
    ).read_text(encoding="utf-8")
    assert "--wait --wait-timeout 90" in deploy
    assert "http://127.0.0.1:8080/__abd_health" in compose_template
    assert "Reject hostnames already owned by another published vhost" in validation
    assert '"{{ project_root }}/proxy/admin.d"' in validation
    assert "Raw IP literals are intentionally rejected" in validation
    assert "item.path | dirname | realpath" in validation
    assert "proxy.conf_dir | realpath" in validation
    assert "regex_findall('(?m)^[ \\t]*server_name[ \\t]+([^;]+);')" in validation
    assert "item.path != (proxy.conf_dir" not in validation
    assert "publication_rollback_failures" in publish
    assert "Rollback failures:" in publish
    assert "register: rollback_restore_route" in publish
    assert "register: rollback_reconcile_tls" in publish
    assert "candidate_tls_transition_aliases" in publish
    assert 'ABD_PUBLICATION_LOCK_HELD: "1"' in publish
    assert "Acquire cross-process publication lock" in site_play
    assert site_play.index("Acquire cross-process publication lock") < site_play.index(
        "Validate deployment inputs under publication lock"
    )
    assert validation.index(
        "Reload global deployment defaults under publication lock"
    ) < validation.index("Load per-site overrides")
    assert "Require nginx's mounted publication directory" in validation
    assert "Validate deployment inputs under publication lock" in site_play
    assert "Release direct-play lock after validation failure" in site_play
    assert "Release completed direct-play publication lock" in site_play
    assert "handlers:" not in site_play
    assert "Release successful publication lock" not in site_play
    assert site_play.count('state: absent') == 2


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


def test_unsafe_site_id_is_rejected_before_writing_or_deploying(
    isolated_app_config, monkeypatch,
):
    from app.services import sites

    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(sites.subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="site_id"):
        sites.write_site_config(
            "../site-evil", scraper_version="1", port="8099", genmode=True,
            db_user="", db_password="", db_host_port="5499",
        )
    with pytest.raises(ValueError, match="site_id"):
        sites.deploy_site("site-001;touch-pwned")
    with pytest.raises(ValueError, match="lowercase"):
        sites.deploy_site("Site-001")
    with pytest.raises(ValueError, match="DNS label"):
        sites.deploy_site("site_001")
    with pytest.raises(ValueError, match="non-edge"):
        sites.deploy_site("site-")
    with pytest.raises(ValueError, match="reserved"):
        sites.deploy_site("admin")

    assert called is False
    assert not (isolated_app_config["sites_cfg"].parent / "site-evil.yaml").exists()


def test_cancelled_deploy_restores_exact_pre_deploy_publication(
    isolated_app_config, monkeypatch,
):
    """SIGTERM cannot bypass rollback after Ansible has promoted artifacts."""
    from app.services import sites

    paths = isolated_app_config
    _seed_site(paths)
    route = paths["proxy_conf"] / "site-001.conf"
    old_route = route.read_bytes()
    alert = paths["root"] / "monitoring" / "alerts.d" / "site-001.yml"
    target = paths["root"] / "monitoring" / "targets.d" / "site-001.yml"
    alert.parent.mkdir(parents=True)
    alert.write_text("old alert\n", encoding="utf-8")

    class FakeProcess:
        returncode = -15

        def communicate(self, timeout):
            route.write_text("new route\n", encoding="utf-8")
            alert.write_text("new alert\n", encoding="utf-8")
            target.parent.mkdir(parents=True)
            target.write_text("new target\n", encoding="utf-8")
            return "cancelled", None

    class Task:
        checks = 0

        def check_cancelled(self):
            self.checks += 1
            if self.checks > 1:
                raise CancelledError()

        def attach_process(self, proc):
            pass

        def detach_process(self, proc):
            pass

        def update(self, **fields):
            pass

    monkeypatch.setattr(sites.subprocess, "Popen", lambda *a, **k: FakeProcess())
    reloaded = []
    stopped = []
    monkeypatch.setattr(
        sites, "_stop_certbot_reconcile",
        lambda site_id: stopped.append(site_id) or None,
    )
    monkeypatch.setattr(
        sites, "_reload_after_publication_rollback",
        lambda: reloaded.append(True) or [],
    )

    with pytest.raises(CancelledError):
        sites.deploy_site("site-001", task=Task())

    assert route.read_bytes() == old_route
    assert alert.read_text(encoding="utf-8") == "old alert\n"
    assert not target.exists()
    assert reloaded == [True]
    assert stopped == ["site-001"]
    history = (paths["history"] / "applies.jsonl").read_text(encoding="utf-8")
    assert '"status": "cancelled"' in history


def test_deploy_invokes_ansible_and_records_history(isolated_app_config, monkeypatch):
    """Deploy shells the right ansible-playbook command and appends to the apply log."""
    from app.services import sites

    paths = isolated_app_config
    _seed_site(paths)
    calls = []

    class FakeProcess:
        returncode = 0

        def communicate(self, timeout):
            calls.append(("communicate", timeout))
            return "ok", None

    def fake_popen(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return FakeProcess()

    monkeypatch.setattr(sites.subprocess, "Popen", fake_popen)
    ok, output = sites.deploy_site("site-001", reset_db=True, timeout=5)

    assert ok is True and output == "ok"
    assert calls[0][0] == ["ansible-playbook", "site.yml", "-e", "site_id=site-001", "-e", "reset_db=true"]
    assert calls[0][1]["start_new_session"] is True
    assert calls[0][1]["env"]["ABD_PUBLICATION_LOCK_HELD"] == "1"
    assert calls[1] == ("communicate", 5)
    history = (paths["history"] / "applies.jsonl").read_text(encoding="utf-8")
    assert "site-001" in history and '"status": "ok"' in history
    assert not (paths["root"] / "configs/.publication.lock").exists()


def test_deploy_refuses_a_concurrent_publication_owner(
    isolated_app_config, monkeypatch,
):
    from app.services import sites

    _seed_site(isolated_app_config)
    lock = isolated_app_config["root"] / "configs/.publication.lock"
    lock.mkdir()
    (lock / "owner").write_text("operation=set-public-host\n", encoding="utf-8")
    monkeypatch.setattr(
        sites.subprocess,
        "Popen",
        lambda *a, **k: pytest.fail("Ansible started despite publication lock"),
    )

    ok, output = sites.deploy_site("site-001")

    assert ok is False
    assert "Another deployment/TLS/public-host transaction owns" in output
    history = (isolated_app_config["history"] / "applies.jsonl").read_text(
        encoding="utf-8"
    )
    assert '"status": "publication_busy"' in history


def test_deploy_reports_missing_ansible_cleanly(isolated_app_config, monkeypatch):
    """A missing ansible-playbook binary yields a friendly message, not a stack trace."""
    from app.services import sites

    def raise_fnf(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(sites.subprocess, "Popen", raise_fnf)
    ok, output = sites.deploy_site("site-001")
    assert ok is False and "ansible-playbook not found" in output


def test_synchronous_timeout_kills_process_group_before_rollback(
    isolated_app_config, monkeypatch,
):
    from app.services import sites

    _seed_site(isolated_app_config)
    calls = []

    class FakeProcess:
        pid = 4321
        returncode = -9
        attempts = 0

        def communicate(self, timeout=None):
            self.attempts += 1
            if self.attempts == 1:
                raise subprocess.TimeoutExpired("ansible-playbook", timeout)
            return "partial output", None

        def kill(self):
            calls.append("fallback-kill")

    monkeypatch.setattr(sites.subprocess, "Popen", lambda *a, **k: FakeProcess())
    monkeypatch.setattr(sites.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(
        sites.os, "killpg", lambda pgid, sig: calls.append((pgid, sig))
    )
    monkeypatch.setattr(
        sites, "_stop_certbot_reconcile",
        lambda site_id: calls.append(("stop-certbot", site_id)) or None,
    )
    monkeypatch.setattr(
        sites, "_restore_publication",
        lambda snapshot, *args: calls.append("rollback") or "\nrestored",
    )

    ok, output = sites.deploy_site("site-001", timeout=2)

    assert ok is False
    assert (4321, sites.signal.SIGKILL) in calls
    assert calls.index((4321, sites.signal.SIGKILL)) < calls.index("rollback")
    assert calls.index(("stop-certbot", "site-001")) < calls.index("rollback")
    assert "partial output" in output and "timed out" in output


def test_unconfirmed_certbot_stop_blocks_restore_and_persists_recovery(
    isolated_app_config, monkeypatch,
):
    """Never restore route files while daemon-side Certbot may still mutate TLS."""
    from app.services import sites

    paths = isolated_app_config
    _seed_site(paths)
    route = paths["proxy_conf"] / "site-001.conf"
    old_route = route.read_bytes()

    class FakeProcess:
        pid = 9876
        returncode = -9
        attempts = 0

        def communicate(self, timeout=None):
            self.attempts += 1
            if self.attempts == 1:
                route.write_text("partially published\n", encoding="utf-8")
                raise subprocess.TimeoutExpired("ansible-playbook", timeout)
            return "partial output", None

        def kill(self):
            pass

    monkeypatch.setattr(sites.subprocess, "Popen", lambda *a, **k: FakeProcess())
    monkeypatch.setattr(sites.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(sites.os, "killpg", lambda *args: None)
    monkeypatch.setattr(
        sites,
        "_stop_certbot_reconcile",
        lambda site_id: "could not confirm daemon-side Certbot stopped",
    )
    monkeypatch.setattr(
        sites,
        "_restore_publication",
        lambda *args, **kwargs: pytest.fail("unsafe restore was attempted"),
    )

    ok, output = sites.deploy_site("site-001", timeout=1)

    assert ok is False
    assert "Rollback blocked" in output
    assert "No publication files were restored" in output
    assert route.read_text(encoding="utf-8") == "partially published\n"
    lock = paths["root"] / "configs/.publication.lock"
    manifest = lock / "recovery/manifest.json"
    assert lock.is_dir() and manifest.is_file()
    manifest_text = manifest.read_text(encoding="utf-8")
    assert str(route) in manifest_text
    assert old_route == (lock / "recovery/artifact-0.bin").read_bytes()


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


# --- Retirement: take down / delete ----------------------------------------
def _seed_published_site(paths):
    """A fully published site: config, route, monitoring artifacts, rendered stack."""
    _seed_site(paths)
    alert = paths["root"] / "monitoring" / "alerts.d" / "site-001.yml"
    target = paths["root"] / "monitoring" / "targets.d" / "site-001.yml"
    compose = paths["website"] / "sites" / "site-001" / "docker-compose.yml"
    for path, text in (
        (alert, "alert rules\n"),
        (target, "probe targets\n"),
        (compose, "services: {}\n"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return {
        "route": paths["proxy_conf"] / "site-001.conf",
        "alert": alert,
        "target": target,
        "compose": compose,
        "stack": compose.parent,
        "yaml": paths["sites_cfg"] / "site-001.yaml",
    }


class _FakeDocker:
    """Answer docker/compose calls, recording argv and observable state per call."""

    def __init__(self, watch=None, fail=()):
        self.calls = []
        self.watch = watch          # path whose existence is snapshotted per call
        self.fail = tuple(fail)     # substrings of argv that should return rc=1

    def __call__(self, argv, **kwargs):
        joined = " ".join(argv)
        self.calls.append({
            "argv": list(argv),
            "cwd": kwargs.get("cwd"),
            "watched_present": self.watch.exists() if self.watch else None,
        })
        failed = any(token in joined for token in self.fail)
        return subprocess.CompletedProcess(
            argv, 1 if failed else 0,
            stdout="", stderr="docker said no" if failed else "",
        )

    def argvs(self):
        return [call["argv"] for call in self.calls]


def _up_containers():
    return {"proxy-nginx": "healthy", "mon-prometheus": None,
            "site-001-web-1": "healthy", "site-001-db-1": "healthy"}


def test_take_down_withdraws_publication_then_stops_the_stack(
    isolated_app_config, monkeypatch,
):
    """Take-down un-publishes route + monitoring, stops containers, keeps data."""
    from app.services import sites

    paths = isolated_app_config
    artifacts = _seed_published_site(paths)
    docker = _FakeDocker(watch=artifacts["route"])
    running = _up_containers()
    monkeypatch.setattr(sites.subprocess, "run", docker)
    monkeypatch.setattr(sites, "_running_container_statuses", lambda: running)

    ok, detail = sites.stop_site("site-001")

    assert ok is True, detail
    # Publication is gone: no route, no alert rule, no blackbox target.
    assert not artifacts["route"].exists()
    assert not artifacts["alert"].exists()
    assert not artifacts["target"].exists()
    # Everything needed to bring the same site back is untouched.
    assert artifacts["yaml"].exists()
    assert artifacts["compose"].exists()

    argvs = docker.argvs()
    assert ["docker", "exec", "proxy-nginx", "nginx", "-t"] in argvs
    assert ["docker", "exec", "proxy-nginx", "nginx", "-s", "reload"] in argvs
    assert ["docker", "kill", "--signal=HUP", "mon-prometheus"] in argvs

    stop = next(c for c in docker.calls if "stop" in c["argv"])
    assert stop["argv"] == ["docker", "compose", "stop", "--timeout", "10"]
    assert stop["cwd"] == str(artifacts["stack"])
    # Ordering is load-bearing: the route must already be withdrawn when the
    # containers go away, or the hostname 502s instead of falling to the 444
    # catch-all. `docker compose down -v` is never used by a take-down.
    assert stop["watched_present"] is False
    assert not any("down" in argv for argv in argvs)

    history = (paths["history"] / "applies.jsonl").read_text(encoding="utf-8")
    assert '"status": "stopped"' in history
    assert not (paths["root"] / "configs/.publication.lock").exists()

    # Once the containers really are gone from `docker ps`, the page reports the
    # site as Stopped — distinct from a never-deployed "config only" site, and
    # distinct from the "unrouted" state a half-finished take-down leaves.
    for name in ("site-001-web-1", "site-001-db-1"):
        running.pop(name)
    state = sites.list_sites()[0]
    assert state["state"] == "stopped"
    assert state["routed"] is False and state["compose_rendered"] is True


def test_delete_destroys_stack_data_and_config(isolated_app_config, monkeypatch):
    """Delete un-publishes, drops the volume, and forgets the site entirely."""
    from app.services import sites

    paths = isolated_app_config
    artifacts = _seed_published_site(paths)
    docker = _FakeDocker(watch=artifacts["route"])
    monkeypatch.setattr(sites.subprocess, "run", docker)
    monkeypatch.setattr(sites, "_running_container_statuses", _up_containers)

    ok, detail = sites.delete_site("site-001")

    assert ok is True, detail
    for key in ("route", "alert", "target", "yaml", "stack"):
        assert not artifacts[key].exists(), f"{key} survived the delete"

    down = next(c for c in docker.calls if "down" in c["argv"])
    assert down["argv"] == [
        "docker", "compose", "down", "--volumes", "--remove-orphans",
        "--timeout", "10",
    ]
    assert down["cwd"] == str(artifacts["stack"])
    assert down["watched_present"] is False

    assert sites.list_sites() == []
    history = (paths["history"] / "applies.jsonl").read_text(encoding="utf-8")
    assert '"status": "deleted"' in history
    assert not (paths["root"] / "configs/.publication.lock").exists()


def test_retirement_never_reconciles_tls(isolated_app_config, monkeypatch):
    """Shrinking the shared cert costs an ACME issuance and buys nothing.

    A SAN whose hostname no longer routes is unreachable (the catch-all answers
    it), and the next deploy reconciles to the exact published set anyway.
    """
    from app.services import sites

    paths = isolated_app_config
    all_yml = paths["ansible"] / "group_vars" / "all.yml"
    all_yml.write_text(
        all_yml.read_text(encoding="utf-8")
        + "  tls_fullchain: /etc/letsencrypt/live/abd/fullchain.pem\n"
          "  tls_key: /etc/letsencrypt/live/abd/privkey.pem\n"
          "  tls_auto_expand: true\n",
        encoding="utf-8",
    )
    _seed_published_site(paths)
    docker = _FakeDocker()
    monkeypatch.setattr(sites.subprocess, "run", docker)
    monkeypatch.setattr(sites, "_running_container_statuses", _up_containers)

    for retire in (sites.stop_site, sites.delete_site):
        _seed_published_site(paths)
        ok, detail = retire("site-001")
        assert ok is True, detail

    assert not any(
        "setup-letsencrypt" in " ".join(argv) for argv in docker.argvs()
    )


def test_take_down_restores_everything_when_nginx_refuses(
    isolated_app_config, monkeypatch,
):
    """An nginx rejection leaves the site exactly as published and running."""
    from app.services import sites

    paths = isolated_app_config
    artifacts = _seed_published_site(paths)
    route_before = artifacts["route"].read_bytes()
    docker = _FakeDocker(fail=("nginx -t",))
    monkeypatch.setattr(sites.subprocess, "run", docker)
    monkeypatch.setattr(sites, "_running_container_statuses", _up_containers)
    monkeypatch.setattr(sites, "_reload_after_publication_rollback", lambda: [])

    ok, detail = sites.stop_site("site-001")

    assert ok is False
    assert "left published and running" in detail
    assert artifacts["route"].read_bytes() == route_before
    assert artifacts["alert"].read_text(encoding="utf-8") == "alert rules\n"
    assert artifacts["target"].read_text(encoding="utf-8") == "probe targets\n"
    # Nothing was stopped: the refusal happens before any container is touched.
    assert not any("compose" in argv for argv in docker.argvs())
    history = (paths["history"] / "applies.jsonl").read_text(encoding="utf-8")
    assert '"status": "stopped_refused"' in history


def test_failed_delete_keeps_the_config_so_it_can_be_retried(
    isolated_app_config, monkeypatch,
):
    """A stack that would not go down must stay listed, never orphaned."""
    from app.services import sites

    paths = isolated_app_config
    artifacts = _seed_published_site(paths)
    docker = _FakeDocker(fail=("compose down",))
    monkeypatch.setattr(sites.subprocess, "run", docker)
    monkeypatch.setattr(sites, "_running_container_statuses", _up_containers)

    ok, detail = sites.delete_site("site-001")

    assert ok is False
    assert "off the internet" in detail and "Re-run this action" in detail
    # The site is un-published (that part succeeded and is not undone) ...
    assert not artifacts["route"].exists()
    # ... but it is still configured, so the UI can retry the destroy step.
    assert artifacts["yaml"].exists()
    assert artifacts["stack"].exists()
    assert sites.list_sites()[0]["site_id"] == "site-001"
    history = (paths["history"] / "applies.jsonl").read_text(encoding="utf-8")
    assert '"status": "deleted_partial"' in history
    # A failed transaction must not strand the cross-process lock.
    assert not (paths["root"] / "configs/.publication.lock").exists()


def test_retirement_refuses_a_concurrent_publication_owner(
    isolated_app_config, monkeypatch,
):
    """Take-down/delete take the same lock as deploy and TLS reconciliation."""
    from app.services import sites

    paths = isolated_app_config
    artifacts = _seed_published_site(paths)
    lock = paths["root"] / "configs/.publication.lock"
    lock.mkdir(parents=True)
    (lock / "owner").write_text("site_id=site-002\n", encoding="utf-8")
    docker = _FakeDocker()
    monkeypatch.setattr(sites.subprocess, "run", docker)

    for retire in (sites.stop_site, sites.delete_site):
        ok, detail = retire("site-001")
        assert ok is False
        assert "owns" in detail
    # Nothing was withdrawn, stopped, or destroyed.
    assert artifacts["route"].exists() and artifacts["yaml"].exists()
    assert docker.calls == []


def test_retirement_rejects_unsafe_site_ids(isolated_app_config, monkeypatch):
    from app.services import sites

    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(sites.subprocess, "run", fake_run)
    for bad in ("../site-evil", "site-001;rm -rf /", "Site-001", "admin", "site_1"):
        with pytest.raises(ValueError):
            sites.stop_site(bad)
        with pytest.raises(ValueError):
            sites.delete_site(bad)
    assert called is False


def test_take_down_tolerates_a_stopped_proxy_and_monitoring_stack(
    isolated_app_config, monkeypatch,
):
    """Removing an include target cannot break nginx, so a down proxy is no bar."""
    from app.services import sites

    paths = isolated_app_config
    artifacts = _seed_published_site(paths)
    docker = _FakeDocker()
    monkeypatch.setattr(sites.subprocess, "run", docker)
    monkeypatch.setattr(sites, "_running_container_statuses", dict)

    ok, detail = sites.stop_site("site-001")

    assert ok is True, detail
    assert "not running" in detail  # the warning is surfaced, not swallowed
    assert not artifacts["route"].exists() and not artifacts["alert"].exists()
    # Neither a reload nor a HUP is attempted against a container that is down.
    assert not any("nginx" in argv for argv in docker.argvs())
    assert not any("--signal=HUP" in argv for argv in docker.argvs())
    assert any("stop" in argv for argv in docker.argvs())


def test_config_only_site_retires_without_touching_docker_compose(
    isolated_app_config, monkeypatch,
):
    """A site that was never rendered has no stack to stop or destroy."""
    from app.services import sites

    paths = isolated_app_config
    _seed_site(paths)                       # config + route, no rendered stack
    docker = _FakeDocker()
    monkeypatch.setattr(sites.subprocess, "run", docker)
    monkeypatch.setattr(sites, "_running_container_statuses", _up_containers)

    ok, detail = sites.delete_site("site-001")

    assert ok is True, detail
    assert not (paths["sites_cfg"] / "site-001.yaml").exists()
    assert not any("compose" in argv for argv in docker.argvs())


def test_site_inventory_is_safe_to_read_from_several_threads(
    isolated_app_config, monkeypatch,
):
    """Concurrent readers must not corrupt each other's YAML parse.

    A ruamel YAML() instance carries per-parse state and is not thread-safe, but
    this module is read concurrently — the monitoring overview fans out its
    container and probe inventories in parallel and both walk list_sites().
    Sharing one parser made those loads interleave into a bogus ParserError that
    callers swallowed, silently dropping every site from monitoring on roughly a
    third of refreshes. Nothing about the files is invalid, so no reader may ever
    fail to see them.
    """
    import threading

    paths = isolated_app_config
    _seed_site(paths)
    for index in range(2, 5):
        (paths["sites_cfg"] / f"site-00{index}.yaml").write_text(
            f'scraper_version: "1"\nwebsite:\n  port: "80{index}0"\n'
            f'database:\n  host_port: "54{index}0"\n',
            encoding="utf-8",
        )
    from app.services import sites

    monkeypatch.setattr(sites, "_running_container_statuses", lambda: {})

    failures, counts = [], []
    barrier = threading.Barrier(8)

    def reader():
        barrier.wait()          # maximise overlap on the shared parser
        for _ in range(15):
            try:
                counts.append(len(sites.list_sites()))
                sites.load_all_yml()
            except Exception as exc:
                failures.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == [], f"concurrent reads raised: {failures[:3]}"
    assert counts and set(counts) == {4}, (
        f"every read must see all 4 sites, saw {sorted(set(counts))}"
    )

