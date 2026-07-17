"""Site configuration + deployment service.

Reads/writes the Ansible variable contract (``ansible/group_vars/all.yml`` global
defaults + per-site overrides in ``configs/sites/<id>.yaml``), lists the scraper
HTML flavors, and deploys a site by shelling ``ansible-playbook`` — the same flow
the old Streamlit ``Site_Config`` page + ``build.py`` performed, ported here.
"""

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
from concurrent.futures import CancelledError
from datetime import datetime, timezone
from pathlib import Path

from ruamel.yaml import YAML

from .. import config
from . import template_gen

_yaml = YAML()
_yaml.preserve_quotes = True
# A ruamel YAML() instance carries per-parse state and is NOT thread-safe, while
# this module is read from several threads at once: the monitoring overview fans
# out container and probe inventory concurrently, and both walk list_sites().
# Sharing the parser let those loads interleave and corrupt each other, raising
# a bogus ParserError that callers then swallowed — which silently dropped every
# site from the monitoring inventory on roughly a third of refreshes. Serialize
# every use instead; the files are a few hundred bytes, so contention is noise.
# Re-entrant because these helpers legitimately nest (merged_site_config reads
# all.yml and a site file within one call).
_yaml_lock = threading.RLock()
_SITE_ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _yaml_load(handle):
    with _yaml_lock:
        return _yaml.load(handle)


def _yaml_dump(data, handle):
    with _yaml_lock:
        _yaml.dump(data, handle)


def _validate_site_id(site_id):
    value = str(site_id or "")
    if not _SITE_ID_RE.fullmatch(value) or value == "admin":
        raise ValueError(
            "site_id must be a 1-63 character lowercase DNS label containing "
            "only letters, digits, and non-edge hyphens; 'admin' is reserved."
        )
    return value


# --- all.yml (global defaults) --------------------------------------------
def load_all_yml():
    with open(config.ALL_YML) as handle:
        return _yaml_load(handle)


def save_all_yml(data):
    with open(config.ALL_YML, "w") as handle:
        _yaml_dump(data, handle)


def get_website_dir():
    try:
        return str(load_all_yml().get("website_dir", ""))
    except Exception:
        return ""


def set_website_dir(path):
    data = load_all_yml()
    data["website_dir"] = path
    save_all_yml(data)


def _proxy_defaults():
    try:
        proxy = load_all_yml().get("proxy", {}) or {}
    except Exception:
        proxy = {}

    raw_conf_dir = str(proxy.get("conf_dir", "proxy/conf.d"))
    raw_conf_dir = raw_conf_dir.replace(
        "{{ project_root }}", str(config.PROJECT_ROOT)
    )
    conf_dir = Path(raw_conf_dir)
    if not conf_dir.is_absolute():
        conf_dir = config.PROJECT_ROOT / conf_dir
    conf_dir = conf_dir.resolve(strict=False)
    mounted_conf_dir = (config.PROJECT_ROOT / "proxy" / "conf.d").resolve(
        strict=False
    )
    if conf_dir != mounted_conf_dir:
        raise ValueError(
            "proxy.conf_dir must resolve to the nginx-mounted directory "
            f"{mounted_conf_dir}; got {conf_dir}"
        )
    return {
        "base_domain": proxy.get("base_domain", "dukecodeplus.example"),
        "local_base_domain": proxy.get("local_base_domain", "dukecodeplus.localhost"),
        "container": proxy.get("container", "proxy-nginx"),
        "conf_dir": conf_dir,
    }


def _monitoring_defaults():
    try:
        monitoring = load_all_yml().get("monitoring", {}) or {}
    except Exception:
        monitoring = {}

    def deployment_path(key, fallback):
        raw = str(monitoring.get(key, fallback))
        raw = raw.replace("{{ project_root }}", str(config.PROJECT_ROOT))
        path = Path(raw)
        return path if path.is_absolute() else config.PROJECT_ROOT / path

    return {
        "prometheus_container": monitoring.get(
            "prometheus_container", "mon-prometheus"
        ),
        "rules_dir": deployment_path("rules_dir", "monitoring/alerts.d"),
        "targets_dir": deployment_path("targets_dir", "monitoring/targets.d"),
    }


def _published_routes():
    """Return ``site_id -> canonical hostname`` for final nginx routes.

    A final ``<proxy.conf_dir>/<site>.conf`` is the durable publication marker.
    It is written transactionally only after Compose startup succeeds; YAML and
    a rendered Compose file alone are not evidence that a site is public.
    """
    routes = {}
    proxy_conf_dir = _proxy_defaults()["conf_dir"]
    if not proxy_conf_dir.exists():
        return routes
    for path in proxy_conf_dir.glob("*.conf"):
        try:
            text = path.read_text()
        except OSError:
            continue
        canonical = re.search(r"\bset\s+\$site_name\s+([^;]+);", text)
        if canonical:
            routes[path.stem] = canonical.group(1).strip()
    return routes


def _running_container_statuses():
    """Return running container names -> Docker health, or ``None``.

    Health is ``healthy``, ``unhealthy``, ``starting``, or ``None`` when the
    container has no healthcheck. A running process alone is deliberately not
    enough to label a published honeypot live.
    """
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    containers = {}
    for line in result.stdout.splitlines():
        name, _, status = line.partition("\t")
        if not name:
            continue
        health = None
        if "(healthy)" in status:
            health = "healthy"
        elif "(unhealthy)" in status:
            health = "unhealthy"
        elif "(health: starting)" in status:
            health = "starting"
        containers[name] = health
    return containers


# --- Scraper templates -----------------------------------------------------
def available_scraper_versions():
    """Return the scraper flavors present as ``website/templates/scraper<N>.html``."""
    versions = set()
    for path in config.TEMPLATES_DIR.glob("scraper*.html"):
        match = re.fullmatch(r"scraper(\d+)\.html", path.name)
        if match:
            versions.add(int(match.group(1)))
    return sorted(versions)


def template_source(version):
    """Return the raw HTML source for a scraper flavor, or ``None``."""
    path = config.TEMPLATES_DIR / f"scraper{version}.html"
    return path.read_text() if path.exists() else None


# --- Per-site config -------------------------------------------------------
def _merged_defaults():
    try:
        data = load_all_yml()
    except Exception:
        data = {}
    website = dict(data.get("website", {}) or {})
    database = dict(data.get("database", {}) or {})
    return {
        "scraper_version": data.get("scraper_version", 1),
        "website": {"port": website.get("port", 8080), "genmode": website.get("genmode", True)},
        "database": {
            "user": database.get("user", "user"),
            "password": database.get("password", "password"),
            "host_port": database.get("host_port", 5432),
        },
    }


def merged_site_config(site_id):
    """Merge per-site overrides over global defaults for one site."""
    site_id = _validate_site_id(site_id)
    defaults = _merged_defaults()
    path = config.SITES_CONFIG_DIR / f"{site_id}.yaml"
    overrides = {}
    if path.exists():
        with open(path) as handle:
            overrides = _yaml_load(handle) or {}

    scraper_version = int(overrides.get("scraper_version", defaults["scraper_version"]))
    website = {**defaults["website"], **(overrides.get("website") or {})}
    database = {**defaults["database"], **(overrides.get("database") or {})}
    proxy = _proxy_defaults()
    hostname = (overrides.get("proxy", {}) or {}).get(
        "server_name", f"{site_id}.{proxy['base_domain']}"
    )
    published_hostname = _published_routes().get(site_id)
    routed = published_hostname is not None
    compose_rendered = (
        config.WEBSITE_DIR / "sites" / site_id / "docker-compose.yml"
    ).exists()
    return {
        "site_id": site_id,
        "scraper_version": scraper_version,
        "db_name": f"scraper{scraper_version}-db",
        "website": website,
        "database": database,
        "hostname": hostname,
        "published_hostname": published_hostname,
        "local_hostname": f"{site_id}.{proxy['local_base_domain']}",
        "configured": path.exists(),
        "compose_rendered": compose_rendered,
        "routed": routed,
        # Compatibility for monitoring/query callers: "deployed" now means a
        # final public route exists, never merely a rendered Compose artifact.
        "deployed": routed,
    }


def list_sites():
    """Return desired config plus independently observed deployment state."""
    site_rows = []
    running_containers = _running_container_statuses()
    proxy_container = _proxy_defaults()["container"]
    proxy_running = (
        None if running_containers is None
        else proxy_container in running_containers
    )
    if config.SITES_CONFIG_DIR.exists():
        for path in sorted(config.SITES_CONFIG_DIR.glob("*.yaml")):
            site = merged_site_config(path.stem)
            if running_containers is None:
                web_running = None
                web_health = None
                live = None
                # Without Docker evidence we cannot distinguish config-only
                # from running-but-unrouted; keep route truth separate and do
                # not manufacture either runtime conclusion.
                state = "unknown"
            else:
                web_name = f"{site['site_id']}-web-1"
                web_running = web_name in running_containers
                web_health = running_containers.get(web_name)
                live = bool(
                    site["routed"] and web_running and proxy_running
                    and web_health == "healthy"
                )
                if live:
                    state = "live"
                elif site["routed"] and web_running and proxy_running:
                    if web_health == "unhealthy":
                        state = "unhealthy"
                    elif web_health == "starting":
                        state = "starting"
                    else:
                        state = "health_unknown"
                elif site["routed"]:
                    state = "offline"
                elif web_running:
                    state = "unrouted"
                elif site["compose_rendered"]:
                    # Unpublished, not running, but a stack is rendered on
                    # disk: a deliberate take-down, or a deployment that never
                    # finished. Either way there is something to redeploy or
                    # delete, which "config only" would wrongly deny.
                    state = "stopped"
                else:
                    state = "config_only"
            site.update({
                "web_running": web_running,
                "web_health": web_health,
                "proxy_running": proxy_running,
                "live": live,
                "state": state,
                "config_pending": bool(
                    site["published_hostname"]
                    and site["published_hostname"] != site["hostname"]
                ),
            })
            site_rows.append(site)
    return site_rows


def active_proxy_sites():
    """Canonical hostnames currently configured as reverse-proxy routes."""
    return sorted(set(_published_routes().values()))


def local_site_url(site_id):
    return f"http://{merged_site_config(site_id)['local_hostname']}/"


def suggest_ports():
    """Suggest the next non-colliding (web_port, db_host_port) for a new site.

    Unique ports per site are the most common deploy failure, so pre-fill the
    form with values that don't clash with any existing site config.
    """
    used_web, used_db = set(), set()
    configured_sites = list_sites()
    for site in configured_sites:
        try:
            used_web.add(int(site["website"]["port"]))
            used_db.add(int(site["database"]["host_port"]))
        except (TypeError, ValueError):
            continue
    web = 8080
    while web in used_web:
        web += 1
    db = 5432
    while db in used_db:
        db += 1
    return {
        "web_port": web,
        "db_host_port": db,
        "next_index": len(configured_sites) + 1,
    }


# --- Deployment ------------------------------------------------------------
def _publication_artifact_paths(site_id):
    """Files whose presence means a site has been publicly published."""
    site_id = _validate_site_id(site_id)
    monitoring = _monitoring_defaults()
    return (
        _proxy_defaults()["conf_dir"] / f"{site_id}.conf",
        monitoring["rules_dir"] / f"{site_id}.yml",
        monitoring["targets_dir"] / f"{site_id}.yml",
    )


def _certbot_reconcile_container(site_id):
    """Deterministic daemon-side container used by this site's TLS task."""
    return f"abd-certbot-reconcile-{_validate_site_id(site_id)}"


def _publication_lock_owned_by(site_id):
    owner = config.PROJECT_ROOT / "configs" / ".publication.lock" / "owner"
    try:
        return owner.read_text(encoding="utf-8").strip() == f"site_id={site_id}"
    except OSError:
        return False


def _acquire_publication_lock(site_id):
    """Atomically own publication across Ansible and parent-side rollback."""
    lock_dir = config.PROJECT_ROOT / "configs" / ".publication.lock"
    try:
        lock_dir.mkdir()
        (lock_dir / "owner").write_text(
            f"site_id={site_id}\n", encoding="utf-8"
        )
    except FileExistsError:
        return (
            f"Another deployment/TLS/public-host transaction owns {lock_dir}. "
            "Wait for it to finish; inspect the owner file before manually "
            "removing a stale retained lock."
        )
    except OSError as exc:
        try:
            lock_dir.rmdir()
        except OSError:
            pass
        return f"Could not acquire publication safety lock {lock_dir}: {exc}"
    return None


def _release_publication_lock(site_id):
    """Release only the lock owned by this site deployment."""
    lock_dir = config.PROJECT_ROOT / "configs" / ".publication.lock"
    if not lock_dir.exists():
        return None
    if not _publication_lock_owned_by(site_id):
        return f"publication safety lock {lock_dir} changed owner"
    try:
        for child in lock_dir.iterdir():
            child.unlink()
        lock_dir.rmdir()
    except OSError as exc:
        return f"publication safety lock {lock_dir} could not be released: {exc}"
    return None


def _stop_certbot_reconcile(site_id):
    """Stop Certbot in Docker before restoring files after process death.

    Killing Ansible's local process group does not necessarily stop a container
    already handed to the Docker daemon. The deterministic ``--name`` passed by
    the publication role lets the parent stop and reap that mutation boundary
    before it restores nginx/monitoring artifacts.
    """
    name = _certbot_reconcile_container(site_id)
    try:
        result = subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return f"could not confirm daemon-side Certbot container {name} stopped"
    detail = f"{result.stdout}\n{result.stderr}"
    if result.returncode != 0 and "No such container" not in detail:
        return f"could not stop daemon-side Certbot container {name}"
    return None


def _persist_publication_snapshot(site_id, snapshot):
    """Persist an in-memory artifact snapshot when rollback must be deferred."""
    lock_dir = config.PROJECT_ROOT / "configs" / ".publication.lock"
    recovery_dir = lock_dir / "recovery"
    try:
        recovery_dir.mkdir(mode=0o700, exist_ok=True)
        artifacts = []
        for index, (path, previous) in enumerate(snapshot.items()):
            entry = {"path": str(path), "present": previous is not None}
            if previous is not None:
                content, mode = previous
                backup_name = f"artifact-{index}.bin"
                backup_path = recovery_dir / backup_name
                with open(backup_path, "wb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(backup_path, 0o600)
                entry.update({"backup": backup_name, "mode": mode})
            artifacts.append(entry)

        manifest = {
            "site_id": site_id,
            "reason": "daemon-side Certbot stop could not be confirmed",
            "artifacts": artifacts,
        }
        temporary = recovery_dir / ".manifest.json.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, recovery_dir / "manifest.json")
        return recovery_dir, None
    except OSError as exc:
        return recovery_dir, str(exc)


def _blocked_publication_rollback(site_id, stop_warning, snapshot):
    """Explain why restoring publication files is unsafe and retain the lock.

    Certbot runs behind the Docker daemon, outside Ansible's process group. If
    the parent cannot prove that deterministic container is gone, it may still
    be mutating the certificate lineage. Restoring route/TLS-related state in
    parallel would turn a recoverable failed deploy into an indeterminate
    mixed generation, so the snapshot and publication lock deliberately stay
    in place for an operator to reconcile.
    """
    lock_dir = config.PROJECT_ROOT / "configs" / ".publication.lock"
    recovery_dir, persistence_error = _persist_publication_snapshot(
        site_id, snapshot
    )
    detail = (
        "\nRollback blocked: "
        f"{stop_warning}. No publication files were restored because the "
        "daemon-side certificate mutation may still be active. "
        f"Safety lock retained at {lock_dir}; confirm the Certbot container "
        "has stopped, then use the recovery manifest at "
        f"{recovery_dir / 'manifest.json'} to restore the captured artifacts "
        "and reconcile TLS, or complete the publication transaction manually."
    )
    if persistence_error:
        detail += (
            " Snapshot persistence also failed: "
            f"{persistence_error}; preserve the running app process and seek "
            "operator recovery before removing the lock."
        )
    return detail


def _snapshot_publication(site_id):
    """Capture exact pre-deploy artifacts for process-death rollback.

    Ansible's block/rescue handles ordinary task failures. A user cancellation,
    timeout, or external SIGKILL can terminate Ansible before rescue runs, so
    the parent process keeps this second, independent rollback boundary.
    """
    snapshot = {}
    for path in _publication_artifact_paths(site_id):
        try:
            file_stat = path.stat()
            snapshot[path] = (path.read_bytes(), file_stat.st_mode & 0o777)
        except FileNotFoundError:
            snapshot[path] = None
    return snapshot


def _reload_after_publication_rollback():
    """Best-effort activation of restored files; return actionable warnings."""
    warnings = []
    proxy_container = _proxy_defaults()["container"]
    prometheus_container = _monitoring_defaults()["prometheus_container"]
    try:
        checked = subprocess.run(
            ["docker", "exec", proxy_container, "nginx", "-t"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if checked.returncode == 0:
            reloaded = subprocess.run(
                ["docker", "exec", proxy_container, "nginx", "-s", "reload"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if reloaded.returncode != 0:
                warnings.append("nginx rejected the rollback reload")
        else:
            warnings.append("nginx could not validate the restored route set")
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        warnings.append("nginx could not be reached to activate the restored route set")

    try:
        all_yml = load_all_yml()
        proxy = all_yml.get("proxy", {}) or {}
        reconcile_tls = bool(
            proxy.get("tls_auto_expand")
            and proxy.get("tls_fullchain")
            and proxy.get("tls_key")
        )
    except Exception:
        reconcile_tls = False
    if reconcile_tls:
        try:
            reconciled = subprocess.run(
                [str(config.PROJECT_ROOT / "scripts" / "setup-letsencrypt.sh")],
                cwd=str(config.PROJECT_ROOT),
                capture_output=True,
                text=True,
                timeout=240,
                env={**os.environ, "ABD_PUBLICATION_LOCK_HELD": "1"},
            )
            if reconciled.returncode != 0:
                warnings.append(
                    "trusted TLS could not be reconciled with restored routes"
                )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            warnings.append(
                "trusted TLS reconciliation did not finish after route rollback"
            )

    try:
        # Alert rules need SIGHUP. Blackbox file_sd targets are refreshed by
        # Prometheus automatically, so this command is harmless if only a
        # target file changed.
        reloaded = subprocess.run(
            ["docker", "kill", "--signal=HUP", prometheus_container],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if reloaded.returncode != 0:
            warnings.append("Prometheus rejected the restored-rule reload")
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        warnings.append("Prometheus could not be reached to reload restored rules")
    return warnings


def _restore_publication(snapshot, prior_warnings=None):
    """Atomically restore/delete publication files captured before deployment."""
    errors = []
    for path, previous in snapshot.items():
        temporary = None
        try:
            if previous is None:
                path.unlink(missing_ok=True)
                continue
            content, mode = previous
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(
                prefix=f".{path.name}.rollback-", dir=path.parent
            )
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
                os.fchmod(handle.fileno(), mode)
            os.replace(temporary, path)
            temporary = None
        except OSError as exc:
            errors.append(f"{path}: {exc}")
        finally:
            if temporary:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    # A killed Ansible process can leave this non-included staging file. It is
    # never a valid durable artifact and should not survive a failed operation.
    route_path = next(iter(snapshot))
    candidate = route_path.parent / f".{route_path.stem}.candidate"
    try:
        candidate.unlink(missing_ok=True)
    except OSError as exc:
        errors.append(f"{candidate}: {exc}")

    warnings = list(prior_warnings or [])
    warnings.extend(_reload_after_publication_rollback())
    lock_dir = config.PROJECT_ROOT / "configs" / ".publication.lock"
    if not errors and not warnings and lock_dir.exists():
        release_warning = _release_publication_lock(route_path.stem)
        if release_warning:
            warnings.append(release_warning)
    detail = "\nRestored the pre-deploy route and monitoring publication state."
    if errors or warnings:
        detail += "\nRollback warning: " + "; ".join(errors + warnings) + "."
        if lock_dir.exists():
            detail += f" Safety lock retained at {lock_dir}."
    return detail


def write_site_config(site_id, *, scraper_version, port, genmode, db_user, db_password, db_host_port):
    """Write ``configs/sites/<site_id>.yaml`` from submitted form values."""
    site_id = _validate_site_id(site_id)
    config.SITES_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cfg = {
        "scraper_version": str(scraper_version),
        "website": {"genmode": "true" if genmode else "false", "port": str(port)},
        "database": {"host_port": str(db_host_port)},
    }
    # Preserve a hand-set proxy override (server_name / server_aliases) across
    # UI rewrites: the form has no proxy fields, so dropping the block here
    # would silently re-point the site at the default hostname on redeploy.
    site_yaml = config.SITES_CONFIG_DIR / f"{site_id}.yaml"
    if site_yaml.exists():
        try:
            with open(site_yaml) as handle:
                existing = _yaml_load(handle) or {}
            if existing.get("proxy"):
                cfg["proxy"] = existing["proxy"]
        except Exception:
            pass
    if db_user:
        cfg["database"]["user"] = db_user
    if db_password:
        cfg["database"]["password"] = db_password
    # Generator-authored flavors carry their own category-typed varList
    # (configs/generated_templates.json); embed it so the playbook renders
    # varLists/scraper<N>.txt from these tokens instead of the global
    # canary_tokens in all.yml. Hand-made flavors keep the global default.
    tokens = template_gen.canary_tokens_for(scraper_version)
    if tokens:
        cfg["canary_tokens"] = tokens
    with open(config.SITES_CONFIG_DIR / f"{site_id}.yaml", "w") as handle:
        _yaml_dump(cfg, handle)
    return cfg


def deploy_site(site_id, reset_db=False, timeout=900, task=None):
    """Run the Ansible playbook for ``site_id``; return (ok, combined_output).

    The ordinary synchronous path is retained for CLI callers and unit tests.
    The web path supplies a ``TaskContext``: Ansible then runs in its own
    process group, is registered with the task, and can be stopped (including
    children it spawned) from the Site Configurator's Cancel button.
    """
    site_id = _validate_site_id(site_id)
    if task is not None:
        task.check_cancelled()
    lock_error = _acquire_publication_lock(site_id)
    if lock_error:
        _append_history(site_id, reset_db, False, status="publication_busy")
        return False, lock_error
    try:
        publication_snapshot = _snapshot_publication(site_id)
    except Exception:
        _release_publication_lock(site_id)
        raise
    cmd = ["ansible-playbook", "site.yml", "-e", f"site_id={site_id}"]
    if reset_db:
        cmd += ["-e", "reset_db=true"]
    if task is not None:
        return _deploy_site_cancellable(
            site_id, reset_db, timeout, cmd, task, publication_snapshot
        )
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(config.ANSIBLE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
            env={**os.environ, "ABD_PUBLICATION_LOCK_HELD": "1"},
        )
        output, _ = proc.communicate(timeout=timeout)
        ok = proc.returncode == 0
        if not ok and _publication_lock_owned_by(site_id):
            output = output or ""
            stop_warning = _stop_certbot_reconcile(site_id)
            if stop_warning:
                output += _blocked_publication_rollback(
                    site_id, stop_warning, publication_snapshot
                )
            else:
                output += _restore_publication(publication_snapshot)
        elif ok:
            release_warning = _release_publication_lock(site_id)
            if release_warning:
                ok = False
                output = (output or "") + f"\n{release_warning}."
    except FileNotFoundError:
        _release_publication_lock(site_id)
        ok, output = False, (
            "ansible-playbook not found. Run the app in its container "
            "(make app) or install ansible-core to deploy from the host."
        )
    except subprocess.TimeoutExpired:
        trailing = _kill_process_group(proc)
        stop_warning = _stop_certbot_reconcile(site_id)
        ok = False
        output = (trailing or "") + f"\nDeploy timed out after {timeout}s."
        if stop_warning:
            output += _blocked_publication_rollback(
                site_id, stop_warning, publication_snapshot
            )
        else:
            output += _restore_publication(publication_snapshot)
    except KeyboardInterrupt:
        if proc is not None:
            _kill_process_group(proc, graceful=True)
        stop_warning = _stop_certbot_reconcile(site_id)
        if stop_warning:
            rollback_detail = _blocked_publication_rollback(
                site_id, stop_warning, publication_snapshot
            )
        else:
            rollback_detail = _restore_publication(publication_snapshot)
        if stop_warning or "Rollback warning:" in rollback_detail:
            _append_history(
                site_id, reset_db, False, status="interrupted_rollback_failed"
            )
            raise RuntimeError(
                "Deployment was interrupted, but publication rollback needs "
                f"operator attention.{rollback_detail}"
            ) from None
        _append_history(site_id, reset_db, False, status="interrupted")
        raise

    _append_history(site_id, reset_db, ok)
    return ok, output


def _kill_process_group(proc, graceful=False):
    """Stop Ansible and every local child it spawned, then reap it."""
    def kill_one():
        try:
            proc.kill()
        except (ProcessLookupError, OSError, AttributeError):
            pass

    sig = signal.SIGTERM if graceful else signal.SIGKILL
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, OSError, AttributeError):
        kill_one()
    if graceful:
        try:
            output, _ = proc.communicate(timeout=4)
            return output or ""
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError, AttributeError):
                kill_one()
    output, _ = proc.communicate()
    return output or ""


def _deploy_site_cancellable(
    site_id, reset_db, timeout, cmd, task, publication_snapshot
):
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(config.ANSIBLE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
            env={**os.environ, "ABD_PUBLICATION_LOCK_HELD": "1"},
        )
    except FileNotFoundError:
        _release_publication_lock(site_id)
        output = (
            "ansible-playbook not found. Run the app in its container "
            "(make app) or install ansible-core to deploy from the host."
        )
        _append_history(site_id, reset_db, False)
        return False, output

    task.attach_process(proc)
    task.update(label=f"Deploying {site_id} with Ansible…")
    try:
        try:
            output, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            output = _kill_process_group(proc)
            stop_warning = _stop_certbot_reconcile(site_id)
            output = (output or "") + f"\nDeploy timed out after {timeout}s."
            if stop_warning:
                output += _blocked_publication_rollback(
                    site_id, stop_warning, publication_snapshot
                )
            else:
                output += _restore_publication(publication_snapshot)
            _append_history(site_id, reset_db, False)
            return False, output
        task.check_cancelled()
        ok = proc.returncode == 0
        if not ok and _publication_lock_owned_by(site_id):
            stop_warning = _stop_certbot_reconcile(site_id)
            if stop_warning:
                output = (output or "") + _blocked_publication_rollback(
                    site_id, stop_warning, publication_snapshot
                )
            else:
                output = (output or "") + _restore_publication(
                    publication_snapshot
                )
        elif ok:
            release_warning = _release_publication_lock(site_id)
            if release_warning:
                ok = False
                output = (output or "") + f"\n{release_warning}."
        _append_history(site_id, reset_db, ok)
        return ok, output or ""
    except CancelledError:
        stop_warning = _stop_certbot_reconcile(site_id)
        if stop_warning:
            rollback_detail = _blocked_publication_rollback(
                site_id, stop_warning, publication_snapshot
            )
        else:
            rollback_detail = _restore_publication(publication_snapshot)
        if stop_warning or "Rollback warning:" in rollback_detail:
            _append_history(
                site_id, reset_db, False, status="cancelled_rollback_failed"
            )
            raise RuntimeError(
                "Deployment was cancelled, but publication rollback needs "
                f"operator attention.{rollback_detail}"
            )
        _append_history(site_id, reset_db, False, status="cancelled")
        raise
    finally:
        task.detach_process(proc)


def _append_history(site_id, reset_db, ok, status=None):
    config.HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.HISTORY_DIR / "applies.jsonl", "a") as handle:
        handle.write(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "site_id": site_id,
            "reset_db": reset_db,
            "status": status or ("ok" if ok else "failed"),
        }) + "\n")


# --- Retirement: take down / delete ----------------------------------------
# Retiring a site unwinds exactly what the publish role committed, in reverse:
#
#   1. Route first, containers last. A published route whose web container is
#      gone answers 502 — that tells a crawler something exists here and is
#      broken. Withdrawing the route first drops the hostname onto nginx's
#      catch-all (444), which is what "take this honeypot down" means, and it
#      stops the mirror immediately (unmatched traffic is never logged), so a
#      wind-down never lands attributable rows in ``all_visits``.
#   2. Monitoring next. The generated rules are absent()-based on purpose
#      (cAdvisor drops a stopped container's series entirely), so leaving
#      alerts.d/<id>.yml behind pages an operator forever for a take-down they
#      asked for, and the blackbox target keeps probing a dead hostname.
#   3. TLS is deliberately NOT reconciled. Shrinking the shared certificate
#      costs an ACME issuance against a rate-limited domain and buys nothing: a
#      SAN whose hostname no longer routes is unreachable (the catch-all
#      answers it). setup-letsencrypt.sh always reconciles to the exact
#      published route set, so the next deployment drops the stale name for
#      free — at a moment that is already issuing.
#
# Central ``all_visits`` history is never touched. It is the cross-site research
# record, and Crawler Analytics already reads a site with no published route as
# *historical* rather than active.


def _compose_dir(site_id):
    """The rendered Compose stack directory for a site, if one exists."""
    return config.WEBSITE_DIR / "sites" / _validate_site_id(site_id)


def _run_compose(site_id, args, timeout):
    """Run one ``docker compose`` command in a site's rendered stack directory.

    A site that was never rendered (config-only, or already deleted) has no
    stack to act on, which is success rather than an error.
    """
    directory = _compose_dir(site_id)
    if not (directory / "docker-compose.yml").exists():
        return True, ""
    try:
        result = subprocess.run(
            ["docker", "compose", *args],
            cwd=str(directory),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return False, (
            "docker not found. Run the app in its container (make app) so the "
            "host Docker socket and CLI are available."
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"docker compose {' '.join(args)} did not finish: {exc}"
    output = f"{result.stdout or ''}{result.stderr or ''}".strip()
    return result.returncode == 0, output


def _nginx_apply():
    """Validate then reload nginx after a route file changed.

    Returns ``(ok, detail)``. ``ok`` False means nginx is still serving the
    previous configuration, so the caller must restore its snapshot.
    """
    container = _proxy_defaults()["container"]
    for argv, failure in (
        (["nginx", "-t"], "nginx rejected the resulting configuration"),
        (["nginx", "-s", "reload"], "nginx refused to reload"),
    ):
        try:
            result = subprocess.run(
                ["docker", "exec", container, *argv],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            return False, f"{container} could not be reached: {exc}"
        if result.returncode != 0:
            detail = f"{result.stderr or ''}{result.stdout or ''}".strip()
            return False, f"{failure}: {detail}"
    return True, ""


def _prometheus_reload():
    """SIGHUP Prometheus so a withdrawn site's alert rules stop evaluating.

    Best-effort by design: blackbox file_sd targets are re-read automatically,
    and a rule that keeps evaluating until the next reload is a monitoring
    annoyance, never a reason to fail a completed take-down. A stopped
    Prometheus reads the reduced rule set from disk when it next starts, so it
    is not reported as a problem.
    """
    container = _monitoring_defaults()["prometheus_container"]
    running = _running_container_statuses()
    if running is not None and container not in running:
        return None
    try:
        result = subprocess.run(
            ["docker", "kill", "--signal=HUP", container],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return f"{container} could not be reached to drop this site's alert rules"
    if result.returncode != 0:
        return f"{container} did not accept the alert-rule reload"
    return None


def _withdraw_publication(site_id, warnings):
    """Remove this site's route + monitoring artifacts and activate the change.

    Returns ``None`` on success, or a failure detail string when nginx refused
    the reduced configuration (the caller then restores its snapshot).
    """
    route_path = _proxy_defaults()["conf_dir"] / f"{site_id}.conf"
    if route_path.exists():
        proxy_container = _proxy_defaults()["container"]
        running = _running_container_statuses()
        route_path.unlink()
        if running is not None and proxy_container not in running:
            # Removing an include target can never make nginx's config invalid,
            # so a stopped proxy is no reason to refuse: the withdrawn route
            # simply is not served, and never loads when the proxy restarts.
            warnings.append(
                f"{proxy_container} is not running; the withdrawn route takes "
                "effect when the proxy next starts"
            )
        else:
            ok, detail = _nginx_apply()
            if not ok:
                return detail

    monitoring = _monitoring_defaults()
    for path in (
        monitoring["rules_dir"] / f"{site_id}.yml",
        monitoring["targets_dir"] / f"{site_id}.yml",
    ):
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            warnings.append(f"{path.name} could not be removed: {exc}")
    reload_warning = _prometheus_reload()
    if reload_warning:
        warnings.append(reload_warning)
    return None


def _retire_site(site_id, *, destroy, timeout, task):
    """Shared take-down/delete transaction; returns ``(ok, detail)``.

    ``destroy`` False stops the containers but keeps the stack, its volumes,
    and ``configs/sites/<id>.yaml``, so a later deploy brings the same site
    back with its stored visits and canary assignments intact. ``destroy`` True
    removes the stack, its data volume, and the site's configuration.
    """
    site_id = _validate_site_id(site_id)
    if task is not None:
        task.check_cancelled()
    noun = "Deletion" if destroy else "Take-down"
    history_status = "deleted" if destroy else "stopped"

    lock_error = _acquire_publication_lock(site_id)
    if lock_error:
        _append_history(site_id, destroy, False, status="publication_busy")
        return False, lock_error
    try:
        snapshot = _snapshot_publication(site_id)
    except Exception:
        _release_publication_lock(site_id)
        raise

    warnings = []
    if task is not None:
        task.update(label=f"Withdrawing {site_id}'s public route…")
    failure = _withdraw_publication(site_id, warnings)
    if failure:
        # Nothing has been stopped yet, so restoring the route/monitoring files
        # returns the site to exactly its pre-request state.
        _append_history(site_id, destroy, False, status=f"{history_status}_refused")
        return False, (
            f"{noun} of {site_id} was refused: {failure}. The site was left "
            "published and running." + _restore_publication(snapshot)
        )

    if task is not None:
        task.update(label=(
            f"Destroying {site_id}'s containers and data volume…" if destroy
            else f"Stopping {site_id}'s containers…"
        ))
    # `stop` keeps containers and volumes so a redeploy is a fast restart;
    # `down --volumes` is the explicit, destructive path. --remove-orphans
    # cleans up a service renamed by an earlier template revision.
    #
    # The timeout is Compose's own default, and deliberately not raised: it is
    # only ever spent by the *stateless* web container. `python server.py` is
    # PID 1 there, and the kernel does not deliver a default-disposition signal
    # to PID 1, so SIGTERM is ignored and the container always waits out the
    # ceiling before being killed — which costs nothing, because every byte of
    # its state lives in Postgres. The db container is the one that matters, and
    # postgres:16 sets STOPSIGNAL SIGINT (fast shutdown): it exits cleanly in
    # well under a second, and is WAL-crash-safe even if it did not. Raising
    # this number buys no safety and adds that many seconds to every take-down.
    args = (
        ["down", "--volumes", "--remove-orphans", "--timeout", "10"] if destroy
        else ["stop", "--timeout", "10"]
    )
    compose_ok, compose_output = _run_compose(site_id, args, timeout)
    if not compose_ok:
        _release_publication_lock(site_id)
        _append_history(site_id, destroy, False, status=f"{history_status}_partial")
        detail = (
            f"{site_id}'s public route and monitoring rules were withdrawn, but "
            f"its containers could not be {'destroyed' if destroy else 'stopped'}. "
            "The site is off the internet; its stack is still running locally. "
            f"Re-run this action to finish.\n{compose_output}"
        )
        # A partial failure is exactly when the operator needs every observation
        # this transaction made, not only the one that stopped it.
        if warnings:
            detail += "\nAlso: " + "; ".join(warnings) + "."
        return False, detail

    if destroy:
        rendered = _compose_dir(site_id)
        try:
            shutil.rmtree(rendered)
        except FileNotFoundError:
            pass
        except OSError as exc:
            warnings.append(f"rendered stack {rendered} could not be removed: {exc}")
        # The YAML goes last, and only once the stack is provably gone: while it
        # exists the site stays listed and redeployable, so a partially failed
        # delete is always retryable from the same page instead of orphaning a
        # running stack the UI can no longer see.
        try:
            (config.SITES_CONFIG_DIR / f"{site_id}.yaml").unlink(missing_ok=True)
        except OSError as exc:
            _release_publication_lock(site_id)
            _append_history(site_id, destroy, False, status="deleted_partial")
            return False, (
                f"{site_id} was withdrawn and its stack destroyed, but its "
                f"configuration could not be removed: {exc}"
            )

    release_warning = _release_publication_lock(site_id)
    if release_warning:
        warnings.append(release_warning)
    _append_history(site_id, destroy, True, status=history_status)

    detail = (
        f"{site_id} deleted: route withdrawn, containers and data volume "
        "destroyed, configuration removed. Its past requests remain in the "
        "central log as historical traffic."
        if destroy else
        f"{site_id} taken down: route withdrawn and containers stopped. Its "
        "configuration, database volume, and canary assignments are kept — "
        "deploy it again to bring it back."
    )
    if warnings:
        detail += "\nWarning: " + "; ".join(warnings) + "."
    return True, detail


def stop_site(site_id, *, timeout=180, task=None):
    """Withdraw a site's route and stop its stack, keeping its config + data."""
    return _retire_site(site_id, destroy=False, timeout=timeout, task=task)


def delete_site(site_id, *, timeout=180, task=None):
    """Withdraw a site's route and destroy its stack, data volume, and config."""
    return _retire_site(site_id, destroy=True, timeout=timeout, task=task)
