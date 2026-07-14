"""Site configuration + deployment service.

Reads/writes the Ansible variable contract (``ansible/group_vars/all.yml`` global
defaults + per-site overrides in ``configs/sites/<id>.yaml``), lists the scraper
HTML flavors, and deploys a site by shelling ``ansible-playbook`` — the same flow
the old Streamlit ``Site_Config`` page + ``build.py`` performed, ported here.
"""

import json
import re
import subprocess
from datetime import datetime, timezone

from ruamel.yaml import YAML

from .. import config
from . import template_gen

_yaml = YAML()
_yaml.preserve_quotes = True


# --- all.yml (global defaults) --------------------------------------------
def load_all_yml():
    with open(config.ALL_YML) as handle:
        return _yaml.load(handle)


def save_all_yml(data):
    with open(config.ALL_YML, "w") as handle:
        _yaml.dump(data, handle)


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
    return {
        "base_domain": proxy.get("base_domain", "dukecodeplus.example"),
        "local_base_domain": proxy.get("local_base_domain", "dukecodeplus.localhost"),
    }


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
    defaults = _merged_defaults()
    path = config.SITES_CONFIG_DIR / f"{site_id}.yaml"
    overrides = {}
    if path.exists():
        with open(path) as handle:
            overrides = _yaml.load(handle) or {}

    scraper_version = int(overrides.get("scraper_version", defaults["scraper_version"]))
    website = {**defaults["website"], **(overrides.get("website") or {})}
    database = {**defaults["database"], **(overrides.get("database") or {})}
    proxy = _proxy_defaults()
    hostname = (overrides.get("proxy", {}) or {}).get(
        "server_name", f"{site_id}.{proxy['base_domain']}"
    )
    return {
        "site_id": site_id,
        "scraper_version": scraper_version,
        "db_name": f"scraper{scraper_version}-db",
        "website": website,
        "database": database,
        "hostname": hostname,
        "local_hostname": f"{site_id}.{proxy['local_base_domain']}",
        "deployed": (config.WEBSITE_DIR / "sites" / site_id / "docker-compose.yml").exists(),
    }


def list_sites():
    """Return merged config for every configured site (``configs/sites/*.yaml``)."""
    sites = []
    if config.SITES_CONFIG_DIR.exists():
        for path in sorted(config.SITES_CONFIG_DIR.glob("*.yaml")):
            sites.append(merged_site_config(path.stem))
    return sites


def active_proxy_sites():
    """Canonical hostnames currently configured as reverse-proxy routes."""
    sites = set()
    if not config.PROXY_CONF_D.exists():
        return []
    for path in config.PROXY_CONF_D.glob("*.conf"):
        text = path.read_text()
        canonical = re.search(r"\bset\s+\$site_name\s+([^;]+);", text)
        if canonical:
            sites.add(canonical.group(1).strip())
            continue
        names = re.search(r"\bserver_name\s+([^;]+);", text)
        if names:
            sites.add(names.group(1).split()[0])
    return sorted(sites)


def local_site_url(site_id):
    return f"http://{merged_site_config(site_id)['local_hostname']}/"


def suggest_ports():
    """Suggest the next non-colliding (web_port, db_host_port) for a new site.

    Unique ports per site are the most common deploy failure, so pre-fill the
    form with values that don't clash with any existing site config.
    """
    used_web, used_db = set(), set()
    for site in list_sites():
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
    return {"web_port": web, "db_host_port": db, "next_index": len(list_sites()) + 1}


# --- Deployment ------------------------------------------------------------
def write_site_config(site_id, *, scraper_version, port, genmode, db_user, db_password, db_host_port):
    """Write ``configs/sites/<site_id>.yaml`` from submitted form values."""
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
                existing = _yaml.load(handle) or {}
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
        _yaml.dump(cfg, handle)
    return cfg


def deploy_site(site_id, reset_db=False, timeout=900):
    """Run the Ansible playbook for ``site_id``; return (ok, combined_output)."""
    cmd = ["ansible-playbook", "site.yml", "-e", f"site_id={site_id}"]
    if reset_db:
        cmd += ["-e", "reset_db=true"]
    try:
        result = subprocess.run(
            cmd, cwd=str(config.ANSIBLE_DIR),
            capture_output=True, text=True, timeout=timeout,
        )
        output = (result.stdout or "") + (result.stderr or "")
        ok = result.returncode == 0
    except FileNotFoundError:
        ok, output = False, (
            "ansible-playbook not found. Run the app in its container "
            "(make app) or install ansible-core to deploy from the host."
        )
    except subprocess.TimeoutExpired:
        ok, output = False, f"Deploy timed out after {timeout}s."

    _append_history(site_id, reset_db, ok)
    return ok, output


def _append_history(site_id, reset_db, ok):
    config.HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.HISTORY_DIR / "applies.jsonl", "a") as handle:
        handle.write(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "site_id": site_id,
            "reset_db": reset_db,
            "status": "ok" if ok else "failed",
        }) + "\n")
