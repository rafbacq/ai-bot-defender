"""Cross-component static contracts — the wiring that connects the layers.

These are cheap, dependency-free invariants that, if broken, silently disconnect
parts of the system (a honeypot page that never beacons, a request that never
mirrors, a route that renders a template that no longer exists). They guard the
seams between the website, the proxy/Ansible deployment, and the web app — exactly
the kind of drift that goes unnoticed until a page 500s in production.
"""

from __future__ import annotations

import re


def test_honeypot_templates_expose_canaries_and_load_the_fingerprint_beacon(repo_root):
    """Every stored honeypot page has canary slots and loads fp.js; every varList
    defines >=10 canary generators."""
    templates = sorted((repo_root / "website" / "templates").glob("scraper*.html"))
    assert templates, "expected at least one scraper template"
    for template in templates:
        text = template.read_text(encoding="utf-8")
        slots = {int(m) for m in re.findall(r"\{\{\s*var(\d+)\s*\}\}", text)}
        assert len(slots) >= 5, f"{template.name} should expose several canary slots"
        assert slots <= set(range(1, 11)), f"{template.name} references an unknown var slot"
        assert "/js/fp.js" in text, f"{template.name} must load the fingerprint beacon"

    for var_file in sorted((repo_root / "website" / "varLists").glob("scraper*.txt")):
        lines = [ln for ln in var_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) >= 10, f"{var_file.name} should define >=10 canary generators"


def test_deployment_templates_preserve_logging_routing_and_indirections(repo_root):
    """The Ansible/nginx templates keep request mirroring, fp-beacon routing, the
    X-Site/X-Client-Port join headers, and the scraper_version indirections."""
    site_conf = (repo_root / "ansible" / "roles" / "configure" / "templates" / "site.conf.j2").read_text(encoding="utf-8")
    compose = (repo_root / "ansible" / "roles" / "configure" / "templates" / "docker-compose.yml.j2").read_text(encoding="utf-8")
    tasks = (repo_root / "ansible" / "roles" / "configure" / "tasks" / "main.yml").read_text(encoding="utf-8")
    mirror = (repo_root / "proxy" / "snippets" / "mirror.conf").read_text(encoding="utf-8")
    nginx = (repo_root / "proxy" / "nginx.conf").read_text(encoding="utf-8")

    # Per-site nginx block: fp-beacon route + request mirror + canonical site tag.
    assert "location = /__fpbeacon" in site_conf
    assert "fp_upstream:8000" in site_conf
    assert "proxy_set_header X-Site $site_name;" in site_conf
    assert "proxy_set_header X-Client-Port $remote_port;" in site_conf
    assert "mirror /_mirror;" in site_conf
    assert "include /etc/nginx/snippets/mirror.conf;" in site_conf
    # The shared mirror target -> collector, carrying the 4-tuple join key.
    assert "set $collector collector;" in mirror
    assert "proxy_pass http://$collector:8000$request_uri;" in mirror
    assert "X-Client-Port $remote_port" in mirror
    # scraper_version indirection + shared proxy network + web alias in the compose.
    assert "SCRAPER_VERSION" in compose
    assert "scraper{{ scraper_version }}-db" in compose
    assert "proxy_net:" in compose and '"{{ site_id }}-web"' in compose
    # Generated scraper templates are never clobbered on re-apply.
    assert "force: false" in tasks
    # The security-load-bearing catch-all default server is still present.
    assert "default_server" in nginx


def test_anti_spoof_xff_is_overwritten_not_appended(repo_root):
    """nginx must SET X-Forwarded-For to $remote_addr, never append (which would let a
    bot prepend a fake IP the honeypot would trust for ASN/canary keying)."""
    site_conf = (repo_root / "ansible" / "roles" / "configure" / "templates" / "site.conf.j2").read_text(encoding="utf-8")
    assert "$proxy_add_x_forwarded_for" not in site_conf, "XFF must not be appended"
    assert "X-Forwarded-For $remote_addr" in site_conf


def test_every_template_main_renders_exists_on_disk(repo_root):
    """Each ``X.html`` that app/main.py renders must exist in app/templates — the
    guard against the page-rename drift that breaks routes silently."""
    main_src = (repo_root / "app" / "main.py").read_text(encoding="utf-8")
    referenced = set(re.findall(r'TemplateResponse\(\s*[^,]+,\s*"([a-z_]+\.html)"', main_src))
    assert referenced, "expected to find rendered templates in main.py"
    templates_dir = repo_root / "app" / "templates"
    for name in sorted(referenced):
        assert (templates_dir / name).exists(), f"main.py renders {name} but it is missing"


def test_base_nav_links_to_the_current_top_level_pages(repo_root):
    """The app's primary navigation points at the current pages (post-consolidation:
    Overview / Sites / Generator / Crawler Analytics / LLM Forensics)."""
    base = (repo_root / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    for href in ["'/'", "'/sites'", "'/generator'", "'/logs'", "'/query'"]:
        assert href in base, f"base.html navigation is missing {href}"
