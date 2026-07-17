"""Cross-component static contracts — the wiring that connects the layers.

These are cheap, dependency-free invariants that, if broken, silently disconnect
parts of the system (a honeypot page that never beacons, a request that never
mirrors, a route that renders a template that no longer exists). They guard the
seams between the website, the proxy/Ansible deployment, and the web app — exactly
the kind of drift that goes unnoticed until a page 500s in production.
"""

from __future__ import annotations

import re


def test_honeypot_templates_are_mobile_safe_and_keep_detection_contracts(repo_root):
    """Stored honeypots are self-contained, responsive, and retain detection."""
    templates = sorted((repo_root / "website" / "templates").glob("scraper*.html"))
    assert templates, "expected at least one scraper template"
    for template in templates:
        text = template.read_text(encoding="utf-8")
        slots = {int(m) for m in re.findall(r"\{\{\s*var(\d+)\s*\}\}", text)}
        assert len(slots) >= 5, f"{template.name} should expose several canary slots"
        assert slots <= set(range(1, 11)), f"{template.name} references an unknown var slot"
        assert "/js/fp.js" in text, f"{template.name} must load the fingerprint beacon"
        assert 'name="viewport"' in text, f"{template.name} needs a mobile viewport"
        assert "/css/site.css" in text, f"{template.name} needs the local site stylesheet"

    site_css = (repo_root / "website" / "static" / "css" / "site.css").read_text(
        encoding="utf-8"
    )
    assert "-webkit-text-size-adjust: 100%" in site_css
    assert "@media (max-width: 640px)" in site_css
    assert "env(safe-area-inset-left)" in site_css

    for var_file in sorted((repo_root / "website" / "varLists").glob("scraper*.txt")):
        lines = [ln for ln in var_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) >= 10, f"{var_file.name} should define >=10 canary generators"

    # Flask serves website/static at URL root. Crawlers request this exact path;
    # keeping the file under static/js would expose only /js/robots.txt.
    robots = repo_root / "website" / "static" / "robots.txt"
    assert robots.exists()
    assert "User-agent: *" in robots.read_text(encoding="utf-8")


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
    fp_block = site_conf.split("location = /__fpbeacon {", 1)[1].split("}", 1)[0]
    health_block = site_conf.split("location = /__abd_health {", 1)[1].split("}", 1)[0]
    acme_block = site_conf.split("location ^~ /.well-known/acme-challenge/ {", 1)[1].split("}", 1)[0]
    assert "access_log off;" in fp_block
    assert "access_log off;" in health_block
    assert "access_log off;" in acme_block
    # The shared mirror target -> collector, carrying the 4-tuple join key.
    assert "set $collector collector;" in mirror
    assert "proxy_pass http://$collector:8000$request_uri;" in mirror
    assert "X-Client-Port $remote_port" in mirror
    assert "X-Forwarded-Proto $scheme" in mirror
    assert "X-Request-ID $request_id" in mirror
    assert "access_log off;" in mirror
    assert "proxy_pass_request_body off;" in mirror
    assert 'proxy_set_header Content-Length "";' in mirror
    assert '"request_id":"$request_id"' in nginx
    # scraper_version indirection + shared proxy network + web alias in the compose.
    assert "SCRAPER_VERSION" in compose
    assert "scraper{{ scraper_version }}-db" in compose
    assert "proxy_net:" in compose and '"{{ site_id }}-web"' in compose
    # Generated scraper templates are never clobbered on re-apply.
    assert "force: false" in tasks
    # The security-load-bearing catch-all default server is still present.
    assert "default_server" in nginx


def test_proxy_start_rebinds_netns_sidecars_after_nginx_is_replaced(repo_root):
    """A replaced nginx must not strand Zeek or the prober on its retired netns."""
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    sync = (repo_root / "scripts" / "sync-tls-capture-netns.sh").read_text(
        encoding="utf-8"
    )

    # Both proxy start paths and monitoring startup reconcile namespace-bound
    # sidecars; the helper is idempotent when everything already matches.
    assert makefile.count("bash scripts/sync-tls-capture-netns.sh") == 3
    assert "{{.HostConfig.NetworkMode}}" in sync
    assert 'expected_mode="container:$nginx_id"' in sync
    assert "--no-deps --force-recreate tls-capture" in sync
    assert "capture_mode\" != \"$expected_mode" in sync
    assert "docker inspect mon-blackbox" in sync
    assert "--no-deps --force-recreate blackbox" in sync
    assert 'blackbox_mode" != "$expected_mode' in sync


def test_nginx_log_rotation_preserves_authoritative_status_lines(repo_root):
    logrotate = (repo_root / "proxy" / "logrotate.conf").read_text(encoding="utf-8")
    compose = (repo_root / "docker-compose.proxy.yml").read_text(encoding="utf-8")
    collector = (repo_root / "proxy" / "collector" / "app.py").read_text(
        encoding="utf-8"
    )

    assert not any(
        line.strip() == "copytruncate" for line in logrotate.splitlines()
    ), "rotation must rename/reopen rather than use the lossy directive"
    assert "sharedscripts" in logrotate
    assert ".reopen-required" in logrotate
    assert "nginx -s reopen" in compose
    assert ".reopen-required" in compose
    shared_interval = (
        "NGINX_LOG_REOPEN_POLL_SECONDS: "
        "${PROXY_LOG_REOPEN_POLL_SECONDS:-5}"
    )
    assert compose.count(shared_interval) == 2
    assert "sleep $${NGINX_LOG_REOPEN_POLL_SECONDS}" in compose
    assert '"NGINX_LOG_REOPEN_POLL_SECONDS", 5.0' in collector
    assert (
        "NGINX_LOG_REOPEN_POLL_SECONDS + ROTATION_DRAIN_SECONDS" in collector
    )
    assert "handle.seek(0)" not in collector, (
        "copytruncate recovery must swap to a fresh BufferedReader"
    )


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


def test_frontend_uses_duke_watch_branding_and_logo(repo_root):
    """Every rendered page inherits the new name, header logo, and favicon."""
    templates_dir = repo_root / "app" / "templates"
    templates = list(templates_dir.glob("*.html"))
    rendered_text = "\n".join(path.read_text(encoding="utf-8") for path in templates)
    base = (templates_dir / "base.html").read_text(encoding="utf-8")
    index = (templates_dir / "index.html").read_text(encoding="utf-8")
    logo = repo_root / "app" / "static" / "duke-watch-logo.png"

    assert "AI Bot Defender" not in rendered_text
    assert "Duke Watch" not in rendered_text
    assert "Duke WATCH" in rendered_text
    assert (
        "<h1>Duke WATCH</h1>\n"
        "    <p>WATCH stands for Web Attribution Through Canary Honeypots" in index
    )
    assert 'class="brand__logo" src="/static/duke-watch-logo.png"' in base
    assert 'rel="icon" type="image/png" href="/static/duke-watch-logo.png"' in base
    assert logo.exists() and logo.stat().st_size > 0


def test_analytics_filters_and_ajax_pager_keep_visible_page_state(repo_root):
    """Site values, header counts, and CSV export must track AJAX pagination."""
    analytics = (repo_root / "app" / "templates" / "analytics.html").read_text(
        encoding="utf-8"
    )

    assert '<option value="{{ s }}"' in analytics
    assert 'id="traffic-page-summary"' in analytics
    assert 'id="csv-export"' in analytics
    assert "summary.textContent = 'Page ' + page" in analytics
    assert "csv.href = '/logs/export.csv?' + urlForPage(page).search" in analytics
    main = (repo_root / "app" / "main.py").read_text(encoding="utf-8")
    assert 'colspan="8"' in main, "AJAX error rows must span the Status column too"
    assert "escape(str(exc))" in main, "database errors must be HTML-escaped"


def test_account_totp_code_posts_are_edge_rate_limited(repo_root):
    """Both self-service TOTP mutations share nginx's credential-rate zone."""
    admin_conf = (repo_root / "proxy" / "admin.d" / "admin.conf").read_text(
        encoding="utf-8"
    )
    for path in ("/account/2fa/enable", "/account/2fa/disable"):
        block = admin_conf.split(f"location = {path} {{", 1)[1].split("}", 1)[0]
        assert "limit_req zone=auth_slow" in block


def test_campaign_graph_allows_only_same_origin_framing(repo_root):
    """The analytics graph is an intentional same-origin iframe.

    A global X-Frame-Options DENY on the admin vhost makes browsers replace the
    graph with "refused to connect", even though both documents have the same
    origin. Keep outside framing blocked without rejecting the app's own embed.
    """
    campaigns = (repo_root / "app" / "templates" / "_campaigns.html").read_text(
        encoding="utf-8"
    )
    admin_conf = (repo_root / "proxy" / "admin.d" / "admin.conf").read_text(
        encoding="utf-8"
    )

    assert 'iframe src="/intel/graph.html' in campaigns
    assert "add_header X-Frame-Options SAMEORIGIN always;" in admin_conf
    assert 'add_header Content-Security-Policy "frame-ancestors \'self\'" always;' in admin_conf
    assert "add_header X-Frame-Options DENY" not in admin_conf


def test_every_processing_page_exposes_a_cancel_control(repo_root):
    """Every long-running button workflow has both UI and POST cancellation."""
    main = (repo_root / "app" / "main.py").read_text(encoding="utf-8")
    templates = repo_root / "app" / "templates"

    for route in (
        '/jobs/{job_id}/cancel',
        '/generator/cancel/{job_id}',
        '/query/runs/{run_id}/cancel',
        '/provenance/runs/{run_id}/cancel',
        '/selfplay/cancel',
    ):
        assert f'@app.post("{route}")' in main

    controls = {
        "_background_job.html": "data-job-cancel",
        "generator.html": "cancel-generation",
        "run_detail.html": "cancel-run",
        "provenance_detail.html": "cancel-probe",
        "selfplay.html": "cancel-selfplay",
    }
    for filename, marker in controls.items():
        text = (templates / filename).read_text(encoding="utf-8")
        assert marker in text, f"{filename} is missing its running-job cancel control"


def test_background_work_is_globally_discoverable_and_not_browser_owned(repo_root):
    """Navigation/visibility only affects rendering, never server execution."""
    main = (repo_root / "app" / "main.py").read_text(encoding="utf-8")
    base = (repo_root / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    generator = (repo_root / "app" / "templates" / "generator.html").read_text(
        encoding="utf-8"
    )
    shared = (repo_root / "app" / "templates" / "_background_job.html").read_text(
        encoding="utf-8"
    )

    assert '@app.get("/jobs/active")' in main
    assert 'id="active-jobs-link"' in base and "fetch('/jobs/active'" in base
    assert "visibilitychange" in base and "window.addEventListener('focus'" in base
    assert "close this tab" in generator.lower()
    assert "close this tab" in shared.lower()
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (repo_root / "app" / "templates").glob("*.html")
    )
    assert "beforeunload" not in combined
    assert "sendBeacon(" not in combined


def test_public_nav_exposes_every_account_access_destination(repo_root):
    """Logged-out visitors can reach login, access, signup, and administration."""
    base = (repo_root / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    links = {
        "/login": "Log in",
        "/request-access": "Request access",
        "/signup": "Create account",
        "/admin/approve": "Admin panel",
    }
    for href, label in links.items():
        anchor = f'href="{href}" class="main-nav__link">{label}</a>'
        assert anchor in base, f"public navigation is missing {label} ({href})"


def test_overview_stats_refresh_immediately_without_overlapping_intervals(repo_root):
    """The overview fetches uncached stats now, periodically, and on tab return."""
    index = (repo_root / "app" / "templates" / "index.html").read_text(encoding="utf-8")

    assert "fetch('/api/stats'" in index and "cache: 'no-store'" in index
    assert "refreshStats().finally(scheduleNext)" in index, "first refresh must not wait for a timer"
    assert "visibilitychange" in index and "window.addEventListener('focus', refreshStats)" in index
    assert "setInterval(" not in index, "fixed intervals can overlap slow database requests"
    assert "proves the model ingested" not in index, "a canary match is evidence, not proof"


def test_frontend_styles_are_same_origin_precompiled_and_mobile_safe(repo_root):
    """HTTPS/mobile rendering must not depend on mixed-content or CDN scripts."""
    base = (repo_root / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    app_css = (repo_root / "app" / "static" / "css" / "app.css").read_text(
        encoding="utf-8"
    )
    utility_path = repo_root / "app" / "static" / "css" / "tailwind.css"

    assert 'href="/static/css/app.css' in base
    assert 'href="/static/css/tailwind.css' in base
    assert "url_for('static'" not in base, "url_for emitted HTTP behind the HTTPS proxy"
    assert "cdn.tailwindcss.com" not in base, "production styling must not require CDN JS"
    assert "viewport-fit=cover" in base
    assert utility_path.exists() and utility_path.stat().st_size > 5_000
    utilities = utility_path.read_text(encoding="utf-8")
    assert ".grid" in utilities and "grid-template-columns" in utilities
    assert "@media (min-width:768px)" in utilities
    assert "-webkit-text-size-adjust: 100%" in app_css
    assert "font-size: 16px" in app_css, "iOS form fields must not trigger viewport zoom"
    assert "overflow-x: auto; justify-content: flex-start" in app_css, (
        "overflowing mobile nav links must remain reachable from the left edge"
    )


def test_manual_forensics_flow_has_one_target_and_progressive_responses(repo_root):
    """Manual querying stays bound to one site and reveals only needed inputs."""
    template = (repo_root / "app" / "templates" / "forensics.html").read_text(
        encoding="utf-8"
    )
    manual = template.split("<!-- Manual-query workflow", 1)[1].split(
        "<!-- Membership inference", 1
    )[0]
    initial_markup = manual.split('<template id="manual-response-template">', 1)[0]
    css = (repo_root / "app" / "static" / "css" / "app.css").read_text(
        encoding="utf-8"
    )

    # One visible selector generates the prompt. Evaluation inherits that exact
    # site in a hidden field instead of asking the user to choose twice.
    assert manual.count("<select") == 1
    assert 'id="manual-site"' in manual
    assert "data-prompt-site=" in manual
    assert 'type="hidden" name="site_id" value="{{ manual.site_id }}"' in manual

    # No spreadsheet chooser and only one live row at first; extra rows come from
    # an inert template when the user asks for them.
    assert 'type="file"' not in manual
    assert initial_markup.count('name="manual_response"') == 1
    assert 'id="add-manual-response"' in manual
    assert 'id="manual-response-template"' in manual

    # Long answers have a roomy editor while the inline cards remain compact.
    assert '<dialog class="manual-dialog"' in manual
    assert 'id="manual-response-editor"' in manual
    assert ".manual-dialog__editor" in css
    assert ".manual-response-row__fields" in css
    assert "@media (max-width: 760px)" in css
