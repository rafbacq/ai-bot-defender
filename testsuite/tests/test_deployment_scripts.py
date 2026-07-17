"""Static and shell contracts for safe site publication/TLS maintenance."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import time


def test_deployment_shell_scripts_parse(repo_root):
    scripts = [
        repo_root / "scripts" / "setup-letsencrypt.sh",
        repo_root / "scripts" / "set-public-host.sh",
        repo_root / "proxy" / "certbot-renew.sh",
    ]
    result = subprocess.run(
        ["bash", "-n", *(str(path) for path in scripts)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_letsencrypt_inventory_is_published_routes_only(repo_root):
    script = (repo_root / "scripts" / "setup-letsencrypt.sh").read_text(
        encoding="utf-8"
    )

    assert 'route_files=("$PROXY_CONF_DIR"/*.conf)' in script
    assert "RAW_PROXY_CONF_DIR" in script
    assert "configs/sites/*.yaml" not in script
    assert "$site_name" in script
    assert "--renew-with-new-domains" in script
    assert "docker exec proxy-nginx curl --noproxy '*'" in script
    assert "__abd_health" in script
    assert "-sk" not in script
    assert "certificate already covers every published hostname" in script
    assert "CERT_MATCHES_PUBLICATION" in script
    assert 'CURRENT_DOMAIN_COUNT" -ne "${#DOMAINS[@]}' in script
    assert 'CERT_MIN_VALID_SECONDS="${TLS_CERT_MIN_VALID_SECONDS:-1209600}"' in script
    assert '-noout -checkend "$CERT_MIN_VALID_SECONDS"' in script
    assert "ROUTES_TLS_WIRED" in script
    assert 'TLS_FULLCHAIN_VALUE" = "$LIVE/fullchain.pem"' in script
    assert 'TLS_KEY_VALUE" = "$LIVE/privkey.pem"' in script
    assert '--name "$CERTBOT_CONTAINER"' in script
    assert "abd_tls_transition_name" in script
    assert "PUBLICATION_LOCK_DIR" in script
    assert "valid_dns_name" in script
    assert 'PLAYBOOK_EXTRA="-e render_only=true -e skip_tls_sync=true"' in script


def test_public_host_change_never_deploys_yaml_only_sites_or_aliases_raw_ip(repo_root):
    script = (repo_root / "scripts" / "set-public-host.sh").read_text(
        encoding="utf-8"
    )

    assert 'route_files=("$PROXY_CONF_DIR"/*.conf)' in script
    assert "RAW_PROXY_CONF_DIR" in script
    assert "PUBLISHED_SITE_IDS" in script
    assert "run_site_playbook" in script
    assert "abd-public-host-playbook" in script
    assert 's|^(  server_aliases: )\\[[^]]*\\]|\\\\1[]|' in script
    assert "valid_ipv4" in script
    assert "valid_dns_name" in script
    assert "ALIASES=" not in script
    assert "preserve_tls_transition_alias=true" in script
    assert "refreshing ai-bot-defender-app with APP_BASE_URL" in script
    assert "safety lock retained" in script
    assert script.index('mkdir "$PUBLICATION_LOCK_DIR"') < script.index(
        'route_files=("$PROXY_CONF_DIR"/*.conf)'
    )
    assert script.rindex("COMMITTED=1") < script.rindex(
        "discard_trusted_lineage_snapshot"
    )
    assert 'safe_to_restore=1' in script
    assert 'if [ "$safe_to_restore" = "1" ]' in script
    assert '--name "$PLAYBOOK_CONTAINER"' in script
    assert '--name "$CERTGEN_CONTAINER" certgen' in script


def test_scheduled_certbot_renewal_uses_publication_lock(repo_root):
    compose = (repo_root / "docker-compose.proxy.yml").read_text(encoding="utf-8")
    wrapper = (repo_root / "proxy" / "certbot-renew.sh").read_text(
        encoding="utf-8"
    )

    assert "./configs:/project/configs" in compose
    assert "certbot-renew.sh:/usr/local/bin/certbot-renew.sh:ro" in compose
    assert "LOCK_DIR=/project/configs/.publication.lock" in wrapper
    assert 'mkdir "$LOCK_DIR"' in wrapper
    assert "operation=scheduled-certbot-renew" in wrapper
    assert wrapper.index('mkdir "$LOCK_DIR"') < wrapper.index("certbot renew")


def test_make_playbook_accepts_guarded_maintenance_arguments(repo_root):
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    all_yml = (repo_root / "ansible" / "group_vars" / "all.yml").read_text(
        encoding="utf-8"
    )

    assert "PLAYBOOK_EXTRA ?=" in makefile
    assert "site.yml -e site_id=$(site_id) $(PLAYBOOK_EXTRA)" in makefile
    assert makefile.count("@bash scripts/sync-tls-capture-netns.sh") == 3
    assert "docker kill --signal=HUP mon-prometheus" in makefile
    assert 'set-public-host: proxy app' in makefile
    assert '@bash scripts/set-public-host.sh "$(HOST)"' in makefile
    assert "server_aliases: []" in all_yml
    assert "tls_auto_expand: true" in all_yml
    assert 'targets_dir: "{{ project_root }}/monitoring/targets.d"' in all_yml
    assert "ABD_PUBLICATION_LOCK_HELD=$(ABD_PUBLICATION_LOCK_HELD)" in makefile


def _fake_docker_path(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(
        """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$DOCKER_CALL_LOG"
if [ "$1" = ps ]; then
    printf '%s\\n' proxy-nginx
elif [ "$1" = exec ] && [ "$3" = openssl ]; then
    if [[ "$*" == *"-checkend"* ]] && [ "${FAKE_CERT_VALID:-1}" != 1 ]; then
        exit 1
    fi
    printf '%s\\n' "$FAKE_CERT_OUTPUT"
elif [ "$1" = rm ]; then
    printf '%s\\n' 'Error: No such container' >&2
    exit 1
else
    exit 97
fi
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    return bin_dir


def _published_certificate_names(repo_root):
    all_yml = (repo_root / "ansible" / "group_vars" / "all.yml").read_text(
        encoding="utf-8"
    )
    base_domain = re.search(r'^  base_domain: "([^"]+)"', all_yml, re.MULTILINE)
    assert base_domain
    names = [f"admin.{base_domain.group(1)}"]
    for route in sorted((repo_root / "proxy" / "conf.d").glob("*.conf")):
        match = re.search(r"\bset\s+\$site_name\s+([^;]+);", route.read_text())
        assert match
        names.append(match.group(1).strip())
    return list(dict.fromkeys(names))


def test_letsencrypt_noop_requires_exact_valid_published_san_set(
    repo_root, tmp_path,
):
    """No-op requires an exact, non-expiring cert; drift forces reconcile."""
    bin_dir = _fake_docker_path(tmp_path)
    call_log = tmp_path / "docker.log"
    names = _published_certificate_names(repo_root)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "DOCKER_CALL_LOG": str(call_log),
        "FAKE_CERT_OUTPUT": "X509v3 Subject Alternative Name:\n    "
        + ", ".join(f"DNS:{name}" for name in names),
    }
    script = repo_root / "scripts" / "setup-letsencrypt.sh"

    exact = subprocess.run(
        ["bash", str(script)], cwd=repo_root, env=env,
        capture_output=True, text=True,
    )
    assert exact.returncode == 0, exact.stderr
    assert "certificate already covers every published hostname" in exact.stdout
    assert not any(
        line.startswith("compose ")
        for line in call_log.read_text(encoding="utf-8").splitlines()
    )

    call_log.write_text("", encoding="utf-8")
    env["FAKE_CERT_OUTPUT"] += ", DNS:retired.example.org"
    env["TLS_RETAIN_EXISTING"] = "1"
    transactional = subprocess.run(
        ["bash", str(script)], cwd=repo_root, env=env,
        capture_output=True, text=True,
    )
    assert transactional.returncode != 0
    assert any(
        line.startswith("compose ")
        for line in call_log.read_text(encoding="utf-8").splitlines()
    ), "unmarked stale SANs must be retired instead of poisoning later issuance"

    env.pop("TLS_RETAIN_EXISTING")
    call_log.write_text("", encoding="utf-8")
    env["FAKE_CERT_OUTPUT"] = "X509v3 Subject Alternative Name:\n    " + ", ".join(
        f"DNS:{name}" for name in names
    )
    env["FAKE_CERT_VALID"] = "0"
    expired = subprocess.run(
        ["bash", str(script)], cwd=repo_root, env=env,
        capture_output=True, text=True,
    )
    assert expired.returncode != 0
    assert any(
        line.startswith("compose ")
        for line in call_log.read_text(encoding="utf-8").splitlines()
    ), "an exact but expiring certificate must be renewed, never treated as a no-op"


def test_letsencrypt_changed_hostname_preserves_then_retires_old_sans(
    repo_root, tmp_path,
):
    """A→B publication keeps A valid; rollback reconcile returns to exact A."""
    project = tmp_path / "tls-project"
    for directory in (
        "scripts", "ansible/group_vars", "configs", "proxy/admin.d",
        "proxy/conf.d",
    ):
        (project / directory).mkdir(parents=True, exist_ok=True)
    script = project / "scripts" / "setup-letsencrypt.sh"
    script.write_bytes((repo_root / "scripts" / "setup-letsencrypt.sh").read_bytes())
    script.chmod(0o755)

    live = "/etc/letsencrypt/live/abd"

    def write_publication(base_domain, transition_domain=None):
        admin_transition = ""
        site_transition = ""
        admin_names = f"admin.{base_domain}"
        site_names = f"site-a.{base_domain}"
        if transition_domain:
            admin_old = f"admin.{transition_domain}"
            site_old = f"site-a.{transition_domain}"
            admin_transition = f"# abd_tls_transition_name {admin_old}\n"
            site_transition = f"# abd_tls_transition_name {site_old}\n"
            admin_names += f" {admin_old}"
            site_names += f" {site_old}"
        (project / "ansible/group_vars/all.yml").write_text(
            "proxy:\n"
            f'  base_domain: "{base_domain}"\n'
            "  server_aliases: []\n"
            f'  tls_fullchain: "{live}/fullchain.pem"\n'
            f'  tls_key: "{live}/privkey.pem"\n'
            '  conf_dir: "{{ project_root }}/proxy/conf.d"\n',
            encoding="utf-8",
        )
        (project / "proxy/admin.d/admin.conf").write_text(
            admin_transition
            + f"server_name {admin_names};\n"
            f"ssl_certificate {live}/fullchain.pem;\n"
            f"ssl_certificate_key {live}/privkey.pem;\n",
            encoding="utf-8",
        )
        (project / "proxy/conf.d/site-a.conf").write_text(
            site_transition
            + f"server_name {site_names};\n"
            f"set $site_name site-a.{base_domain};\n"
            f"ssl_certificate {live}/fullchain.pem;\n"
            f"ssl_certificate_key {live}/privkey.pem;\n",
            encoding="utf-8",
        )

    write_publication("new.example", transition_domain="old.example")
    cert_state = tmp_path / "cert-state"
    cert_state.write_text(
        "admin.old.example\nsite-a.old.example\n", encoding="utf-8"
    )
    docker_log = tmp_path / "tls-docker.log"
    bin_dir = tmp_path / "tls-bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(
        r'''#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$DOCKER_CALL_LOG"
if [ "$1" = ps ]; then
    printf '%s\n' proxy-nginx
elif [ "$1" = exec ] && [ "$3" = openssl ]; then
    if [[ "$*" == *"-checkend"* ]]; then
        exit 0
    fi
    printf '%s\n' 'X509v3 Subject Alternative Name:'
    first=1
    while IFS= read -r domain; do
        [ -n "$domain" ] || continue
        if [ "$first" = 1 ]; then
            printf '    DNS:%s' "$domain"
            first=0
        else
            printf ', DNS:%s' "$domain"
        fi
    done < "$CERT_STATE"
    printf '\n'
elif [ "$1" = compose ]; then
    : > "$CERT_STATE.next"
    take_domain=0
    for argument in "$@"; do
        if [ "$take_domain" = 1 ]; then
            printf '%s\n' "$argument" >> "$CERT_STATE.next"
            take_domain=0
        elif [ "$argument" = -d ]; then
            take_domain=1
        fi
    done
    mv "$CERT_STATE.next" "$CERT_STATE"
elif [ "$1" = rm ]; then
    printf '%s\n' 'Error: No such container' >&2
    exit 1
elif [ "$1" = exec ] && [ "$3" = curl ]; then
    if [[ "$*" == *"__abd_health"* ]]; then
        printf 204
    else
        printf 303
    fi
elif [ "$1" = exec ] && [ "$3" = nginx ]; then
    exit 0
else
    exit 98
fi
''',
        encoding="utf-8",
    )
    docker.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "CERT_STATE": str(cert_state),
        "DOCKER_CALL_LOG": str(docker_log),
    }

    forward = subprocess.run(
        ["bash", str(script)], cwd=project,
        env={**env, "TLS_RETAIN_EXISTING": "1"},
        capture_output=True, text=True,
    )
    assert forward.returncode == 0, forward.stderr
    assert set(cert_state.read_text(encoding="utf-8").splitlines()) == {
        "admin.old.example", "site-a.old.example",
        "admin.new.example", "site-a.new.example",
    }

    write_publication("old.example")
    rollback = subprocess.run(
        ["bash", str(script)], cwd=project, env=env,
        capture_output=True, text=True,
    )
    assert rollback.returncode == 0, rollback.stderr
    assert cert_state.read_text(encoding="utf-8").splitlines() == [
        "admin.old.example", "site-a.old.example",
    ]
    assert sum(
        line.startswith("compose ")
        for line in docker_log.read_text(encoding="utf-8").splitlines()
    ) == 2


def test_letsencrypt_retains_lock_when_daemon_certbot_stop_is_unconfirmed(
    repo_root, tmp_path,
):
    """SIGTERM cannot release the shared lock while named Certbot may survive."""
    project = tmp_path / "tls-stop-project"
    for directory in (
        "scripts", "ansible/group_vars", "configs", "proxy/admin.d",
        "proxy/conf.d",
    ):
        (project / directory).mkdir(parents=True, exist_ok=True)
    script = project / "scripts" / "setup-letsencrypt.sh"
    script.write_bytes((repo_root / "scripts" / "setup-letsencrypt.sh").read_bytes())
    script.chmod(0o755)
    live = "/etc/letsencrypt/live/abd"
    (project / "ansible/group_vars/all.yml").write_text(
        "proxy:\n"
        '  base_domain: "new.example"\n'
        "  server_aliases: []\n"
        f'  tls_fullchain: "{live}/fullchain.pem"\n'
        f'  tls_key: "{live}/privkey.pem"\n',
        encoding="utf-8",
    )
    for path, hostname in (
        (project / "proxy/admin.d/admin.conf", "admin.new.example"),
        (project / "proxy/conf.d/site-a.conf", "site-a.new.example"),
    ):
        canonical = "" if hostname.startswith("admin.") else f"set $site_name {hostname};\n"
        path.write_text(
            f"server_name {hostname};\n{canonical}"
            f"ssl_certificate {live}/fullchain.pem;\n"
            f"ssl_certificate_key {live}/privkey.pem;\n",
            encoding="utf-8",
        )

    marker = tmp_path / "certbot-started"
    bin_dir = tmp_path / "tls-stop-bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(
        r'''#!/usr/bin/env bash
if [ "$1" = ps ]; then
    printf '%s\n' proxy-nginx
elif [ "$1" = exec ] && [ "$3" = openssl ]; then
    if [[ "$*" == *"-checkend"* ]]; then exit 0; fi
    printf '%s\n' 'X509v3 Subject Alternative Name:'
    printf '%s\n' '    DNS:admin.old.example, DNS:site-a.old.example'
elif [ "$1" = compose ]; then
    : > "$CERTBOT_STARTED"
    trap 'exit 143' TERM INT
    while :; do sleep 1; done
elif [ "$1" = rm ]; then
    exit 55
else
    exit 98
fi
''',
        encoding="utf-8",
    )
    docker.chmod(0o755)
    proc = subprocess.Popen(
        ["bash", str(script)], cwd=project,
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "CERTBOT_STARTED": str(marker),
        },
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True,
    )
    deadline = time.monotonic() + 5
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert marker.exists(), "fake daemon-side Certbot never started"
    os.killpg(proc.pid, signal.SIGTERM)
    stdout, stderr = proc.communicate(timeout=5)

    assert proc.returncode != 0, stdout
    lock = project / "configs/.publication.lock"
    assert lock.is_dir()
    owner = (lock / "owner").read_text(encoding="utf-8")
    assert "action=confirm-certbot-stopped" in owner
    assert "publication lock retained" in stderr


def test_public_host_rejects_invalid_target_before_mutation(repo_root, tmp_path):
    bin_dir = _fake_docker_path(tmp_path)
    call_log = tmp_path / "docker.log"
    all_yml = repo_root / "ansible" / "group_vars" / "all.yml"
    before = all_yml.read_bytes()
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "DOCKER_CALL_LOG": str(call_log),
        "FAKE_CERT_OUTPUT": "",
    }

    result = subprocess.run(
        ["bash", str(repo_root / "scripts" / "set-public-host.sh"), "bad/host"],
        cwd=repo_root, env=env, capture_output=True, text=True,
    )

    assert result.returncode != 0
    assert "invalid DNS base domain" in result.stderr
    assert all_yml.read_bytes() == before


def test_public_host_mid_route_failure_restores_every_identity_file(
    repo_root, tmp_path,
):
    """A failed second route cannot leave the first route/global identity split."""
    project = tmp_path / "project"
    for directory in (
        "scripts", "ansible/group_vars", "configs/sites", "proxy/conf.d",
        "proxy/admin.d", "proxy/certs", "monitoring/alerts.d",
        "monitoring/targets.d",
    ):
        (project / directory).mkdir(parents=True, exist_ok=True)
    script = project / "scripts" / "set-public-host.sh"
    script.write_bytes((repo_root / "scripts" / "set-public-host.sh").read_bytes())
    script.chmod(0o755)

    files = {
        "ansible/group_vars/all.yml": (
            'proxy:\n  base_domain: "9.8.7.6.sslip.io"\n'
            '  server_aliases: []\n'
            '  conf_dir: "{{ project_root }}/proxy/conf.d"\n'
            '  tls_fullchain: "/etc/letsencrypt/live/abd/fullchain.pem"\n'
            '  tls_key: "/etc/letsencrypt/live/abd/privkey.pem"\n'
        ),
        ".env": "PROXY_BASE_DOMAIN=9.8.7.6.sslip.io\n",
        "proxy/admin.d/admin.conf": (
            "server_name admin.9.8.7.6.sslip.io;\n"
        ),
        "proxy/certs/wildcard.crt": "old certificate\n",
        "proxy/certs/wildcard.key": "old key\n",
    }
    for site_id in ("site-a", "site-b"):
        files[f"configs/sites/{site_id}.yaml"] = "scraper_version: 1\n"
        files[f"proxy/conf.d/{site_id}.conf"] = (
            f"server_name {site_id}.9.8.7.6.sslip.io;\n"
            f"set $site_name {site_id}.9.8.7.6.sslip.io;\n"
        )
        files[f"monitoring/alerts.d/{site_id}.yml"] = f"old rule {site_id}\n"
        files[f"monitoring/targets.d/{site_id}.yml"] = f"old target {site_id}\n"
    for relative, content in files.items():
        (project / relative).write_text(content, encoding="utf-8")
    originals = {
        relative: (project / relative).read_bytes() for relative in files
    }

    bin_dir = tmp_path / "migration-bin"
    bin_dir.mkdir()
    (bin_dir / "curl").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    (bin_dir / "openssl").write_text(
        "#!/usr/bin/env bash\nprintf '%s\\n' 'DNS:*.9.8.7.6.sslip.io'\n",
        encoding="utf-8",
    )
    (bin_dir / "docker").write_text(
        """#!/usr/bin/env bash
printf '%s\n' "$*" >> "$DOCKER_CALL_LOG"
if [ "$1" = ps ]; then
  printf '%s\n' proxy-nginx
elif [ "$1" = compose ] && [[ "$*" == *" certgen"* ]]; then
  printf '%s\n' 'new certificate' > proxy/certs/wildcard.crt
  printf '%s\n' 'new key' > proxy/certs/wildcard.key
elif [ "$1" = compose ] && [[ "$*" == *"site_id=site-a"* ]]; then
  sed -i 's/9\\.8\\.7\\.6/1.2.3.4/g' proxy/conf.d/site-a.conf
  printf '%s\n' changed > monitoring/alerts.d/site-a.yml
  printf '%s\n' changed > monitoring/targets.d/site-a.yml
  exit 0
elif [ "$1" = compose ] && [[ "$*" == *"site_id=site-b"* ]]; then
  exit 42
fi
exit 0
""",
        encoding="utf-8",
    )
    for command in ("curl", "openssl", "docker"):
        (bin_dir / command).chmod(0o755)

    result = subprocess.run(
        ["bash", str(script), "1.2.3.4"], cwd=project,
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "DOCKER_CALL_LOG": str(tmp_path / "public-host-docker.log"),
        },
        capture_output=True, text=True,
    )

    assert result.returncode != 0
    assert "restoring the previous public identity" in result.stdout
    for relative, original in originals.items():
        assert (project / relative).read_bytes() == original, relative
    docker_calls = (tmp_path / "public-host-docker.log").read_text(encoding="utf-8")
    assert docker_calls.count("--name abd-cert-snapshot-public-host") >= 2
    assert "--name abd-public-host-playbook" in docker_calls
    assert "compose -f docker-compose.app.yml up -d app" not in docker_calls


def test_public_host_does_not_restore_when_certbot_stop_is_unconfirmed(
    repo_root, tmp_path,
):
    project = tmp_path / "unsafe-stop-project"
    for directory in (
        "scripts", "ansible/group_vars", "configs/sites", "proxy/conf.d",
        "proxy/admin.d", "proxy/certs", "monitoring/alerts.d",
        "monitoring/targets.d",
    ):
        (project / directory).mkdir(parents=True, exist_ok=True)
    script = project / "scripts/set-public-host.sh"
    script.write_bytes((repo_root / "scripts/set-public-host.sh").read_bytes())
    script.chmod(0o755)
    (project / "ansible/group_vars/all.yml").write_text(
        'proxy:\n  base_domain: "9.8.7.6.sslip.io"\n'
        '  server_aliases: []\n'
        '  conf_dir: "{{ project_root }}/proxy/conf.d"\n',
        encoding="utf-8",
    )
    (project / ".env").write_text(
        "PROXY_BASE_DOMAIN=9.8.7.6.sslip.io\n", encoding="utf-8"
    )
    (project / "proxy/admin.d/admin.conf").write_text(
        "server_name admin.9.8.7.6.sslip.io;\n", encoding="utf-8"
    )
    (project / "proxy/certs/wildcard.crt").write_text(
        "old certificate\n", encoding="utf-8"
    )
    (project / "proxy/certs/wildcard.key").write_text(
        "old key\n", encoding="utf-8"
    )
    (project / "configs/sites/site-a.yaml").write_text(
        "scraper_version: 1\n", encoding="utf-8"
    )
    (project / "proxy/conf.d/site-a.conf").write_text(
        "server_name site-a.9.8.7.6.sslip.io;\n"
        "set $site_name site-a.9.8.7.6.sslip.io;\n",
        encoding="utf-8",
    )

    bin_dir = tmp_path / "unsafe-stop-bin"
    bin_dir.mkdir()
    (bin_dir / "curl").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    (bin_dir / "openssl").write_text(
        "#!/usr/bin/env bash\nprintf '%s\\n' 'DNS:*.9.8.7.6.sslip.io'\n",
        encoding="utf-8",
    )
    (bin_dir / "docker").write_text(
        r'''#!/usr/bin/env bash
if [ "$1" = ps ]; then
  printf '%s\n' proxy-nginx
elif [ "$1" = compose ] && [[ "$*" == *" certgen"* ]]; then
  printf '%s\n' 'new certificate' > proxy/certs/wildcard.crt
  printf '%s\n' 'new key' > proxy/certs/wildcard.key
elif [ "$1" = compose ] && [[ "$*" == *"ansible-playbook"* ]]; then
  exit 42
elif [ "$1" = rm ] && [[ "$*" == *"abd-certbot-reconcile-public-host"* ]]; then
  exit 55
fi
exit 0
''',
        encoding="utf-8",
    )
    for command in ("curl", "openssl", "docker"):
        (bin_dir / command).chmod(0o755)

    result = subprocess.run(
        ["bash", str(script), "1.2.3.4"], cwd=project,
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
        capture_output=True, text=True,
    )

    assert result.returncode != 0
    assert "could not stop abd-certbot-reconcile-public-host" in result.stdout
    assert "no route, certificate, monitoring, or app state was restored" in result.stdout
    assert 'base_domain: "1.2.3.4.sslip.io"' in (
        project / "ansible/group_vars/all.yml"
    ).read_text(encoding="utf-8")
    assert (project / "configs/.publication.lock").is_dir()
    assert "preserving recovery files" in result.stdout


def _racing_docker_path(tmp_path, *, transient_failures):
    """A fake docker whose curl fails like nginx's reload race, then recovers.

    `nginx -s reload` replaces workers asynchronously. For a short window the
    outgoing worker still accepts a connection and then closes it as it exits;
    over HTTP/2 curl reports that as a framing error (exit 16, http_code 000).
    This stub reproduces exactly that: the first ``transient_failures`` verify
    attempts die at the connection level, and every later one answers normally.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(
        f"""#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$DOCKER_CALL_LOG"
if [ "$1" = ps ]; then
    printf '%s\\n' proxy-nginx
elif [ "$1" = exec ] && [ "$3" = openssl ]; then
    printf '%s\\n' "$FAKE_CERT_OUTPUT"
elif [ "$1" = exec ] && [ "$3" = curl ]; then
    n=$(( $(cat "$CURL_ATTEMPTS" 2>/dev/null || echo 0) + 1 ))
    printf '%s' "$n" > "$CURL_ATTEMPTS"
    if [ "$n" -le {transient_failures} ]; then
        printf '000'; exit 16
    fi
    case "$*" in
        *__abd_health*) printf '204' ;;
        *) printf "${{FAKE_ADMIN_CODE:-303}}" ;;
    esac
elif [ "$1" = exec ]; then
    exit 0
elif [ "$1" = rm ]; then
    printf '%s\\n' 'Error: No such container' >&2
    exit 1
else
    exit 0
fi
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    return bin_dir


def _racing_env(repo_root, tmp_path, bin_dir, **extra):
    names = _published_certificate_names(repo_root)
    return {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "DOCKER_CALL_LOG": str(tmp_path / "docker.log"),
        "CURL_ATTEMPTS": str(tmp_path / "curl.count"),
        # A SAN set that does not match publication forces the script past its
        # no-op fast path into the reload + verification it must survive.
        "FAKE_CERT_OUTPUT": "X509v3 Subject Alternative Name:\n    "
        + ", ".join(f"DNS:{name}" for name in names[:1]),
        "ABD_PUBLICATION_LOCK_HELD": "1",
        **extra,
    }


def test_letsencrypt_verification_survives_the_nginx_reload_race(
    repo_root, tmp_path,
):
    """A connection-level failure right after reload must not condemn the cert.

    This is the real regression: verification runs immediately after
    `nginx -s reload`, so the first hostname absorbed the worker-replacement
    race and failed a certificate that was fine. It only ever bit a *changed*
    hostname inventory — an unchanged one takes the no-op fast path and never
    reaches here — i.e. exactly the deploy-a-new-site workflow.
    """
    bin_dir = _racing_docker_path(tmp_path, transient_failures=2)
    result = subprocess.run(
        ["bash", str(repo_root / "scripts" / "setup-letsencrypt.sh")],
        cwd=repo_root, env=_racing_env(repo_root, tmp_path, bin_dir),
        capture_output=True, text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "failed trusted-TLS verification" not in result.stdout + result.stderr
    for name in _published_certificate_names(repo_root):
        assert f"OK  https://{name}" in result.stdout


def test_letsencrypt_verification_still_fails_a_real_bad_answer(
    repo_root, tmp_path,
):
    """The retry must not paper over a genuine verification failure.

    An HTTP answer is a definitive verdict: retrying it would let a real
    misconfiguration publish a hostname the certificate does not serve.
    """
    bin_dir = _racing_docker_path(tmp_path, transient_failures=0)
    wrong_status = subprocess.run(
        ["bash", str(repo_root / "scripts" / "setup-letsencrypt.sh")],
        cwd=repo_root,
        env=_racing_env(repo_root, tmp_path, bin_dir, FAKE_ADMIN_CODE="502"),
        capture_output=True, text=True,
    )
    assert wrong_status.returncode != 0
    assert "expected 303, got 502" in wrong_status.stdout
    assert "failed trusted-TLS verification" in wrong_status.stderr

    # A hostname that never answers at all is still a failure after the retries.
    dead_root = tmp_path / "dead"
    dead_root.mkdir()
    dead = _racing_docker_path(dead_root, transient_failures=999)
    never_answers = subprocess.run(
        ["bash", str(repo_root / "scripts" / "setup-letsencrypt.sh")],
        cwd=repo_root,
        env=_racing_env(repo_root, tmp_path, dead,
                        CURL_ATTEMPTS=str(dead_root / "curl.count")),
        capture_output=True, text=True,
    )
    assert never_answers.returncode != 0
    assert "TLS validation or connection failed" in never_answers.stdout
