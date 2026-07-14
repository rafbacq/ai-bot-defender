"""Fixtures for the live application test suite.

Every fixture that needs a piece of the running stack (the proxy + logdb, a
deployed honeypot site, or the web app) probes for it and **skips cleanly** when
it is absent — so the suite never crashes the app and never errors on a partial
stack; it just reports those tests as skipped with a clear reason.

Connection points are env-overridable:
  PROXY_HTTP     reverse-proxy entry point      (default http://localhost)
  APP_BASE_URL   the FastAPI web app            (default http://localhost:8000)
  BOT_DEFENDER_APP_BOTS   simulated traffic size (default 40; set by --bots)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
os.environ.setdefault("PROJECT_ROOT", str(REPO_ROOT))

PROXY_HTTP = os.environ.get("PROXY_HTTP", "http://localhost").rstrip("/")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8000").rstrip("/")
PROXY_COMPOSE = REPO_ROOT / "docker-compose.proxy.yml"


# --- Low-level psql-over-docker helper (mirrors the app's own services) -----
def docker_psql_json(compose_file, service, user, db, sql, timeout=30):
    """Run a JSON-returning query via ``docker compose exec`` -> (data, error)."""
    cmd = ["docker", "compose", "-f", str(compose_file), "exec", "-T", service,
           "psql", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1",
           "-U", user, "-d", db, "-c", sql]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return None, "docker CLI not available"
    except subprocess.TimeoutExpired:
        return None, "query timed out"
    if result.returncode != 0:
        return None, (result.stderr or result.stdout).strip()
    out = result.stdout.strip()
    if not out:
        return None, "empty result"
    try:
        return json.loads(out), None
    except json.JSONDecodeError:
        return None, "invalid JSON"


def logdb_json(sql, timeout=30):
    return docker_psql_json(PROXY_COMPOSE, "logdb", "logger", "site_logs", sql, timeout)


def _scalar(data):
    return (data or {}).get("n")


def poll(fn, want, *, timeout=15.0, interval=0.7):
    """Re-evaluate ``fn()`` until it returns >= ``want`` or the timeout elapses.

    Central logging (the nginx mirror -> collector) and the fp beacon are
    fire-and-forget/async, so a write can lag the HTTP response by a moment.
    """
    deadline = time.time() + timeout
    last = 0
    while time.time() < deadline:
        last = fn() or 0
        if last >= want:
            return last
        time.sleep(interval)
    return last


# --- Stack-availability fixtures -------------------------------------------
class Proxy:
    """Handle for querying the central logdb (the proxy's request log store)."""

    def query(self, sql, timeout=30):
        data, err = logdb_json(sql, timeout)
        if err:
            raise RuntimeError(f"logdb query failed: {err}")
        return data

    def count(self, table, where="TRUE"):
        data, err = logdb_json(f"SELECT json_build_object('n', COUNT(*)) FROM {table} WHERE {where};")
        return _scalar(data) if not err else None


@pytest.fixture(scope="session")
def project_root():
    return REPO_ROOT


@pytest.fixture(scope="session")
def proxy():
    data, err = logdb_json("SELECT json_build_object('n', COUNT(*)) FROM all_visits;")
    if err:
        pytest.skip(f"reverse-proxy logdb not reachable ({err}); start it with `make proxy`")
    return Proxy()


def _reachable_site():
    """Pick the first deployed honeypot site that renders through the proxy."""
    import requests
    from app.services import sites as sites_svc

    for site in sites_svc.list_sites():
        if not site.get("deployed"):
            continue
        host = site["local_hostname"]
        try:
            resp = requests.get(PROXY_HTTP + "/", headers={"Host": host, "User-Agent": "AIBDLive-probe"},
                                timeout=10)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and "{{ var" not in resp.text:
            return site
    return None


@pytest.fixture(scope="session")
def site(proxy):
    found = _reachable_site()
    if not found:
        pytest.skip("no deployed honeypot site is reachable through the proxy; "
                    "deploy one with `make playbook site_id=site-001`")
    return found


class SiteDB:
    """Query one deployed site's own database (new_visits / new_agents_vars)."""

    def __init__(self, site):
        self.compose = REPO_ROOT / "website" / "sites" / site["site_id"] / "docker-compose.yml"
        self.user = site["database"]["user"]
        self.db = site["db_name"]

    def query(self, sql, timeout=30):
        data, err = docker_psql_json(self.compose, "db", self.user, self.db, sql, timeout)
        if err:
            raise RuntimeError(f"site db query failed: {err}")
        return data

    def count(self, table, where="TRUE"):
        data, err = docker_psql_json(self.compose, "db", self.user, self.db,
                                     f"SELECT json_build_object('n', COUNT(*)) FROM {table} WHERE {where};")
        return _scalar(data) if not err else None


@pytest.fixture(scope="session")
def site_db(site):
    return SiteDB(site)


@pytest.fixture(scope="session")
def app_url():
    import requests
    try:
        resp = requests.get(APP_BASE_URL + "/login", timeout=10)
    except requests.RequestException as exc:
        pytest.skip(f"web app not reachable at {APP_BASE_URL} ({exc}); start it with `make app`")
    if resp.status_code != 200 or "log in" not in resp.text.lower():
        pytest.skip(
            f"account-enabled web app is not ready at {APP_BASE_URL} "
            f"(HTTP {resp.status_code}); rebuild/restart it with `make app`"
        )
    return APP_BASE_URL


@pytest.fixture(scope="session")
def app_session(app_url, request):
    """Authenticated requests session backed by a disposable local account.

    The live suite inserts an approval directly into the same bind-mounted auth
    DB, creates one uniquely named account through the real auth service, logs in
    over HTTP, and deletes both rows at teardown. No SMTP message is sent and no
    real user record is touched.
    """
    import requests
    from app.services import auth_service

    suffix = uuid.uuid4().hex[:12]
    username = f"aibdtest_{suffix}"
    email = f"aibdtest-{suffix}@example.edu"
    password = f"AIBD live test {suffix}"
    institution = "Duke University"
    session = requests.Session()

    def cleanup():
        session.close()
        conn = auth_service._get_conn()
        try:
            conn.execute("DELETE FROM users WHERE email = ?", (email,))
            conn.execute("DELETE FROM approved_emails WHERE email = ?", (email,))
            conn.commit()
        finally:
            conn.close()

    request.addfinalizer(cleanup)

    conn = auth_service._get_conn()
    try:
        conn.execute(
            "INSERT INTO approved_emails (email, institution, approved_at, used) "
            "VALUES (?, ?, ?, 0)",
            (email, institution, time.time()),
        )
        conn.commit()
    finally:
        conn.close()
    auth_service._reset_rate_limits()
    auth_service.create_account(username, email, password, institution, "live-test")

    response = session.post(
        app_url + "/login",
        data={"username": username, "password": password, "next": "/"},
        allow_redirects=False,
        timeout=15,
    )
    if response.status_code != 303:
        pytest.fail(
            "could not authenticate the disposable live-test account "
            f"(POST /login -> {response.status_code}); ensure the app and test "
            "process use the same USERS_DB"
        )

    yield session


# --- The shared simulated traffic (flooded once per session) ---------------
@pytest.fixture(scope="session")
def simulated_traffic(site):
    """Flood the live honeypot with a diverse, tagged bot fleet exactly once, then
    wait until the central log has caught up. Shared across the traffic-dependent
    tests so we only generate one controlled burst."""
    from . import simulate

    bots = int(os.environ.get("BOT_DEFENDER_APP_BOTS", "40"))
    tag = simulate.make_tag()
    summary = simulate.flood(PROXY_HTTP, site["local_hostname"], tag, bots=max(1, bots))

    # Wait for the async mirror to land our page views in all_visits.
    where = f"user_agent LIKE '%{tag}%'"
    landed = poll(lambda: Proxy().count("all_visits", where) or 0,
                  want=summary["page_views"], timeout=20)
    summary["all_visits_landed"] = landed
    return summary
