"""Load ground-truth canary rows for matching.

Two sources are supported:

- A CSV file (the bundled ``jeniffer.csv`` / ``21.csv`` samples, or any export
  with ``var1``..``var10`` columns).
- A live per-site honeypot database: the ``new_agents_vars`` table. Two access
  backends, selected by whether ``SITEDB_HOST`` is set (mirroring
  ``app/services/logdb.py`` and ``crawler_graph.ingest.db``, so every DB seam in
  the repo reads the same kind of env contract):

    * **``SITEDB_HOST`` set** — the AWS deployment (the RDS endpoint hosting
      every ``scraper{N}-db``) or any directly reachable Postgres: a psycopg2
      connection. ``db_name``/``db_user`` stay per-call (each site keeps its own
      database); the password comes from ``SITEDB_PASS`` because the docker path
      never needed one (``psql`` inside the container is trusted).
    * **``SITEDB_HOST`` unset** — the local default: shell ``docker compose
      exec`` against the site stack's ``db`` container, exactly as before.

Each row is a dict containing at least ``user_agent`` and ``var1``..``var10``.
``site_psql_json`` is the shared runner (also used by ``querying.provenance``
for its ``new_visits`` crawl-time queries).
"""

import csv
import json
import os
import subprocess
from pathlib import Path


class GroundTruthError(RuntimeError):
    """Raised when ground-truth rows cannot be loaded."""


# --- per-site DB access config (env, mirroring the LOGDB_* family) ----------
SITEDB_HOST = os.environ.get("SITEDB_HOST")  # unset/empty -> docker-exec path
SITEDB_PORT = int(os.environ.get("SITEDB_PORT", "5432"))
SITEDB_USER = os.environ.get("SITEDB_USER")  # optional override of the per-call db_user
SITEDB_PASS = os.environ.get("SITEDB_PASS", "password")


def load_csv_rows(csv_path):
    """Load all rows from a ground-truth CSV into a list of dicts."""
    path = Path(csv_path)
    if not path.exists():
        raise GroundTruthError(f"Ground-truth CSV not found: {path}")
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _site_direct_json(db_name, db_user, sql):
    """Direct psycopg2 query against ``SITEDB_HOST`` (the AWS/RDS path)."""
    try:
        import psycopg2
    except ModuleNotFoundError as exc:
        raise GroundTruthError("psycopg2 is not installed for the direct DB path.") from exc
    try:
        conn = psycopg2.connect(
            host=SITEDB_HOST, port=SITEDB_PORT, user=SITEDB_USER or db_user,
            password=SITEDB_PASS, dbname=db_name,
            connect_timeout=10, options="-c statement_timeout=30000",
        )
    except psycopg2.OperationalError as exc:
        raise GroundTruthError(
            f"Could not reach the site database at {SITEDB_HOST}:{SITEDB_PORT}: "
            f"{str(exc).strip()}"
        ) from exc
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(sql)
            row = cur.fetchone()
    except psycopg2.Error as exc:
        # Keep the raw detail (e.g. 'relation "new_agents_vars" does not exist')
        # so callers can rewrite the well-known cases into friendly guidance.
        raise GroundTruthError(str(exc).strip() or "The site database query failed.") from exc
    finally:
        conn.close()
    value = row[0] if row else None
    if value is None:
        return []
    return value if isinstance(value, (dict, list)) else json.loads(value)


def _site_docker_json(project_root, site_id, db_name, db_user, sql, timeout):
    """Shell ``docker compose exec`` into the site stack's db container (local path)."""
    compose_file = Path(project_root) / "website" / "sites" / site_id / "docker-compose.yml"
    if not compose_file.exists():
        raise GroundTruthError(
            f"Site '{site_id}' is not deployed (no {compose_file})."
        )
    command = [
        "docker", "compose", "-f", str(compose_file), "exec", "-T", "db",
        "psql", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1",
        "-U", db_user, "-d", db_name, "-c", sql,
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise GroundTruthError("Docker CLI is not available.") from exc
    except subprocess.TimeoutExpired as exc:
        raise GroundTruthError("The site database query timed out.") from exc
    if result.returncode != 0:
        raise GroundTruthError(
            (result.stderr or result.stdout).strip() or "The site database query failed."
        )
    output = result.stdout.strip()
    try:
        return json.loads(output) if output else []
    except json.JSONDecodeError as exc:
        raise GroundTruthError("The site database returned an invalid response.") from exc


def site_psql_json(project_root, site_id, db_name, db_user, sql, timeout=20):
    """Run one JSON-returning query against a site's database (shared runner).

    Uses the direct psycopg2 connection when ``SITEDB_HOST`` is set (AWS/RDS),
    else ``docker compose exec`` into the deployed site's db container.
    """
    if SITEDB_HOST:
        return _site_direct_json(db_name, db_user, sql)
    return _site_docker_json(project_root, site_id, db_name, db_user, sql, timeout)


def load_site_rows(project_root, site_id, db_name, db_user):
    """Read ``new_agents_vars`` from a deployed site's database.

    Returns a list of row dicts (user_agent + var1..var10 + a couple of fields).
    Raises ``GroundTruthError`` if the database (docker or direct) is unavailable.
    """
    var_cols = ", ".join(f"var{i}" for i in range(1, 11))
    sql = (
        "SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM ("
        f"SELECT user_agent, browser_family, view_count, asn, {var_cols} "
        "FROM new_agents_vars ORDER BY id) t;"
    )
    try:
        return site_psql_json(project_root, site_id, db_name, db_user, sql)
    except GroundTruthError as exc:
        if 'relation "new_agents_vars" does not exist' in str(exc):
            raise GroundTruthError(
                f"Site '{site_id}' has no canary rows yet — visit it first."
            ) from exc
        raise


def pick_leak_candidates(rows, prefer_user_agent=None):
    """Return one row's var1..var10 values (for the mock 'scraper-sim' to leak).

    Prefers a row whose user_agent matches ``prefer_user_agent`` (e.g. our own
    probe's UA, so the demo leak matches a real stored canary set), else the
    first row.
    """
    if not rows:
        return []
    chosen = None
    if prefer_user_agent:
        for row in rows:
            if (row.get("user_agent") or "") == prefer_user_agent:
                chosen = row
                break
    chosen = chosen or rows[0]
    values = []
    for i in range(1, 11):
        value = chosen.get(f"var{i}")
        if value and str(value).strip().lower() != "null":
            values.append(str(value))
    return values
