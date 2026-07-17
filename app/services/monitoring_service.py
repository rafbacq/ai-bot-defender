"""Read-only health, metric, and alert views over the monitoring stack.

The admin page polls :func:`overview` client-side so a slow or stopped
Prometheus instance can never delay the page's initial render. Every outbound
request has a short, explicit timeout; public functions degrade to a stable,
JSON-safe shape and never raise into the FastAPI route.
"""

from __future__ import annotations

import json
import math
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode

import httpx

from .. import config
from . import logdb, sites


_TIMEOUT = httpx.Timeout(2.5, connect=1.0)
# Only for the access-log aggregate: unlike every other read here, its cost
# scales with retained log volume rather than being a constant-time lookup.
_LOKI_AGGREGATE_TIMEOUT = httpx.Timeout(15.0, connect=1.0)
_CACHE_TTL = 8.0
_CACHE = {"at": 0.0, "data": None}
_SPARK_MINUTES = 30
_SPARK_STEP = 60
_STALE_AFTER_S = 90

# These match the provisioned Grafana overview dashboard. Each expression
# aggregates to one instant-vector sample, which keeps parsing deterministic
# even when the host has many CPUs, disks, or containers.
_KPI_QUERIES = {
    "host_cpu_percent": (
        '100 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100'
    ),
    "host_memory_percent": (
        "(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100"
    ),
    "root_disk_percent": (
        '(1 - node_filesystem_avail_bytes{mountpoint="/",fstype!="tmpfs"} '
        '/ node_filesystem_size_bytes{mountpoint="/",fstype!="tmpfs"}) * 100'
    ),
    "running_containers": 'count(container_last_seen{name!=""})',
}

_CONTAINER_QUERIES = {
    "cpu_percent": (
        'sum by (name) '
        '(rate(container_cpu_usage_seconds_total{name!=""}[2m])) * 100'
    ),
    "memory_bytes": (
        'sum by (name) (container_memory_working_set_bytes{name!=""})'
    ),
    "last_seen": 'max by (name) (container_last_seen{name!=""})',
}

_PROBE_QUERIES = {
    "success": 'probe_success{job="public-sites"}',
    "http_status": 'probe_http_status_code{job="public-sites"}',
    "cert_expiry": (
        'probe_ssl_earliest_cert_expiry{job="public-sites",probe_scheme="https"}'
    ),
}

# Capture integrity: is the honeypot actually recording the research data it
# exists to record? Container liveness cannot answer that. The visit collector
# is fire-and-forget on purpose — it swallows database errors so a logging fault
# can never stall a real response — which means a *silent* capture failure is
# exactly the shape this system's worst outage takes: every container green, and
# nothing landing in all_visits.
#
# Two sources, each for what only it knows:
#   * The **central log** answers "what do we have" — corpus size, growth, when
#     traffic last arrived. The collector's own `..._rows_inserted_total` cannot:
#     it is process-local and resets on every collector restart, so it read 37
#     while all_visits actually held 3,043 rows. Never present it as the corpus.
#   * The **collector counters** answer "what are we missing". The database
#     cannot: a dropped visit leaves no trace in it. That is the entire point.
_CAPTURE_QUERIES = {
    "visits_lost": 'sum(abd_collector_mirror_insert_errors_total{job="visit-collector"})',
    "status_missed": 'sum(abd_collector_status_records_missed_total{job="visit-collector"})',
    "status_pending": 'sum(abd_collector_status_pending{job="visit-collector"})',
    "sync_errors": 'sum(abd_collector_status_sync_errors_total{job="visit-collector"})',
    "sync_healthy": 'min(abd_collector_status_sync_healthy{job="visit-collector"})',
    "sync_thread_up": 'min(abd_collector_status_sync_thread_up{job="visit-collector"})',
    "access_log_present": 'min(abd_collector_access_log_present{job="visit-collector"})',
    "sync_last_success": (
        'max(abd_collector_status_sync_last_success_unixtime_seconds'
        '{job="visit-collector"})'
    ),
    # The totals above are cumulative counters, so they answer "has anything ever
    # been lost", not "is anything being lost". Driving the verdict from them
    # would leave the badge red forever after one transient blip — the alarm
    # fatigue that teaches operators to ignore a dashboard. These windowed reads
    # answer "right now", and deliberately mirror the CollectorMirrorInsertFailures
    # and CollectorStatusCorrelationMisses alert rules so the page and the pager
    # can never disagree about whether capture is currently broken.
    "recent_visits_lost": (
        'increase(abd_collector_mirror_insert_errors_total'
        '{job="visit-collector"}[10m])'
    ),
    "recent_status_missed": (
        'increase(abd_collector_status_records_missed_total'
        '{job="visit-collector"}[10m])'
    ),
}

# The corpus read. Deliberately three cheap aggregates and an hourly histogram
# over one day — not a row scan — so this stays a monitoring query even as the
# log grows. The histogram is what makes "last 24 hours" informative: this
# traffic is ~89% idle minutes punctuated by bursts of hundreds, so the shape
# says far more than any single instantaneous rate could.
_CAPTURE_CORPUS_SQL = """
SELECT json_build_object(
    'total',    (SELECT COUNT(*) FROM all_visits),
    'last_24h', (SELECT COUNT(*) FROM all_visits
                 WHERE ts >= NOW() - INTERVAL '24 hours'),
    'newest',   (SELECT EXTRACT(EPOCH FROM MAX(ts)) FROM all_visits),
    'hourly',   (SELECT json_agg(json_build_array(h, n) ORDER BY h)
                 FROM (SELECT EXTRACT(EPOCH FROM date_trunc('hour', ts)) AS h,
                              COUNT(*) AS n
                       FROM all_visits
                       WHERE ts >= NOW() - INTERVAL '24 hours'
                       GROUP BY 1) buckets)
);
"""

# The sync poll runs continuously; this bound matches the CollectorStatusSyncStalled
# alert's intent — a sync that has not succeeded for minutes is not merely slow.
_SYNC_STALE_AFTER_S = 300

# nginx writes one access log per audience, and the filename is the only thing
# separating them. The admin console is excluded from every research-traffic
# reading: it is this dashboard's own request stream, so counting it made a
# traffic reading observe itself — polling from open admin tabs was 35% of the
# old "Honeypot requests" number, and every extra tab inflated it further.
# Scanner noise (unmatched.access.log) is deliberately kept: unattributed
# scanning is research data, not exhaust.
_ADMIN_ACCESS_LOG = "/var/log/nginx-proxy/admin.access.log"
_RESEARCH_LOG_STREAM = (
    f'{{job="nginx_access", filename!="{_ADMIN_ACCESS_LOG}"}}'
)

# What Loki is actually *for* on this page. nginx has no metrics exporter, so its
# access log is the only record of what real visitors were served — Prometheus
# scrapes the host, containers, and a synthetic blackbox probe of /__abd_health,
# none of which sees a crawler's actual response. And `all_visits` cannot answer
# it either: unmatched traffic is never mirrored there by design.
#
# This is an aggregate, deliberately not a row list. Reprinting request rows here
# only duplicated Crawler Analytics, which already renders them with fingerprints,
# verdicts, filters, and export. `sum by (site, status)` collapses the log into
# the one thing nothing else knows: what every host actually returned.
_RESPONSE_MIX_HOURS = 24
_RESPONSE_MIX_QUERY = (
    f"sum by (site, status) "
    f'(count_over_time({_RESEARCH_LOG_STREAM} | json | __error__="" '
    f"[{_RESPONSE_MIX_HOURS}h]))"
)
# Loki refuses a query that would build >500 series. Aggregating by (site,status)
# keeps this at ~50 even under sustained Host-header scanning; an unwrapped
# per-request read (e.g. request_time quantiles) blows the limit outright, which
# is one reason latency is not offered here — the other being that these pages
# serve in under a millisecond, so latency carries no signal.
_RESPONSE_MIX_MAX_HOSTS = 12

_STAGES = (
    ("edge", "Edge"),
    ("capture", "Capture"),
    ("storage", "Storage"),
    ("sites", "Sites"),
    ("app", "App"),
    ("monitoring", "Monitoring"),
)

# One-shot and housekeeping containers (certgen, logrotate, certbot-renew,
# trainer) are deliberately absent: none belongs to the live request pipeline.
_EXPECTED_INFRA = (
    ("proxy-nginx", "edge", "Reverse proxy"),
    ("proxy-collector-1", "capture", "Visit collector"),
    ("proxy-fp-collector", "capture", "Fingerprint collector"),
    ("proxy-tls-capture", "capture", "TLS capture"),
    ("proxy-tls-shipper", "capture", "TLS shipper"),
    ("proxy-logdb-1", "storage", "Central log database"),
    ("ai-bot-defender-app", "app", "Admin application"),
    ("mon-prometheus", "monitoring", "Prometheus"),
    ("mon-blackbox", "monitoring", "Endpoint/TLS prober"),
    ("mon-alertmanager", "monitoring", "Alert manager"),
    ("mon-node-exporter", "monitoring", "Host exporter"),
    ("mon-cadvisor", "monitoring", "Container exporter"),
    ("mon-loki", "monitoring", "Loki"),
    ("mon-promtail", "monitoring", "Log shipper"),
    ("mon-grafana", "monitoring", "Grafana"),
)


def _get_json(url: str, *, timeout=None):
    """GET one monitoring endpoint and return its decoded response.

    Service health endpoints intentionally return plain text, while the data
    APIs return JSON. Every outbound call goes through this one seam: it keeps
    network behavior trivial to monkeypatch in the offline suite, and there is
    exactly one place that decides headers and timeouts.
    """
    response = httpx.get(
        url,
        timeout=timeout or _TIMEOUT,
        headers={"Accept": "application/json, text/plain;q=0.9"},
    )
    response.raise_for_status()
    try:
        return response.json()
    except ValueError:
        return response.text.strip()


def _url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def _probe(name: str) -> tuple[str, bool]:
    endpoints = {
        "grafana": _url(config.GRAFANA_URL, "api/health"),
        "prometheus": _url(config.PROMETHEUS_URL, "-/healthy"),
        "loki": _url(config.LOKI_URL, "ready"),
        "alertmanager": _url(config.ALERTMANAGER_URL, "-/healthy"),
        "blackbox": _url(config.BLACKBOX_URL, "-/healthy"),
    }
    try:
        payload = _get_json(endpoints[name])
        if name == "grafana":
            return name, bool(
                isinstance(payload, dict) and payload.get("database") == "ok"
            )
        # Text health probes only reach this line after a successful 2xx.
        return name, payload is not None
    except Exception:
        return name, False


def stack_health() -> dict[str, bool]:
    """Return one boolean per service, bounded by one probe timeout overall."""
    health = {
        "grafana": False,
        "prometheus": False,
        "loki": False,
        "alertmanager": False,
        "blackbox": False,
    }
    try:
        with ThreadPoolExecutor(max_workers=len(health)) as pool:
            futures = [pool.submit(_probe, name) for name in health]
            for future in as_completed(futures):
                name, ok = future.result()
                health[name] = bool(ok)
    except Exception:
        # Executor/setup failures are unusual, but this route must still return
        # the same offline shape rather than a 500.
        pass
    return health


def _prometheus_query(expression: str):
    query = urlencode({"query": expression})
    return _get_json(_url(config.PROMETHEUS_URL, f"api/v1/query?{query}"))


def _prometheus_query_range(
    expression: str,
    *,
    minutes: int = _SPARK_MINUTES,
    step: int = _SPARK_STEP,
):
    end = time.time()
    query = urlencode({
        "query": expression,
        "start": end - (minutes * 60),
        "end": end,
        "step": step,
    })
    return _get_json(
        _url(config.PROMETHEUS_URL, f"api/v1/query_range?{query}")
    )


def _loki_query(expression: str):
    query = urlencode({"query": expression})
    return _get_json(_url(config.LOKI_URL, f"loki/api/v1/query?{query}"))


def _loki_metric_query(expression: str):
    """Run a LogQL *metric* query, which answers in Prometheus' vector shape.

    Aggregating a day of access log is measured at ~0.05-0.12s here, so it needs
    no special handling — but it is the one read whose cost grows with retained
    log volume rather than staying constant, hence the larger ceiling. It sits
    behind the page cache and is only ever reached from the background fan-out,
    so a slow answer delays nothing a user is waiting on.
    """
    query = urlencode({"query": expression, "time": time.time()})
    return _get_json(
        _url(config.LOKI_URL, f"loki/api/v1/query?{query}"),
        timeout=_LOKI_AGGREGATE_TIMEOUT,
    )


def _loki_query_range(
    expression: str,
    *,
    minutes: int = _SPARK_MINUTES,
    step: int = _SPARK_STEP,
    limit: int | None = None,
):
    end = time.time()
    params = {
        "query": expression,
        "start": end - (minutes * 60),
        "end": end,
        "step": step,
    }
    # Log (as opposed to metric) queries are bounded by `limit`, which Loki
    # otherwise defaults to 100 — transferring far more lines than a panel
    # renders. `direction=backward` is Loki's default and is what makes the
    # bounded set the *newest* lines rather than an arbitrary hundred.
    if limit is not None:
        params["limit"] = limit
        params["direction"] = "backward"
    return _get_json(
        _url(config.LOKI_URL, f"loki/api/v1/query_range?{urlencode(params)}")
    )


def _sample_value(payload) -> float | None:
    """Extract one finite scalar from a Prometheus instant-vector response."""
    try:
        if payload.get("status") != "success":
            return None
        result = payload["data"]["result"]
        if not isinstance(result, list) or not result:
            return None
        value = float(result[0]["value"][1])
        return value if math.isfinite(value) else None
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return None


def _matrix_points(payload) -> list[list[float]]:
    """Extract finite ``[timestamp, value]`` pairs from the first series."""
    try:
        if payload.get("status") != "success":
            return []
        result = payload["data"]["result"]
        if not isinstance(result, list) or not result:
            return []
        values = result[0]["values"]
        if not isinstance(values, list):
            return []
    except (AttributeError, IndexError, KeyError, TypeError):
        return []

    points = []
    for sample in values:
        try:
            timestamp = float(sample[0])
            value = float(sample[1])
        except (IndexError, TypeError, ValueError):
            continue
        if math.isfinite(timestamp) and math.isfinite(value):
            points.append([round(timestamp, 2), round(value, 2)])
    return points


def _vector_by_name(payload) -> dict[str, float]:
    """Normalize a Prometheus vector grouped by its cAdvisor ``name`` label."""
    try:
        if payload.get("status") != "success":
            return {}
        result = payload["data"]["result"]
        if not isinstance(result, list):
            return {}
    except (AttributeError, KeyError, TypeError):
        return {}

    values = {}
    for sample in result:
        try:
            name = sample["metric"]["name"]
            value = float(sample["value"][1])
        except (IndexError, KeyError, TypeError, ValueError):
            continue
        if isinstance(name, str) and name and math.isfinite(value):
            values[name] = value
    return values


def _labeled_vector(payload) -> list[tuple[dict[str, str], float]]:
    """Return finite Prometheus vector samples with normalized string labels."""
    try:
        if payload.get("status") != "success":
            return []
        result = payload["data"]["result"]
        if not isinstance(result, list):
            return []
    except (AttributeError, KeyError, TypeError):
        return []

    samples = []
    for sample in result:
        try:
            labels = _clean_mapping(sample["metric"])
            value = float(sample["value"][1])
        except (IndexError, KeyError, TypeError, ValueError):
            continue
        if labels and math.isfinite(value):
            samples.append((labels, value))
    return samples


def kpis() -> dict[str, float | int | None]:
    """Return host/container KPI values; an unavailable sample stays ``None``."""
    values: dict[str, float | int | None] = {
        name: None for name in _KPI_QUERIES
    }
    try:
        with ThreadPoolExecutor(max_workers=len(_KPI_QUERIES)) as pool:
            futures = {
                pool.submit(_prometheus_query, expression): name
                for name, expression in _KPI_QUERIES.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    value = _sample_value(future.result())
                except Exception:
                    value = None
                if name == "running_containers" and value is not None:
                    values[name] = int(value)
                else:
                    values[name] = value
    except Exception:
        pass
    return values


def _expected_containers() -> list[tuple[str, str, str]]:
    """Return infrastructure plus every routed site's expected containers.

    A stopped site must remain visible as down, so runtime liveness is not an
    inventory predicate. ``deployed`` is retained only as a compatibility
    fallback for callers that predate the explicit routed-state field.
    """
    try:
        expected = list(_EXPECTED_INFRA)
        for site in sites.list_sites():
            routed = site.get("routed")
            if not (site.get("deployed", False) if routed is None else routed):
                continue
            site_id = str(site["site_id"])
            expected.append((f"{site_id}-web-1", "sites", f"{site_id} web"))
            if "host" not in site["database"]:
                expected.append((f"{site_id}-db-1", "sites", f"{site_id} db"))
        return expected
    except Exception:
        # Site configuration is machine-local and may be mid-write. Core
        # monitoring remains useful even if that inventory cannot be read.
        return list(_EXPECTED_INFRA)


def containers() -> list[dict]:
    """Return status and current resource usage for expected containers."""
    vectors = {name: {} for name in _CONTAINER_QUERIES}
    try:
        with ThreadPoolExecutor(max_workers=len(_CONTAINER_QUERIES)) as pool:
            futures = {
                pool.submit(_prometheus_query, expression): name
                for name, expression in _CONTAINER_QUERIES.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    vectors[name] = _vector_by_name(future.result())
                except Exception:
                    vectors[name] = {}
    except Exception:
        pass

    now = time.time()
    rows = []
    for name, stage, label in _expected_containers():
        last_seen = vectors["last_seen"].get(name)
        if last_seen is None:
            status = "down"
            age = None
        else:
            age = round(max(0.0, now - last_seen), 1)
            status = "stale" if age > _STALE_AFTER_S else "up"
        rows.append({
            "name": name,
            "stage": stage,
            "label": label,
            "status": status,
            "cpu_percent": vectors["cpu_percent"].get(name),
            "memory_bytes": vectors["memory_bytes"].get(name),
            "last_seen_age_s": age,
        })
    return rows


def _expected_probe_inventory() -> list[dict[str, str]]:
    """Return the HTTP/HTTPS series every currently routed site must expose."""
    try:
        expected = []
        for site in sites.list_sites():
            routed = site.get("routed")
            if not (site.get("deployed", False) if routed is None else routed):
                continue
            site_id = str(site.get("site_id") or "")
            hostname = str(
                site.get("published_hostname") or site.get("hostname") or ""
            )
            if not site_id or not hostname:
                continue
            for scheme in ("http", "https"):
                expected.append({
                    "site": site_id,
                    "scheme": scheme,
                    "target": f"{scheme}://{hostname}/",
                    "hostname": hostname,
                })
        return expected
    except Exception:
        return []


def endpoint_probes() -> list[dict]:
    """Return observed probes plus explicit rows for missing expected series."""
    vectors: dict[str, list[tuple[dict[str, str], float]]] = {
        name: [] for name in _PROBE_QUERIES
    }
    try:
        with ThreadPoolExecutor(max_workers=len(_PROBE_QUERIES)) as pool:
            futures = {
                pool.submit(_prometheus_query, expression): name
                for name, expression in _PROBE_QUERIES.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    vectors[name] = _labeled_vector(future.result())
                except Exception:
                    vectors[name] = []
    except Exception:
        return []

    def key(labels: dict[str, str]) -> tuple[str, str, str]:
        return (
            labels.get("site", ""),
            labels.get("probe_scheme", ""),
            labels.get("instance", ""),
        )

    status_by_key = {
        key(labels): value for labels, value in vectors["http_status"]
    }
    expiry_by_key = {
        key(labels): value for labels, value in vectors["cert_expiry"]
    }
    now = time.time()
    rows = []
    for labels, success in vectors["success"]:
        sample_key = key(labels)
        expiry = expiry_by_key.get(sample_key)
        rows.append({
            "site": labels.get("site", "Unknown site"),
            "scheme": labels.get("probe_scheme", "unknown"),
            "target": labels.get("instance", ""),
            "hostname": labels.get("hostname", ""),
            "status": "up" if success == 1 else "down",
            "http_status": (
                int(status_by_key[sample_key])
                if sample_key in status_by_key else None
            ),
            "cert_expires_at": round(expiry, 3) if expiry is not None else None,
            "cert_days_remaining": (
                round((expiry - now) / 86400, 1)
                if expiry is not None else None
            ),
        })

    observed = {
        (row["site"], row["scheme"], row["target"])
        for row in rows
    }
    for expected in _expected_probe_inventory():
        expected_key = (
            expected["site"], expected["scheme"], expected["target"]
        )
        if expected_key in observed:
            continue
        rows.append({
            **expected,
            "status": "missing",
            "http_status": None,
            "cert_expires_at": None,
            "cert_days_remaining": None,
        })
    rows.sort(key=lambda row: (row["site"], row["scheme"], row["target"]))
    return rows


def capture_corpus() -> dict:
    """Return what the central log actually holds, or nulls if it cannot be read.

    This is the honest answer to "how much research data do we have", which the
    collector's counters cannot give — they only count what *this* collector
    process has inserted since it started.
    """
    empty = {"total": None, "last_24h": None, "newest": None, "hourly": []}
    try:
        data = logdb.run_psql_json(_CAPTURE_CORPUS_SQL, timeout=8)
    except Exception:
        # The log being unreadable is reported by the tiles as unknown, never as
        # zero: "no data" and "we cannot see the data" are different facts.
        return empty
    if not isinstance(data, dict):
        return empty

    def whole(key):
        try:
            return int(data[key])
        except (KeyError, TypeError, ValueError):
            return None

    newest = data.get("newest")
    try:
        newest = float(newest) if newest is not None else None
    except (TypeError, ValueError):
        newest = None

    hourly = []
    for bucket in data.get("hourly") or []:
        try:
            hourly.append([float(bucket[0]), float(bucket[1])])
        except (IndexError, TypeError, ValueError):
            continue
    hourly.sort()

    return {
        "total": whole("total"),
        "last_24h": whole("last_24h"),
        "newest": round(newest, 3) if newest is not None else None,
        "newest_age_s": (
            round(max(0.0, time.time() - newest), 1)
            if newest is not None else None
        ),
        "hourly": hourly,
    }


def capture_integrity() -> dict:
    """Return the research-capture pipeline's health, or an offline-safe shape.

    ``verdict`` collapses the live counters into one statement an administrator
    can act on. ``failing`` means research data is being lost right now;
    ``blind`` means the collector is not reporting at all, which is not the same
    as healthy and must never be rendered as such. The corpus figures alongside
    it come from the central log itself.
    """
    values: dict[str, float | None] = {name: None for name in _CAPTURE_QUERIES}
    corpus = capture_corpus()
    try:
        with ThreadPoolExecutor(max_workers=len(_CAPTURE_QUERIES)) as pool:
            futures = {
                pool.submit(_prometheus_query, expression): name
                for name, expression in _CAPTURE_QUERIES.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    values[name] = _sample_value(future.result())
                except Exception:
                    values[name] = None
    except Exception:
        pass

    def count(name):
        value = values.get(name)
        return int(value) if value is not None else None

    def flag(name):
        value = values.get(name)
        return None if value is None else bool(value)

    last_success = values.get("sync_last_success")
    sync_age = (
        round(max(0.0, time.time() - last_success), 1)
        if last_success is not None else None
    )

    lost = count("visits_lost")
    missed = count("status_missed")
    recent_lost = count("recent_visits_lost") or 0
    recent_missed = count("recent_status_missed") or 0
    sync_healthy = flag("sync_healthy")
    thread_up = flag("sync_thread_up")
    log_present = flag("access_log_present")

    # "Right now" drives the verdict; the cumulative totals are context.
    reasons = []
    if recent_lost:
        reasons.append(f"{recent_lost} visit(s) failed to reach the central log")
    if recent_missed:
        reasons.append(f"{recent_missed} final status(es) were dropped")
    if log_present is False:
        reasons.append("the authoritative nginx access log is unreadable")
    if thread_up is False:
        reasons.append("the status-sync thread is not running")
    if sync_healthy is False:
        reasons.append("the most recent access-log sync poll failed")
    if sync_age is not None and sync_age > _SYNC_STALE_AFTER_S:
        reasons.append(f"no successful sync poll for {int(sync_age // 60)} min")

    # Loss that has stopped is still loss: those visits are gone from the record
    # for good. Say so plainly without claiming the fault is ongoing.
    healed = []
    if lost and not recent_lost:
        healed.append(f"{lost} visit(s)")
    if missed and not recent_missed:
        healed.append(f"{missed} final status(es)")
    healed_note = (
        " Capture is working now, but " + " and ".join(healed)
        + " were lost earlier and cannot be recovered."
        if healed else ""
    )

    if all(values.get(name) is None for name in _CAPTURE_QUERIES):
        verdict, headline = "blind", "The visit collector is not reporting metrics."
    elif reasons:
        verdict = (
            "failing" if (recent_lost or recent_missed or log_present is False)
            else "degraded"
        )
        headline = "Capture is impaired: " + "; ".join(reasons) + "."
    elif healed:
        verdict = "healed"
        headline = healed_note.strip()
    else:
        verdict = "healthy"
        headline = "Every mirrored visit reached the central log."

    return {
        "verdict": verdict,
        "headline": headline,
        "reasons": reasons,
        # From the central log — the real corpus, not a process-local counter.
        "requests_captured": corpus["total"],
        "last_24h": corpus["last_24h"],
        "newest_age_s": corpus["newest_age_s"],
        "hourly": corpus["hourly"],
        # From the collector — the only source that knows what never arrived.
        "visits_lost": lost,
        "recent_visits_lost": recent_lost,
        "status_missed": missed,
        "recent_status_missed": recent_missed,
        "status_pending": count("status_pending"),
        "sync_errors": count("sync_errors"),
        "sync_healthy": sync_healthy,
        "sync_thread_up": thread_up,
        "access_log_present": log_present,
        "sync_age_s": sync_age,
    }


def response_mix(hours: int = _RESPONSE_MIX_HOURS) -> dict:
    """Return what the proxy actually returned, per host, over the last day.

    This is the one question nothing else on the box can answer. Prometheus has
    no nginx exporter; its blackbox probe only exercises a synthetic
    ``/__abd_health`` endpoint, so it never sees what a real crawler received.
    And ``all_visits`` holds only *matched* traffic — every request the catch-all
    dropped is absent from it by design.

    Buckets are chosen for what an operator does about them, not for tidy
    hundreds: ``served`` is the mission (a crawler got a canaried page),
    ``not_found`` is vulnerability probing (the dominant class here), ``refused``
    is the catch-all and other rejections, and ``errors`` is the only bucket that
    means this system is broken.
    """
    try:
        payload = _loki_metric_query(_RESPONSE_MIX_QUERY)
    except Exception:
        return {"hosts": [], "totals": {}, "hours": hours, "available": False}

    samples = _labeled_vector(payload)
    if not samples:
        # An empty result is a real answer (no traffic), but so is a failed
        # parse. `available` is decided by the query, not by the row count.
        available = isinstance(payload, dict) and payload.get("status") == "success"
        return {"hosts": [], "totals": {}, "hours": hours, "available": available}

    buckets = ("served", "not_found", "refused", "errors")
    hosts: dict[str, dict] = {}
    for labels, value in samples:
        host = labels.get("site") or ""
        try:
            status = int(labels.get("status", ""))
        except (TypeError, ValueError):
            continue
        count = int(value)
        if not count:
            continue
        if status < 400:
            bucket = "served"
        elif status == 404:
            bucket = "not_found"
        elif status >= 500:
            bucket = "errors"
        else:
            # 444 (catch-all drop), 499 (client aborted), 400/405 and friends.
            bucket = "refused"
        row = hosts.setdefault(
            host, {"host": host, "total": 0, **{name: 0 for name in buckets}}
        )
        row[bucket] += count
        row["total"] += count

    totals = {name: sum(row[name] for row in hosts.values()) for name in buckets}
    totals["total"] = sum(row["total"] for row in hosts.values())
    totals["hosts"] = len(hosts)

    ranked = sorted(hosts.values(), key=lambda row: -row["total"])
    # A host that erred outranks a busier healthy one: the reason to open this
    # panel is to find the broken thing, and truncation must not hide it.
    ranked.sort(key=lambda row: (row["errors"] > 0), reverse=True)
    return {
        "hosts": ranked[:_RESPONSE_MIX_MAX_HOSTS],
        "hidden_hosts": max(0, len(ranked) - _RESPONSE_MIX_MAX_HOSTS),
        "totals": totals,
        "hours": hours,
        "available": True,
    }


def series() -> dict[str, list]:
    """Return short host trends for KPI sparklines."""
    values = {
        "host_cpu_percent": [],
        "host_memory_percent": [],
    }
    try:
        with ThreadPoolExecutor(max_workers=len(values)) as pool:
            futures = {
                pool.submit(_prometheus_query_range, _KPI_QUERIES[name]): name
                for name in values
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    values[name] = _matrix_points(future.result())
                except Exception:
                    values[name] = []
    except Exception:
        pass
    return values


def _pipeline(rows: list[dict]) -> list[dict]:
    """Collapse expected container health into request-pipeline stages."""
    pipeline = []
    for key, label in _STAGES:
        stage_rows = [row for row in rows if row.get("stage") == key]
        if not stage_rows:
            continue
        total = len(stage_rows)
        up = sum(1 for row in stage_rows if row.get("status") == "up")
        down = sum(1 for row in stage_rows if row.get("status") == "down")
        if up == total:
            status = "up"
        elif down == total:
            status = "down"
        else:
            status = "degraded"
        pipeline.append({
            "key": key,
            "label": label,
            "status": status,
            "detail": f"{up}/{total} up",
        })
    return pipeline


def _clean_mapping(value) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key): str(item)
        for key, item in value.items()
        if key is not None and item is not None
    }


def alerts() -> list[dict]:
    """Return normalized firing Prometheus alerts, or an empty list offline."""
    try:
        payload = _get_json(_url(config.PROMETHEUS_URL, "api/v1/alerts"))
        raw_alerts = payload.get("data", {}).get("alerts", [])
        if payload.get("status") != "success" or not isinstance(raw_alerts, list):
            return []
    except Exception:
        return []

    normalized = []
    for item in raw_alerts:
        if not isinstance(item, dict) or item.get("state") != "firing":
            continue
        labels = _clean_mapping(item.get("labels"))
        annotations = _clean_mapping(item.get("annotations"))
        normalized.append({
            "name": labels.get("alertname", "Unnamed alert"),
            "severity": labels.get("severity", "unknown"),
            "summary": annotations.get("summary", ""),
            "description": annotations.get("description", ""),
            "active_at": str(item.get("activeAt") or ""),
            "state": "firing",
            "labels": labels,
        })
    normalized.sort(key=lambda item: (item["severity"], item["name"]))
    return normalized


def overview() -> dict:
    """Return the complete monitoring-page payload without ever raising.

    Prometheus and Loki data calls are independently gated by their own health
    probes. A short process-local cache coalesces simultaneous admin tabs into
    one bounded fan-out.
    """
    now = time.time()
    cached = _CACHE.get("data")
    if cached is not None and now - float(_CACHE.get("at") or 0.0) < _CACHE_TTL:
        return cached

    health = stack_health()
    payload = {
        "ok": all(health.values()),
        "generated_at": round(time.time(), 3),
        "health": health,
        # Host resources only. Traffic volume lives with capture integrity,
        # where it is a count over a real window rather than an instantaneous
        # rate — this traffic is ~89% idle minutes punctuated by bursts of
        # hundreds, so a per-minute reading reported 0.0 nearly always and told
        # an operator nothing about demand.
        "kpis": {name: None for name in _KPI_QUERIES},
        "series": {
            "host_cpu_percent": [],
            "host_memory_percent": [],
        },
        "containers": [],
        "pipeline": [],
        "probes": [],
        "alerts": [],
        "response_mix": {"hosts": [], "totals": {}, "available": False},
        "capture": {
            "verdict": "blind",
            "headline": "Prometheus is unavailable, so capture integrity is unknown.",
            "reasons": [],
        },
        "notifications": {
            "mode": config.ALERT_DELIVERY_MODE,
            "external_delivery": config.ALERT_DELIVERY_MODE != "local-only",
        },
    }

    if health.get("prometheus"):
        try:
            worker_count = 8 if health.get("loki") else 6
            with ThreadPoolExecutor(max_workers=worker_count) as pool:
                futures = {
                    "kpis": pool.submit(kpis),
                    "alerts": pool.submit(alerts),
                    "containers": pool.submit(containers),
                    "probes": pool.submit(endpoint_probes),
                    "series": pool.submit(series),
                    "capture": pool.submit(capture_integrity),
                }
                if health.get("loki"):
                    futures["response_mix"] = pool.submit(response_mix)

                for name, future in futures.items():
                    try:
                        value = future.result()
                    except Exception:
                        continue
                    if name == "capture" and isinstance(value, dict):
                        payload["capture"] = value
                    elif name == "kpis" and isinstance(value, dict):
                        payload["kpis"].update(value)
                    elif name == "alerts" and isinstance(value, list):
                        payload["alerts"] = value
                    elif name == "containers" and isinstance(value, list):
                        payload["containers"] = value
                        payload["pipeline"] = _pipeline(value)
                    elif name == "probes" and isinstance(value, list):
                        payload["probes"] = value
                    elif name == "response_mix" and isinstance(value, dict):
                        payload["response_mix"] = value
                    elif name == "series" and isinstance(value, dict):
                        payload["series"].update(value)
        except Exception:
            pass
    elif health.get("loki"):
        try:
            payload["response_mix"] = response_mix()
        except Exception:
            pass

    _CACHE.update(at=time.time(), data=payload)
    return payload
