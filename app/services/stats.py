"""Aggregate the landing-page statistics from every layer of the project."""

from . import (
    fingerprint_service, graph_intel, querying_service, request_log,
    selfplay_service, sites,
)


def landing_stats():
    """Return the headline metrics shown on the landing page.

    Each value degrades gracefully: counts that need a running service (the
    request log) return ``None`` when that service is unavailable, and the UI
    renders a dash instead of a number.
    """
    configured = sites.list_sites()
    live_routes = sites.active_proxy_sites()
    runs = querying_service.runs_summary()
    intel = graph_intel.summary() or {}
    fp = fingerprint_service.summary_counts()
    sp = selfplay_service.summary() or {}

    return {
        "sites_live": len(live_routes),
        "sites_configured": len(configured),
        "llm_models": len(querying_service.available_models()),
        "queries_completed": runs["queries_completed"],
        "matches_found": runs["matches_found"],
        "best_score": runs["best_score"],
        "query_runs": runs["total_runs"],
        "requests_logged": request_log.total_request_count(),
        "campaigns": intel.get("campaigns"),
        "disguised": intel.get("disguised"),
        "device_fingerprints": fp.get("fingerprints"),
        "unique_devices": fp.get("unique_devices"),
        "contradictions": intel.get("contradiction"),
        "evasion_lift": sp.get("evasion_lift"),
        "robust_auc": sp.get("robust_auc"),
    }
