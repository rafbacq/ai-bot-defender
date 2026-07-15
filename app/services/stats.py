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
    registered_models = querying_service.available_models()
    runs = querying_service.runs_summary()
    intel = graph_intel.summary() or {}
    fp = fingerprint_service.summary_counts()
    # Device disguise is a live database aggregate. Do not use
    # ``intel["disguised"]`` here: that is the number of *campaigns* marked as
    # disguised in the last persisted graph-analysis run, so it can remain
    # unchanged long after new fingerprint beacons arrive. The /logs page uses
    # this same live aggregate for its disguised-device panel.
    disguise = fingerprint_service.disguise_summary() or {}
    sp = selfplay_service.summary() or {}

    return {
        "sites_live": len(live_routes),
        "sites_configured": len(configured),
        # Count models that can actually run now, not every registry entry.
        # Offline controls are always ready; live providers become ready as
        # soon as their key is saved from the Forensics page.
        "llm_models": sum(
            1 for model_id in registered_models
            if querying_service.model_ready(model_id)
        ),
        "queries_completed": runs["queries_completed"],
        "matches_found": runs["matches_found"],
        "best_score": runs["best_score"],
        "query_runs": runs["total_runs"],
        "requests_logged": request_log.total_request_count(),
        "campaigns": intel.get("campaigns"),
        "disguised": disguise.get("disguised"),
        "device_fingerprints": fp.get("fingerprints"),
        "unique_devices": fp.get("unique_devices"),
        "contradictions": intel.get("contradiction"),
        "intel_generated_at": intel.get("generated_at"),
        "evasion_lift": sp.get("evasion_lift"),
        "robust_auc": sp.get("robust_auc"),
    }
