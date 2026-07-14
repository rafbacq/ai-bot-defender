"""Orchestrate the crawler-graph intelligence run end to end.

    fetch visits + handshakes  ->  join fingerprints  ->  enrich (ASN/UA flags)
        ->  aggregate endpoints  ->  build identity graph  ->  community detection
        ->  (optional) GraphSAGE attribution  ->  campaigns + findings  ->  report

``run_intel`` is what both the CLI (``python -m crawler_graph build``) and the
app's /intel service call. It accepts injected ``visits``/``handshakes`` (used by
the offline selftest and unit tests) so it can run without a live database.
"""

from datetime import datetime, timezone

from . import config
from . import reporting as report
from .analysis import consistency
from .graphing import builder as graph
from .graphing import campaigns as campaigns_mod
from .graphing import community
from .ingest import db, enrich
from .ml import features


def _gnn_meta(gnn_result, requested):
    """A JSON-serializable summary of a GraphSAGE training run for the report.

    Carries the generalization metrics (train/val accuracy), the provider classes
    it learned, and how many IPs it ended up attributing — everything the /intel
    page needs to show *why* an attribution should (or shouldn't) be trusted.
    """
    preds = gnn_result.get("predictions") or {}
    n_attributed = sum(
        1 for p in preds.values()
        if p.get("provider") and p["provider"] != "unknown"
    )
    return {
        "requested": bool(requested),
        "used": bool(preds),
        "reason": gnn_result.get("reason"),
        "method": gnn_result.get("method"),
        "classes": gnn_result.get("labels") or [],
        "n_classes": len(gnn_result.get("labels") or []),
        "n_labeled": gnn_result.get("n_labeled"),
        "n_val": gnn_result.get("n_val"),
        "train_acc": gnn_result.get("train_acc"),
        "val_acc": gnn_result.get("val_acc"),
        "final_loss": gnn_result.get("final_loss"),
        "n_attributed": n_attributed,
        "n_nodes": len(preds),
    }


def run_intel(
    *,
    visits=None,
    handshakes=None,
    browser_fps=None,
    tcp_fps=None,
    limit=None,
    since_hours=None,
    resolve_asn=True,
    use_gnn=False,
    method="auto",
    write=True,
    render=True,
):
    """Run the full pipeline and return a result dict (campaigns + meta + graph).

    When ``visits`` is None the data is loaded from logdb; otherwise the provided
    rows are used as-is (offline mode). ``use_gnn`` trains the GraphSAGE model and
    folds its predictions into attribution (requires torch/torch_geometric).
    """
    started = datetime.now(timezone.utc)

    if visits is None:
        visits = db.fetch_visits(limit=limit, since_hours=since_hours)
    if handshakes is None:
        try:
            handshakes = db.fetch_handshakes(since_hours=since_hours)
        except db.IntelDBError:
            handshakes = []
    if tcp_fps is None:
        try:
            tcp_fps = db.fetch_tcp_fingerprints(since_hours=since_hours)
        except db.IntelDBError:
            tcp_fps = []
    if browser_fps is None:
        try:
            browser_fps = db.fetch_browser_fingerprints(since_hours=since_hours)
        except db.IntelDBError:
            browser_fps = []

    # Layer 2: attach TLS (4-tuple) + TCP/OS (4-tuple) fingerprints to each visit.
    enrich.join_fingerprints(visits, handshakes or [])
    enrich.join_tcp_fingerprints(visits, tcp_fps or [])
    enrich.enrich_visits(visits, resolve_asn=resolve_asn)
    endpoints = enrich.aggregate_endpoints(visits)
    # Layer 1: fold browser fingerprints onto endpoints (by IP), then run the
    # cross-layer consistency engine over the assembled per-endpoint signals.
    enrich.attach_browser_fingerprints(endpoints, browser_fps or [])
    consistency.annotate(endpoints)

    full_graph = graph.build_graph(endpoints)
    membership, method_used = community.detect_communities(full_graph, method=method)
    ip_graph = graph.project_to_ip_graph(full_graph)

    gnn_result = {"predictions": {}}
    if use_gnn:
        arrays = features.build_arrays(ip_graph, endpoints)
        from .ml import gnn as gnn_mod

        gnn_result = gnn_mod.train_classifier(arrays)
        if write and gnn_result.get("predictions"):
            gnn_mod.save_predictions(gnn_result)
            try:  # persisting the model is best-effort — never fail a run on it
                gnn_mod.save_model(gnn_result)
            except Exception:
                pass

    camps = campaigns_mod.build_campaigns(
        full_graph, membership, endpoints, gnn_preds=gnn_result.get("predictions")
    )

    meta = {
        "n_visits": len(visits),
        "n_handshakes": len(handshakes or []),
        "n_browser_fps": len(browser_fps or []),
        "n_tcp_fps": len(tcp_fps or []),
        "n_endpoints": len(endpoints),
        "community_method": method_used,
        "modularity": community.modularity(full_graph, membership),
        "graph": graph.graph_summary(full_graph),
        "gnn_used": bool(use_gnn and gnn_result.get("predictions")),
        "gnn_reason": gnn_result.get("reason"),
        "gnn": _gnn_meta(gnn_result, requested=use_gnn),
        "fingerprints_present": any(e.get("has_fingerprint") for e in endpoints.values()),
        "browser_fingerprints_present": any(
            e.get("has_browser_fingerprint") for e in endpoints.values()),
        "tcp_fingerprints_present": any(e.get("tcp_os") for e in endpoints.values()),
        "n_inconsistent_endpoints": sum(
            1 for e in endpoints.values() if (e.get("consistency") or {}).get("inconsistent")),
        "n_vm_cohort_endpoints": sum(
            1 for e in endpoints.values() if (e.get("consistency") or {}).get("vm_cohort")),
        "duration_s": round((datetime.now(timezone.utc) - started).total_seconds(), 2),
    }

    result = {
        "meta": meta,
        "findings": campaigns_mod.findings(camps),
        "campaigns": camps,
    }

    if write:
        result["campaigns_path"] = str(report.write_campaigns(camps, meta))
        if render:
            viz = report.render_graph(ip_graph, membership)
            if viz:
                result["viz_path"] = str(viz)
            # Interactive HTML graph (distinct colour per campaign + hover rundown).
            viz_html = report.render_interactive(ip_graph, membership, camps)
            if viz_html:
                result["viz_html_path"] = str(viz_html)

    return result
