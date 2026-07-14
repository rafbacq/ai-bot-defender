"""Crawler-intelligence service for the /intel page.

Thin adapter over the repo-root ``crawler_graph`` package. The page reads the
persisted ``output/campaigns.json`` (fast); a "Recompute" action re-runs the
pipeline against the live ``logdb``. Two recompute modes:

  * **cheap** (default) — community detection + UA/ASN/fingerprint attribution,
    no torch.
  * **GraphSAGE GNN** (``use_gnn=True``) — also trains the supervised provider
    classifier and folds its predictions into attribution. torch + torch_geometric
    are baked into the app image (the template-generator stack already ships torch;
    ``torch_geometric`` is added in a late Docker layer), so this now runs *in the
    app* — no terminal step required. Training is fast on this graph size (CPU is
    fine) but the first run pays the torch-import cost, so it is opt-in per recompute.

The package reads logdb exactly like ``request_log`` (``docker compose exec
logdb psql``), so this works from inside the path-mirrored app container.
"""

import json

from .. import config

# crawler_graph lives at the repo root and imports the same way querying does.
try:
    from crawler_graph import config as cg_config
    from crawler_graph import pipeline as cg_pipeline
    from crawler_graph import reporting as cg_report
    _IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - surfaced in the UI
    cg_config = cg_pipeline = cg_report = None
    _IMPORT_ERROR = str(exc)


class IntelError(RuntimeError):
    """Raised when the crawler-graph layer is unavailable."""


def available():
    return _IMPORT_ERROR is None


def gnn_available():
    """True when torch + torch_geometric are importable (GNN can run in-app)."""
    if not available():
        return False
    try:
        from crawler_graph.ml import gnn as gnn_mod
        return gnn_mod.torch_available()
    except Exception:
        return False


def gnn_status():
    """Persisted GraphSAGE state from the last GNN run, for the page header.

    Reads ``output/gnn_predictions.json`` (written whenever the GNN trains) and
    whether ``output/gnn_model.pt`` is on disk. Returns ``None`` if the GNN has
    never been run here.
    """
    if not available():
        return None
    preds_path = cg_config.GNN_PREDS
    if not preds_path.exists():
        return None
    try:
        with open(preds_path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    preds = payload.get("predictions", {})
    n_attributed = sum(
        1 for p in preds.values()
        if p.get("provider") and p["provider"] != "unknown"
    )
    return {
        "classes": payload.get("labels") or [],
        "n_classes": len(payload.get("labels") or []),
        "n_labeled": payload.get("n_labeled"),
        "n_val": payload.get("n_val"),
        "train_acc": payload.get("train_acc"),
        "val_acc": payload.get("val_acc"),
        "final_loss": payload.get("final_loss"),
        "method": payload.get("method"),
        "n_nodes": len(preds),
        "n_attributed": n_attributed,
        "model_saved": cg_config.GNN_MODEL.exists(),
    }


def load_report():
    """Return the persisted campaigns payload, or ``None`` if not computed yet."""
    if not available():
        return None
    return cg_report.read_campaigns()


def viz_path():
    """Absolute path to the campaign visualization PNG, or ``None``."""
    if not available():
        return None
    path = cg_config.GRAPH_VIZ
    return path if path.exists() else None


def interactive_viz_path():
    """Absolute path to the interactive HTML graph (hover + per-cluster colour),
    or ``None`` if it hasn't been rendered yet."""
    if not available():
        return None
    path = cg_config.GRAPH_VIZ_HTML
    return path if path.exists() else None


def recompute(limit=None, since_hours=None, use_gnn=False):
    """Re-run the pipeline against logdb and persist + return the result.

    ``use_gnn`` additionally trains the GraphSAGE classifier and applies its
    provider attribution (requires torch_geometric — see ``gnn_available``).
    """
    if not available():
        raise IntelError(f"crawler_graph is not importable: {_IMPORT_ERROR}")
    if use_gnn and not gnn_available():
        raise IntelError(
            "The GraphSAGE GNN needs torch_geometric, which is not importable in "
            "this environment. Rebuild the app image (it installs it) or run the "
            "cheap recompute without the GNN."
        )
    try:
        return cg_pipeline.run_intel(
            limit=limit, since_hours=since_hours,
            resolve_asn=True, use_gnn=use_gnn, write=True, render=True,
        )
    except Exception as exc:
        raise IntelError(str(exc)) from exc


def summary():
    """Compact findings summary for the landing-page stats (or ``None``)."""
    payload = load_report()
    if not payload:
        return None
    f = payload.get("findings", {})
    return {
        "campaigns": f.get("n_campaigns"),
        "disguised": f.get("n_disguised"),
        "agentic": f.get("n_agentic"),
        "contradiction": f.get("n_contradiction"),
        "vm_cohort": f.get("n_vm_cohort"),
        "browser_fingerprinted": f.get("n_browser_fingerprinted"),
        "generated_at": payload.get("generated_at"),
    }
