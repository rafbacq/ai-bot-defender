"""Node feature engineering for the GNN.

Turns the per-endpoint records + the IP–IP projected graph into the numeric
arrays a GraphSAGE model consumes: a feature matrix ``X``, an ``edge_index``,
edge weights, integer node labels (provider class, or -1 for unlabeled), and the
label vocabulary. No torch here — just plain Python lists — so this module has
no heavy dependency; ``gnn.py`` converts these to tensors.

Labels are the *declared* provider (from the UA) — high-precision seeds for
semi-supervised learning. The model then predicts providers for the unlabeled
IPs, and a confident prediction on a browser/automation IP is a disguise signal.
"""

import math

# The numeric per-node features (order is the model's input contract). The
# fingerprint/consistency features are appended after the originals so the order
# stays additive (the model retrains each run, so a longer vector is fine).
FEATURE_NAMES = [
    "log_n_requests",
    "log_n_sites",
    "log_n_paths",
    "path_entropy",
    "ua_entropy",
    "hour_entropy",
    "n_user_agents",
    "has_fingerprint",
    "is_browser",
    "is_automated",
    "burstiness",
    "log_mean_gap",
    "log_span_s",
    # Layer-1 (browser) + Layer-2 (TCP-OS) + cross-layer consistency signals.
    "has_browser_fp",
    "log_n_device_keys",
    "automation_score",
    "inconsistency_score",
    "vm_cohort",
    "tcp_os_windows",
    "tcp_os_apple",
    "tcp_os_linux",
    "behavior_synthetic",
]


def _safe_log(x):
    try:
        return math.log1p(max(0.0, float(x)))
    except (TypeError, ValueError):
        return 0.0


def node_vector(rec):
    """Map one endpoint record to the fixed-length numeric feature vector."""
    cons = rec.get("consistency") or {}
    tcp = set(rec.get("tcp_os") or [])
    return [
        _safe_log(rec.get("n_requests", 0)),
        _safe_log(rec.get("n_sites", 0)),
        _safe_log(rec.get("n_paths", 0)),
        float(rec.get("path_entropy") or 0.0),
        float(rec.get("ua_entropy") or 0.0),
        float(rec.get("hour_entropy") or 0.0),
        _safe_log(rec.get("n_user_agents", 0)),
        1.0 if rec.get("has_fingerprint") else 0.0,
        1.0 if rec.get("is_browser") else 0.0,
        1.0 if rec.get("is_automated") else 0.0,
        float(rec.get("burstiness") or 0.0),
        _safe_log(rec.get("mean_gap") or 0.0),
        _safe_log(rec.get("span_s") or 0.0),
        1.0 if rec.get("has_browser_fingerprint") else 0.0,
        _safe_log(rec.get("n_device_keys", 0)),
        float(rec.get("automation_score") or 0.0),
        float(cons.get("score") or 0.0),
        1.0 if cons.get("vm_cohort") else 0.0,
        1.0 if "Windows" in tcp else 0.0,
        1.0 if "Apple" in tcp else 0.0,
        1.0 if "Linux" in tcp else 0.0,
        1.0 if rec.get("behavior_synthetic") else 0.0,
    ]


def build_arrays(ip_graph, endpoints):
    """Return a dict of arrays describing the graph for the GNN.

    Keys: ``nodes`` (ip list, the row order), ``x`` (list[list[float]]),
    ``edge_index`` (2 x E), ``edge_weight`` (E), ``y`` (int labels, -1 unlabeled),
    ``labels`` (provider vocab, index = class id), ``train_mask`` (bool per node).
    """
    nodes = [n for n, d in ip_graph.nodes(data=True) if d.get("kind", "ip") == "ip"]
    if not nodes:
        nodes = list(ip_graph.nodes())
    index = {n: i for i, n in enumerate(nodes)}

    # Build the label vocabulary from declared providers present in the data.
    providers = sorted({
        p
        for ip in nodes
        for p in (endpoints.get(ip, {}).get("providers_ua") or [])
    })
    label_id = {p: i for i, p in enumerate(providers)}

    x, y, train_mask = [], [], []
    for ip in nodes:
        rec = endpoints.get(ip, {})
        x.append(node_vector(rec))
        decl = rec.get("providers_ua") or []
        if len(decl) == 1 and decl[0] in label_id:
            y.append(label_id[decl[0]])
            train_mask.append(True)
        else:
            y.append(-1)
            train_mask.append(False)

    src, dst, weight = [], [], []
    for u, v, data in ip_graph.edges(data=True):
        if u in index and v in index:
            w = float(data.get("weight", 1.0))
            src += [index[u], index[v]]      # undirected -> both directions
            dst += [index[v], index[u]]
            weight += [w, w]

    return {
        "nodes": nodes,
        "x": x,
        "edge_index": [src, dst],
        "edge_weight": weight,
        "y": y,
        "labels": providers,
        "train_mask": train_mask,
        "feature_names": FEATURE_NAMES,
    }
