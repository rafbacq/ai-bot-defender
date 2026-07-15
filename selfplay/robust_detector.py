"""The robust detector — the v1 deliverable that ships back to ``/logs``.

The self-play attacker discovers evasions the *rule-based* production detector
misses — notably a residential-consistent browser crawling at high volume with
metronomic timing (no cross-layer contradiction, no cohort fingerprint to stitch).
That evader deliberately breaks the graph (unique device/JA4 per IP → isolated
nodes), so a GNN's neighbour message-passing has nothing to propagate. The
discriminative signal lives in the **node features themselves** (``log_n_requests``,
``burstiness``, ``log_mean_gap`` …), so the robust detector is a small **MLP over the
exact 22-D ``crawler_graph.ml.features.node_vector``** — same feature contract as the
production GNN — trained on honest-vs-attacker endpoints (disguised-crawler = 1,
humans + *declared* crawlers = 0).

Ships as ``selfplay/output/robust_detector.pt``; ``score_live`` writes
``robust_predictions.json`` for the ``/logs`` second-opinion panel. torch is imported
lazily; without it everything degrades to a "not trained" state.
"""

import json
import os
import tempfile

import numpy as np

from . import config


# ------------------------------------------------------------ dataset
def gather_dataset(env, policy, n_attacker_eps=40, n_bg_batches=6, greedy=False):
    """Build (X, y) from attacker rollouts (label 1) + honest background (label 0)."""
    from . import calibration
    from crawler_graph.ml import features
    import torch

    X, y = [], []
    # Positives: the attacker's own cohorts (its learned evasions are the hard cases).
    for _ in range(n_attacker_eps):
        obs, _ = env.reset()
        h = policy.initial_state(1)
        done = False
        while not done:
            ot = torch.as_tensor(obs, dtype=torch.float32).unsqueeze(0)
            action, _, _, _, h = policy.act(ot, h, greedy=greedy)
            obs, _, done, _, info = env.step(action)
        eps = calibration.build_endpoints(env.state.bundle)
        atk = set(env.state.ips.keys())
        for ip, rec in eps.items():
            if ip in atk:
                X.append(features.node_vector(rec))
                y.append(1)
    # Negatives: honest humans + declared crawlers from the background.
    for b in range(n_bg_batches):
        bg = env.tm.sample_background(env.cfg.background_size, seed=1000 + b)
        eps = calibration.build_endpoints(bg)
        for rec in eps.values():
            X.append(features.node_vector(rec))
            y.append(0)
    return np.asarray(X, dtype=np.float64), np.asarray(y, dtype=np.float64), features.FEATURE_NAMES


# ------------------------------------------------------------ model
def _build_mlp(in_dim, hidden=48):
    import torch.nn as nn
    return nn.Sequential(
        nn.Linear(in_dim, hidden), nn.ReLU(),
        nn.Linear(hidden, hidden), nn.ReLU(),
        nn.Linear(hidden, 1),
    )


def train(X, y, epochs=300, lr=1e-3, seed=0, val_frac=0.3):
    import torch
    import torch.nn.functional as F
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    n = len(y)
    if n < 8 or len(set(y.tolist())) < 2:
        return {"trained": False, "reason": f"insufficient/one-class data (n={n})"}
    idx = rng.permutation(n)
    cut = max(2, int((1 - val_frac) * n))
    tr, va = idx[:cut], idx[cut:]
    mean, std = X[tr].mean(0), X[tr].std(0)
    std = np.where(std < 1e-6, 1.0, std)
    Xs = torch.tensor((X - mean) / std, dtype=torch.float32)
    yt = torch.tensor(y, dtype=torch.float32)
    tr_t, va_t = torch.tensor(tr), torch.tensor(va)

    # class weighting (positives may be rarer)
    pos = float(y[tr].sum()); neg = float(len(tr) - pos)
    pos_w = torch.tensor([neg / max(1.0, pos)], dtype=torch.float32)

    model = _build_mlp(X.shape[1])
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    best_auc, best_state = -1.0, None
    for ep in range(epochs):
        model.train(); opt.zero_grad()
        logits = model(Xs[tr_t]).squeeze(-1)
        loss = F.binary_cross_entropy_with_logits(logits, yt[tr_t], pos_weight=pos_w)
        loss.backward(); opt.step()
        if len(va) >= 2 and ep % 10 == 0:
            model.eval()
            with torch.no_grad():
                vs = torch.sigmoid(model(Xs[va_t]).squeeze(-1)).numpy()
            auc = _auc(vs, y[va])
            if auc >= best_auc:
                best_auc, best_state = auc, {k: v.clone() for k, v in model.state_dict().items()}
    if best_state is not None:
        model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        tr_auc = _auc(torch.sigmoid(model(Xs[tr_t]).squeeze(-1)).numpy(), y[tr])
    return {"trained": True, "_model": model, "mean": mean, "std": std,
            "in_dim": int(X.shape[1]), "val_auc": round(float(best_auc), 4),
            "train_auc": round(float(tr_auc), 4), "n": int(n),
            "n_pos": int(y.sum()), "n_neg": int(len(y) - y.sum())}


def _auc(scores, labels):
    from .calibration import _auc as auc_fn
    return auc_fn(scores, labels)


# ------------------------------------------------------------ persist
def save(result, path=None):
    import torch
    path = path or config.ROBUST_DETECTOR
    config.ensure_output_dir()
    torch.save({
        "state_dict": result["_model"].state_dict(),
        "in_dim": result["in_dim"],
        "mean": result["mean"], "std": result["std"],
        "val_auc": result.get("val_auc"), "train_auc": result.get("train_auc"),
        "n_pos": result.get("n_pos"), "n_neg": result.get("n_neg"),
    }, path)
    return str(path)


def available():
    try:
        from crawler_graph.ml import gnn
        return gnn.torch_available() and config.ROBUST_DETECTOR.exists()
    except Exception:
        return False


def _load():
    import torch
    ckpt = torch.load(config.ROBUST_DETECTOR, map_location="cpu", weights_only=False)
    model = _build_mlp(ckpt["in_dim"])
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    return model, ckpt


def make_scorer(result):
    """Wrap an in-memory training ``result`` into a ``scorer(endpoints) -> {ip: prob}``
    (used by PSRO, which juggles several defender models without touching disk)."""
    import torch
    from crawler_graph.ml import features
    model, mean, std = result["_model"], result["mean"], result["std"]

    def scorer(endpoints):
        if not endpoints:
            return {}
        ips = list(endpoints.keys())
        X = np.asarray([features.node_vector(endpoints[ip]) for ip in ips], dtype=np.float64)
        Xs = torch.tensor((X - mean) / std, dtype=torch.float32)
        with torch.no_grad():
            p = torch.sigmoid(model(Xs).squeeze(-1)).numpy()
        return {ip: float(v) for ip, v in zip(ips, p)}

    return scorer


def score_endpoints(endpoints):
    """Return ``{ip: disguise_prob}`` for a dict of endpoint records."""
    import torch
    from crawler_graph.ml import features
    if not endpoints:
        return {}
    model, ckpt = _load()
    ips = list(endpoints.keys())
    X = np.asarray([features.node_vector(endpoints[ip]) for ip in ips], dtype=np.float64)
    Xs = torch.tensor((X - ckpt["mean"]) / ckpt["std"], dtype=torch.float32)
    with torch.no_grad():
        probs = torch.sigmoid(model(Xs).squeeze(-1)).numpy()
    return {ip: float(p) for ip, p in zip(ips, probs)}


# ------------------------------------------------------------ live second opinion
def score_live(threshold=0.5, since_hours=None, limit=None, cancel_check=None):
    """Score the current logdb endpoints with the robust detector and persist
    ``robust_predictions.json`` for the /logs second-opinion panel. Also compares
    against the production detector's disguise verdict. Degrades gracefully."""
    from crawler_graph.ingest import db, enrich
    from crawler_graph.analysis import consistency
    from crawler_graph.graphing import builder, community, campaigns as cmod

    if not available():
        return {"ok": False, "reason": "robust detector not trained / torch missing"}
    if cancel_check:
        cancel_check()
    try:
        visits = db.fetch_visits(limit=limit, since_hours=since_hours)
    except Exception as exc:
        return {"ok": False, "reason": f"logdb unavailable: {exc}"}
    if not visits:
        return {"ok": False, "reason": "no visits in logdb"}
    if cancel_check:
        cancel_check()
    try:
        handshakes = db.fetch_handshakes(since_hours=since_hours)
        tcp = db.fetch_tcp_fingerprints(since_hours=since_hours)
        bfp = db.fetch_browser_fingerprints(since_hours=since_hours)
    except Exception:
        handshakes = tcp = bfp = []

    enrich.join_fingerprints(visits, handshakes)
    enrich.join_tcp_fingerprints(visits, tcp)
    enrich.enrich_visits(visits, resolve_asn=True)
    endpoints = enrich.aggregate_endpoints(visits)
    enrich.attach_browser_fingerprints(endpoints, bfp)
    consistency.annotate(endpoints)
    if cancel_check:
        cancel_check()

    probs = score_endpoints(endpoints)
    # production disguise verdict per IP (from campaign membership)
    g = builder.build_graph(endpoints)
    mem, _ = community.detect_communities(g)
    camps = cmod.build_campaigns(g, mem, endpoints)
    if cancel_check:
        cancel_check()
    prod_disguised = set()
    for c in camps:
        if c.get("disguise_suspected") or c.get("agentic_suspected"):
            prod_disguised.update(c.get("sample_ips") or [])

    rows, robust_only = [], 0
    for ip, p in probs.items():
        robust_flag = p >= threshold
        prod_flag = ip in prod_disguised
        if robust_flag and not prod_flag:
            robust_only += 1
        rows.append({"ip": ip, "robust_prob": round(p, 4),
                     "robust_flag": bool(robust_flag), "prod_flag": bool(prod_flag),
                     "agree": bool(robust_flag == prod_flag)})
    rows.sort(key=lambda r: r["robust_prob"], reverse=True)
    payload = {
        "n_endpoints": len(rows),
        "n_robust_flagged": sum(1 for r in rows if r["robust_flag"]),
        "n_prod_flagged": sum(1 for r in rows if r["prod_flag"]),
        "n_robust_only": robust_only,           # caught by robust, missed by production
        "threshold": threshold,
        "predictions": rows[:500],
    }
    if cancel_check:
        cancel_check()
    config.ensure_output_dir()
    fd, tmp = tempfile.mkstemp(
        prefix="robust_predictions_", suffix=".json.tmp",
        dir=config.OUTPUT_DIR,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        if cancel_check:
            cancel_check()
        os.replace(tmp, config.ROBUST_PREDS)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
    payload["ok"] = True
    return payload
