"""GraphSAGE GNN for crawler attribution (AI Bot Defender — Direction 6a).

Two capabilities over the IP–IP identity graph:

  * **Supervised provider classification.** Train on the IPs whose declared UA
    gives a high-precision provider label, then predict a provider for *every*
    IP. A confident prediction on an IP that presents a browser/automation UA
    (no declared bot) is a disguise signal the UA alone can't surface — message
    passing propagates "this neighborhood behaves like OpenAI infra" across the
    graph.
  * **Unsupervised embeddings.** A GraphSAGE encoder trained with a
    neighbor-contrastive objective produces per-IP embeddings for campaign
    discovery / KMeans when labels are scarce.

torch + torch_geometric are imported lazily *inside* the functions, so importing
this module (and the whole package) never requires them. ``torch_available()``
lets callers degrade gracefully. They ship in the app image, so training runs
in-process from the /intel page; headless via ``python -m crawler_graph gnn-train``
or ``build --gnn``. Needs >=2 declared-provider classes to train (see
``train_classifier``).
"""

import json

from .. import config
from . import features


def torch_available():
    try:
        import torch  # noqa: F401
        import torch_geometric  # noqa: F401
        return True
    except Exception:
        return False


def _build_model(in_dim, hidden, n_classes):
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.nn import SAGEConv

    class GraphSAGE(nn.Module):
        def __init__(self):
            super().__init__()
            self.conv1 = SAGEConv(in_dim, hidden)
            self.conv2 = SAGEConv(hidden, hidden)
            self.head = nn.Linear(hidden, n_classes)

        def encode(self, x, edge_index):
            h = F.relu(self.conv1(x, edge_index))
            h = F.dropout(h, p=0.3, training=self.training)
            h = self.conv2(h, edge_index)
            return h

        def forward(self, x, edge_index):
            return self.head(F.relu(self.encode(x, edge_index)))

    return GraphSAGE()


def _to_tensors(arrays):
    import torch

    x = torch.tensor(arrays["x"], dtype=torch.float)
    # Standardize features (column-wise) for stable training.
    mean = x.mean(dim=0, keepdim=True)
    std = x.std(dim=0, keepdim=True).clamp_min(1e-6)
    x = (x - mean) / std
    edge_index = torch.tensor(arrays["edge_index"], dtype=torch.long)
    if edge_index.numel() == 0:
        edge_index = torch.empty((2, 0), dtype=torch.long)
    y = torch.tensor(arrays["y"], dtype=torch.long)
    train_mask = torch.tensor(arrays["train_mask"], dtype=torch.bool)
    return x, edge_index, y, train_mask, mean, std


def _split_labeled(y_list, train_mask_list, val_frac=0.3, seed=42):
    """Stratified train/val split over the labeled nodes.

    Each class keeps at least one node in train; classes with >=3 labeled nodes
    contribute ~``val_frac`` to validation, so we can report generalization
    instead of only fit. Returns (train_idx_mask, val_idx_mask) as bool lists.
    """
    import random as _random

    by_class = {}
    for i, (lab, m) in enumerate(zip(y_list, train_mask_list)):
        if m and lab >= 0:
            by_class.setdefault(lab, []).append(i)

    rng = _random.Random(seed)
    n = len(y_list)
    tr = [False] * n
    va = [False] * n
    for _, idxs in by_class.items():
        idxs = idxs[:]
        rng.shuffle(idxs)
        n_val = int(len(idxs) * val_frac) if len(idxs) >= 3 else 0
        for i in idxs[:n_val]:
            va[i] = True
        for i in idxs[n_val:]:
            tr[i] = True
    return tr, va


def train_classifier(arrays, hidden=32, epochs=200, lr=0.01, weight_decay=5e-4,
                     verbose=False, cancel_check=None):
    """Train the supervised GraphSAGE classifier; return predictions per IP.

    Returns ``{ip: {"provider": str, "confidence": float}}`` plus training meta.
    If there are too few labeled nodes or no torch, returns an empty result with
    a ``reason`` so callers can fall back to community-only attribution.
    """
    labels = arrays["labels"]
    nodes = arrays["nodes"]
    if not labels:
        return {"predictions": {}, "reason": "no declared-provider labels to train on"}
    if len(labels) < 2:
        # With a single class the classifier is degenerate (predicts that one
        # provider for everyone at confidence ~1.0), which would spray bogus
        # "GNN attributes this to X" disguise flags. Need >=2 classes to learn
        # anything that separates infrastructure.
        return {"predictions": {}, "reason": (
            f"only one declared-provider class ({labels[0]}) — GNN attribution "
            "needs >=2 provider classes to be meaningful")}
    n_labeled = sum(1 for v in arrays["y"] if v >= 0)
    if n_labeled < max(2, len(labels)):
        return {"predictions": {}, "reason": f"too few labeled nodes ({n_labeled})"}
    if not torch_available():
        return {"predictions": {}, "reason": "torch / torch_geometric not installed"}

    import torch
    import torch.nn.functional as F

    torch.manual_seed(42)
    x, edge_index, y, train_mask, mean, std = _to_tensors(arrays)
    tr_list, va_list = _split_labeled(arrays["y"], arrays["train_mask"])
    tr = torch.tensor(tr_list, dtype=torch.bool)
    va = torch.tensor(va_list, dtype=torch.bool)
    if not bool(tr.any()):  # tiny data: fall back to training on all labeled
        tr = train_mask

    model = _build_model(x.size(1), hidden, len(labels))
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)

    best_val, best_state, last_loss = -1.0, None, None
    for epoch in range(epochs):
        if cancel_check is not None:
            cancel_check()
        model.train()
        opt.zero_grad()
        out = model(x, edge_index)
        loss = F.cross_entropy(out[tr], y[tr])
        loss.backward()
        opt.step()
        last_loss = float(loss.item())
        if bool(va.any()):
            model.eval()
            with torch.no_grad():
                vpred = model(x, edge_index).argmax(dim=1)
                vacc = float((vpred[va] == y[va]).float().mean())
            if vacc >= best_val:  # keep the best-generalizing checkpoint
                best_val = vacc
                best_state = {k: v.clone() for k, v in model.state_dict().items()}
        if verbose and epoch % 50 == 0:
            print(f"  epoch {epoch:4d}  loss {last_loss:.4f}"
                  + (f"  val_acc {best_val:.3f}" if best_val >= 0 else ""), flush=True)

    if best_state is not None:
        model.load_state_dict(best_state)

    model.eval()
    with torch.no_grad():
        logits = model(x, edge_index)
        prob = F.softmax(logits, dim=1)
        conf, pred = prob.max(dim=1)
        train_acc = float((pred[tr] == y[tr]).float().mean()) if bool(tr.any()) else None

    predictions = {}
    for i, ip in enumerate(nodes):
        predictions[ip] = {
            "provider": labels[int(pred[i])],
            "confidence": round(float(conf[i]), 4),
            "labeled": bool(train_mask[i]),
        }
    return {
        "predictions": predictions,
        "labels": labels,
        "n_labeled": n_labeled,
        "n_val": int(va.sum()),
        "final_loss": round(last_loss, 4) if last_loss is not None else None,
        "train_acc": round(train_acc, 4) if train_acc is not None else None,
        "val_acc": round(best_val, 4) if best_val >= 0 else None,
        "method": "graphsage-classifier",
        # Non-serializable handles for save_model (stripped before JSON persist).
        "_model": model,
        "_mean": mean,
        "_std": std,
        "in_dim": x.size(1),
        "hidden": hidden,
    }


def save_model(result, path=None):
    """Persist a trained classifier (weights + label map + feature norm) to disk."""
    import torch

    model = result.get("_model")
    if model is None:
        raise RuntimeError("result has no trained model to save")
    path = path or config.GNN_MODEL
    config.ensure_output_dir()
    torch.save({
        "state_dict": model.state_dict(),
        "labels": result["labels"],
        "in_dim": result["in_dim"],
        "hidden": result["hidden"],
        "mean": result["_mean"],
        "std": result["_std"],
    }, path)
    return path


def load_and_predict(arrays, path=None):
    """Load a saved classifier and predict providers for ``arrays``' nodes."""
    import torch
    import torch.nn.functional as F

    path = path or config.GNN_MODEL
    ckpt = torch.load(path, map_location="cpu", weights_only=False)
    model = _build_model(ckpt["in_dim"], ckpt["hidden"], len(ckpt["labels"]))
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    x = (torch.tensor(arrays["x"], dtype=torch.float) - ckpt["mean"]) / ckpt["std"]
    ei = torch.tensor(arrays["edge_index"], dtype=torch.long)
    if ei.numel() == 0:
        ei = torch.empty((2, 0), dtype=torch.long)
    with torch.no_grad():
        prob = F.softmax(model(x, ei), dim=1)
        conf, pred = prob.max(dim=1)
    return {
        arrays["nodes"][i]: {"provider": ckpt["labels"][int(pred[i])],
                             "confidence": round(float(conf[i]), 4)}
        for i in range(len(arrays["nodes"]))
    }


def train_embeddings(arrays, hidden=32, dim=16, epochs=150, lr=0.01):
    """Unsupervised GraphSAGE embeddings via a neighbor-contrastive loss.

    Returns ``{ip: [float, ...]}`` embeddings, for KMeans/HDBSCAN campaign
    discovery when labels are scarce. Empty (with a reason) if torch is absent.
    """
    if not torch_available():
        return {"embeddings": {}, "reason": "torch / torch_geometric not installed"}
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.nn import SAGEConv

    torch.manual_seed(42)
    x, edge_index, _, _, _, _ = _to_tensors(arrays)
    nodes = arrays["nodes"]
    if edge_index.size(1) == 0:
        return {"embeddings": {}, "reason": "graph has no edges"}

    class Encoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.c1 = SAGEConv(x.size(1), hidden)
            self.c2 = SAGEConv(hidden, dim)

        def forward(self, x, ei):
            h = F.relu(self.c1(x, ei))
            return self.c2(h, ei)

    model = Encoder()
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    n = x.size(0)
    src, dst = edge_index[0], edge_index[1]

    model.train()
    for _ in range(epochs):
        opt.zero_grad()
        z = model(x, edge_index)
        z = F.normalize(z, dim=1)
        # Positive: connected pairs close; Negative: random pairs apart.
        pos = (z[src] * z[dst]).sum(dim=1)
        neg_idx = torch.randint(0, n, (src.size(0),))
        neg = (z[src] * z[neg_idx]).sum(dim=1)
        loss = -(F.logsigmoid(pos).mean() + F.logsigmoid(-neg).mean())
        loss.backward()
        opt.step()

    model.eval()
    with torch.no_grad():
        z = F.normalize(model(x, edge_index), dim=1)
    return {
        "embeddings": {ip: [round(float(v), 5) for v in z[i]] for i, ip in enumerate(nodes)},
        "method": "graphsage-contrastive",
    }


def save_predictions(result, path=None):
    path = path or config.GNN_PREDS
    config.ensure_output_dir()
    # Drop the non-serializable model/tensor handles (prefixed with "_").
    serializable = {k: v for k, v in result.items() if not k.startswith("_")}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(serializable, handle, indent=2, default=str)
    return path


def load_predictions(path=None):
    path = path or config.GNN_PREDS
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle).get("predictions", {})
    except (OSError, json.JSONDecodeError):
        return {}
