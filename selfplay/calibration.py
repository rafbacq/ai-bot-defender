"""Phase-0 calibration: is the simulator statistically indistinguishable from the
real ``all_visits`` traffic, measured on the *exact* feature vector the detector
consumes (``crawler_graph.ml.features.node_vector``)?

Two gates, both implemented in pure numpy (no scipy/sklearn — kept dependency-light
like ``crawler_graph``):

1. **Per-feature 2-sample Kolmogorov–Smirnov test** over each of the 22
   ``FEATURE_NAMES`` — fraction of features whose distribution is *not* rejected
   (p > 0.05).
2. **Adversarial validation** — a logistic-regression classifier trained to tell
   real vs. simulated feature vectors apart. A held-out AUC near 0.5 means the two
   are indistinguishable; we require AUC < 0.60.

Both pass ⇒ ``passed=True`` gates Phase-1 training. When the real corpus is thin
the report records ``n_real`` so the fidelity claim stays honest.
"""

import numpy as np


# ------------------------------------------------------------------ endpoints
def build_endpoints(bundle):
    """Run the real enrich + consistency chain on a simulator bundle -> endpoints."""
    from crawler_graph.analysis import consistency
    from crawler_graph.ingest import enrich
    v, h, b, t = bundle.as_tuple()
    v = list(v)
    enrich.join_fingerprints(v, h)
    enrich.join_tcp_fingerprints(v, t)
    enrich.enrich_visits(v, resolve_asn=False)
    eps = enrich.aggregate_endpoints(v)
    enrich.attach_browser_fingerprints(eps, b)
    consistency.annotate(eps)
    return eps


def endpoints_to_matrix(endpoints):
    from crawler_graph.ml import features
    rows = [features.node_vector(rec) for rec in endpoints.values()]
    return np.asarray(rows, dtype=np.float64), features.FEATURE_NAMES


# ------------------------------------------------------------------ KS test
def _probks(lam):
    """Kolmogorov survival function Q_KS(lam) — Numerical Recipes ``probks``.

    Uses the convergence-based early exit (and 1.0 fallback for small lam) so it is
    numerically stable where the naive fixed-term alternating series oscillates —
    in particular Q_KS(0) = 1 (identical distributions ⇒ p = 1), not 0.
    """
    if lam <= 0:
        return 1.0
    a2 = -2.0 * lam * lam
    fac, total, termbf = 2.0, 0.0, 0.0
    for j in range(1, 101):
        term = fac * np.exp(a2 * j * j)
        total += term
        if abs(term) <= 1e-3 * termbf or abs(term) <= 1e-8 * total:
            return float(min(1.0, max(0.0, total)))
        fac = -fac
        termbf = abs(term)
    return 1.0


def _ks_2samp(x, y):
    x = np.sort(np.asarray(x, dtype=np.float64))
    y = np.sort(np.asarray(y, dtype=np.float64))
    n1, n2 = len(x), len(y)
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0
    allv = np.concatenate([x, y])
    cdf1 = np.searchsorted(x, allv, side="right") / n1
    cdf2 = np.searchsorted(y, allv, side="right") / n2
    d = float(np.max(np.abs(cdf1 - cdf2)))
    if d == 0.0:
        return 0.0, 1.0
    en = np.sqrt(n1 * n2 / (n1 + n2))
    return d, _probks((en + 0.12 + 0.11 / en) * d)


# ------------------------------------------------------------------ adversarial AUC
def _auc(scores, labels):
    """AUC via the Mann–Whitney U rank statistic."""
    scores = np.asarray(scores, dtype=np.float64)
    labels = np.asarray(labels)
    pos = scores[labels == 1]
    neg = scores[labels == 0]
    if len(pos) == 0 or len(neg) == 0:
        return 0.5
    order = np.argsort(scores)
    ranks = np.empty(len(scores), dtype=np.float64)
    ranks[order] = np.arange(1, len(scores) + 1)
    # average ranks for ties
    _, inv, counts = np.unique(scores, return_inverse=True, return_counts=True)
    sums = np.zeros(len(counts))
    np.add.at(sums, inv, ranks)
    ranks = (sums / counts)[inv]
    r_pos = ranks[labels == 1].sum()
    u = r_pos - len(pos) * (len(pos) + 1) / 2.0
    return float(u / (len(pos) * len(neg)))


def _logreg_val_auc(X, y, seed=0, epochs=300, lr=0.1):
    rng = np.random.default_rng(seed)
    n = len(y)
    idx = rng.permutation(n)
    cut = max(1, int(0.7 * n))
    tr, va = idx[:cut], idx[cut:]
    if len(va) == 0:
        va = tr
    mu, sd = X[tr].mean(0), X[tr].std(0)
    sd = np.where(sd < 1e-8, 1.0, sd)
    Xs = (X - mu) / sd
    w = np.zeros(Xs.shape[1])
    b = 0.0
    for _ in range(epochs):
        z = Xs[tr] @ w + b
        p = 1.0 / (1.0 + np.exp(-z))
        g = p - y[tr]
        w -= lr * (Xs[tr].T @ g / len(tr) + 1e-3 * w)
        b -= lr * float(g.mean())
    val_scores = 1.0 / (1.0 + np.exp(-(Xs[va] @ w + b)))
    return _auc(val_scores, y[va])


# ------------------------------------------------------------------ report
def indistinguishability_report(real_eps, sim_eps, ks_alpha=0.05, auc_max=0.60,
                                min_pass_frac=0.80, seed=0):
    Xr, names = endpoints_to_matrix(real_eps)
    Xs, _ = endpoints_to_matrix(sim_eps)
    if len(Xr) == 0 or len(Xs) == 0:
        return {"passed": False, "reason": "empty real or sim feature matrix",
                "n_real": len(Xr), "n_sim": len(Xs)}

    ks = {}
    n_pass = 0
    for j, name in enumerate(names):
        d, p = _ks_2samp(Xr[:, j], Xs[:, j])
        ks[name] = {"D": round(d, 4), "p": round(p, 4)}
        if p > ks_alpha:
            n_pass += 1
    ks_pass_frac = n_pass / len(names)

    X = np.vstack([Xr, Xs])
    y = np.concatenate([np.ones(len(Xr)), np.zeros(len(Xs))]).astype(np.float64)
    # Adversarial validation: mean held-out AUC across several shuffles. For truly
    # indistinguishable data this sits at ~0.5 (do NOT fold with max(a,1-a): that
    # rectifies estimation noise upward and would fail identical distributions).
    aucs = [_logreg_val_auc(X, y, seed=seed + k) for k in range(5)]
    adv_auc = float(np.mean(aucs))

    passed = (ks_pass_frac >= min_pass_frac) and (adv_auc < auc_max)
    return {
        "passed": bool(passed),
        "n_real": int(len(Xr)),
        "n_sim": int(len(Xs)),
        "ks_features_passed": int(n_pass),
        "ks_features_total": int(len(names)),
        "ks_pass_frac": round(ks_pass_frac, 3),
        "adversarial_auc": round(adv_auc, 3),
        "auc_max": auc_max,
        "min_pass_frac": min_pass_frac,
        "ks": ks,
    }
