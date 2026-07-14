"""v2a — two-player co-evolution via PSRO (Policy-Space Response Oracles).

Each round:
  1. **Best-response attacker** — train a PPO-Lagrangian crawler against the current
     defender meta-strategy (an *ensemble* of the learned-detector population folded
     into the production rule detector as defense-in-depth).
  2. **Best-response defender** — retrain the robust MLP detector on the pooled
     hard-negatives of the *attacker population* vs. honest traffic.

The convergence metric is **exploitability**: how much a fresh best-response attacker
can still evade the current defender. As the defender covers each discovered evasion,
exploitability trends toward 0 — i.e. the honeypot forces stealth crawling to become
uneconomical (the attacker is pushed to low-volume/human-like behavior that sacrifices
harvest). We also emit the empirical payoff matrix (attacker_i vs defender_j).

The final, hardened robust detector is saved to ``robust_detector.pt`` (the shipped
``/logs`` second opinion), and the emergent-strategy transitions are logged.

Lean + dependency-light: a custom PSRO driver (no RLlib) with a fictitious-play
meta-solver over the empirical payoff matrix.
"""

import time

import numpy as np

from . import evaluate, personas as personas_mod, ppo, reporting, robust_detector, store
from .config import SelfPlayConfig
from .defender import FrozenDetector
from .env import HoneypotCrawlEnv
from .traffic_model import TrafficModel


def _ensemble_scorer(scorers):
    """Combine several robust detectors into one ``endpoints -> {ip: max prob}``
    (defense-in-depth over the defender population). ``None`` entries (rule-only) are
    skipped. Returns ``None`` when the population has no learned detector yet."""
    live = [s for s in scorers if s is not None]
    if not live:
        return None

    def scorer(endpoints):
        out = {}
        for s in live:
            for ip, p in s(endpoints).items():
                if p > out.get(ip, 0.0):
                    out[ip] = p
        return out

    return scorer


def _make_env(cfg, personas, scorer, seed_off=0):
    tm = TrafficModel(personas, cfg=cfg, seed=cfg.seed + 1 + seed_off)
    det = FrozenDetector(cfg=cfg, use_frozen_gnn=cfg.use_frozen_gnn, robust_scorer=scorer)
    return HoneypotCrawlEnv(tm, det, cfg, seed=cfg.seed + seed_off)


def _fictitious_play(payoff, iters=2000):
    """Return (row_strategy, col_strategy) approximating a Nash of the zero-sum-ish
    game where the attacker (rows) maximizes evasion and the defender (cols)
    minimizes it. Simple fictitious play over the empirical payoff matrix."""
    P = np.asarray(payoff, dtype=np.float64)
    m, n = P.shape
    row_cnt = np.ones(m)
    col_cnt = np.ones(n)
    for _ in range(iters):
        # attacker best-responds to defender's average strategy
        col_mix = col_cnt / col_cnt.sum()
        r = int(np.argmax(P @ col_mix))
        row_cnt[r] += 1
        # defender best-responds to attacker's average strategy
        row_mix = row_cnt / row_cnt.sum()
        c = int(np.argmin(row_mix @ P))
        col_cnt[c] += 1
    return row_cnt / row_cnt.sum(), col_cnt / col_cnt.sum()


def run_psro(cfg=None, verbose=False, save=True):
    from crawler_graph.ml import gnn
    if not gnn.torch_available():
        raise RuntimeError("torch required for co-evolution (run in the app/trainer image).")

    cfg = cfg or SelfPlayConfig()
    t0 = time.time()
    personas, _ = personas_mod.fit_personas({})   # offline / default background
    br_cfg = SelfPlayConfig.from_overrides(**{**cfg.to_dict(), "iterations": cfg.psro_br_iterations})

    attacker_pop = []       # list of policies
    defender_scorers = [None]   # index 0 = rule-only baseline defender
    defender_results = [None]
    exploitability = []
    rounds = []
    best_robust = None

    for rd in range(cfg.psro_iterations):
        cur_def = _ensemble_scorer(defender_scorers)

        # 1) best-response attacker vs the current defender ------------------
        env_a = _make_env(cfg, personas, cur_def, seed_off=rd)
        policy, hist = ppo.train_attacker(env_a, br_cfg)
        attacker_pop.append(policy)
        exploit = evaluate.evaluate_policy(env_a, policy, cfg.eval_episodes, greedy=True)
        exploitability.append(round(exploit["evasion_rate"], 3))

        # 2) best-response defender vs the attacker population ---------------
        Xs, ys = [], []
        for pol in attacker_pop:                 # pool hard-negatives across attackers
            env_d = _make_env(cfg, personas, cur_def, seed_off=100 + rd)
            X, y, _ = robust_detector.gather_dataset(env_d, pol, n_attacker_eps=20, n_bg_batches=3)
            Xs.append(X); ys.append(y)
        X = np.vstack(Xs); y = np.concatenate(ys)
        res = robust_detector.train(X, y, seed=cfg.seed)
        if res.get("trained"):
            defender_scorers.append(robust_detector.make_scorer(res))
            defender_results.append(res)
            best_robust = res

        rec = {"round": rd, "exploitability": exploitability[-1],
               "attacker_stack_usage": exploit["stack_usage"],
               "attacker_mean_D": exploit["mean_D"], "attacker_harvest": exploit["mean_harvest"],
               "robust_val_auc": res.get("val_auc")}
        rounds.append(rec)
        reporting.append_strategy({"phase": "coevolve", **rec})
        if verbose:
            print(f"[psro] round {rd}: exploitability={exploitability[-1]:.3f} "
                  f"attacker_D={exploit['mean_D']:.3f} robust_auc={res.get('val_auc')}", flush=True)

    # --- empirical payoff matrix (attacker_i vs defender_j) ------------------
    payoff = []
    for i, pol in enumerate(attacker_pop):
        row = []
        for j, sc in enumerate(defender_scorers):
            env_ij = _make_env(cfg, personas, _ensemble_scorer([sc]) if sc else None, seed_off=200 + i)
            m = evaluate.evaluate_policy(env_ij, pol, max(12, cfg.eval_episodes // 2), greedy=True)
            row.append(round(m["evasion_rate"], 3))
        payoff.append(row)
    atk_meta, def_meta = _fictitious_play(payoff) if payoff and payoff[0] else ([], [])

    if save and best_robust is not None:
        robust_detector.save(best_robust)

    report = {
        "kind": "coevolve",
        "config": cfg.to_dict(),
        "exploitability": exploitability,
        "rounds": rounds,
        "payoff_matrix": payoff,
        "attacker_meta_strategy": [round(float(x), 3) for x in atk_meta],
        "defender_meta_strategy": [round(float(x), 3) for x in def_meta],
        "robust_val_auc": best_robust.get("val_auc") if best_robust else None,
        "n_attackers": len(attacker_pop),
        "n_defenders": len(defender_scorers),
        "duration_s": round(time.time() - t0, 1),
        "summary": {
            "final_exploitability": exploitability[-1] if exploitability else None,
            "exploitability_drop": round(exploitability[0] - exploitability[-1], 3)
            if len(exploitability) >= 2 else None,
            "robust_val_auc": best_robust.get("val_auc") if best_robust else None,
        },
    }
    if save:
        report["run_id"] = store.save_run(report)
    return report
