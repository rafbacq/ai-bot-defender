"""Phase-1 orchestrator: calibrate → baseline → PPO-Lagrangian → robust detector →
artifacts. Produces the headline result (evasion vs. a fixed baseline, the
cost-to-evade curve, the per-factor ablation) and the shippable robust detector.

Run: ``python -m selfplay train`` (in the app/trainer image — needs torch).
"""

import time

import numpy as np

from . import calibration, config, evaluate, personas as personas_mod
from . import reporting, robust_detector, store
from .config import SelfPlayConfig
from .defender import FrozenDetector
from .env import HoneypotCrawlEnv, OBS_DIM, ACTION_DIMS
from .traffic_model import TrafficModel


def _load_real_endpoints(cfg):
    """Best-effort: pull real logdb traffic → endpoint records (for persona fitting
    + the calibration reference). Returns ``{}`` when logdb is unavailable."""
    try:
        from crawler_graph.analysis import consistency
        from crawler_graph.ingest import db, enrich
        visits = db.fetch_visits(limit=cfg.__dict__.get("real_limit", 20000), since_hours=None)
        if not visits:
            return {}
        try:
            handshakes = db.fetch_handshakes(); tcp = db.fetch_tcp_fingerprints()
            bfp = db.fetch_browser_fingerprints()
        except Exception:
            handshakes = tcp = bfp = []
        enrich.join_fingerprints(visits, handshakes)
        enrich.join_tcp_fingerprints(visits, tcp)
        enrich.enrich_visits(visits, resolve_asn=True)
        eps = enrich.aggregate_endpoints(visits)
        enrich.attach_browser_fingerprints(eps, bfp)
        consistency.annotate(eps)
        return eps
    except Exception:
        return {}


def build_env(cfg, real_endpoints=None):
    personas, n_real = personas_mod.fit_personas(real_endpoints or {})
    tm = TrafficModel(personas, cfg=cfg, seed=cfg.seed + 1)
    det = FrozenDetector(cfg=cfg, use_frozen_gnn=cfg.use_frozen_gnn)
    env = HoneypotCrawlEnv(tm, det, cfg, seed=cfg.seed)
    return env, personas, n_real


def _require_torch():
    from crawler_graph.ml import gnn
    if not gnn.torch_available():
        raise RuntimeError("torch is required for training (run in the app/trainer image).")


def train_phase1(cfg=None, calibrate=True, on_iter=None, save=True):
    _require_torch()
    import torch
    from . import ppo

    cfg = cfg or SelfPlayConfig()
    t0 = time.time()
    real = _load_real_endpoints(cfg)
    env, personas, n_real = build_env(cfg, real)

    # --- Phase 0: calibration -------------------------------------------
    calib = None
    if calibrate:
        sim_eps = calibration.build_endpoints(env.tm.sample_background(240, seed=cfg.seed + 7))
        real_eps = real if len(real) >= 20 else calibration.build_endpoints(
            env.tm.sample_background(240, seed=cfg.seed + 99))
        calib = calibration.indistinguishability_report(real_eps, sim_eps)
        calib["n_real_endpoints"] = int(len(real))
        calib["used_real"] = bool(len(real) >= 20)
        import json
        config.ensure_output_dir()
        with open(config.CALIB_REPORT, "w", encoding="utf-8") as fh:
            json.dump(calib, fh, indent=2)

    # --- baselines (before learning) ------------------------------------
    base_random = evaluate._agg(evaluate.rollout_random(env, cfg.eval_episodes))
    base_naive = evaluate._agg(evaluate.rollout_fixed(env, (0, 0, 0, 1), cfg.eval_episodes))

    # --- train ----------------------------------------------------------
    strat_prev = None

    def _log(rec):
        nonlocal strat_prev
        if on_iter:
            on_iter(rec)
        # emergent-strategy autocurriculum log: record milestones
        note = None
        if rec["iter"] == 0:
            note = "start"
        elif strat_prev is not None and rec["evasion_rate"] - strat_prev >= 0.2:
            note = "evasion jump"
        if note:
            reporting.append_strategy({"iter": rec["iter"], "note": note,
                                       "mean_D": round(rec["mean_D"], 3),
                                       "evasion_rate": round(rec["evasion_rate"], 3),
                                       "lambda": round(rec["lambda"], 2)})
        strat_prev = rec["evasion_rate"]

    policy, history = ppo.train_attacker(env, cfg, on_iter=_log)

    # --- evaluate trained policy ----------------------------------------
    trained = evaluate.evaluate_policy(env, policy, cfg.eval_episodes, greedy=True)
    ablation = evaluate.factor_ablation(env, policy, n_episodes=max(16, cfg.eval_episodes // 2))
    curve = evaluate.cost_to_evade_curve(env, n_episodes=max(16, cfg.eval_episodes // 2))
    reporting.append_strategy({"iter": "final", "note": "converged strategy",
                               "stack_usage": trained["stack_usage"],
                               "evasion_rate": trained["evasion_rate"]})

    # --- robust detector (v1 deliverable) -------------------------------
    robust = {"trained": False}
    try:
        X, y, _ = robust_detector.gather_dataset(env, policy, n_attacker_eps=40, n_bg_batches=6)
        robust = robust_detector.train(X, y, seed=cfg.seed)
        if robust.get("trained") and save:
            robust_detector.save(robust)
    except Exception as exc:
        robust = {"trained": False, "reason": f"{type(exc).__name__}: {exc}"}

    # --- persist policy + artifacts -------------------------------------
    if save:
        torch.save({"state_dict": policy.state_dict(), "obs_dim": OBS_DIM,
                    "act_dims": list(ACTION_DIMS), "hidden": cfg.hidden},
                   config.POLICY_CKPT)

    summary = {
        "final_evasion_rate": trained["evasion_rate"],
        "final_mean_D": trained["mean_D"],
        "final_harvest": trained["mean_harvest"],
        "baseline_evasion_rate": base_naive["evasion_rate"],
        "baseline_random_evasion": base_random["evasion_rate"],
        "baseline_mean_D": base_naive["mean_D"],
        "evasion_lift": round(trained["evasion_rate"] - base_naive["evasion_rate"], 3),
        "robust_val_auc": robust.get("val_auc"),
        "duration_s": round(time.time() - t0, 1),
    }
    report = {
        "kind": "phase1",
        "config": cfg.to_dict(),
        "calibration": calib,
        "history": history,
        "trained": trained,
        "baselines": {"random": base_random, "naive_fixed": base_naive},
        "ablation": ablation,
        "cost_to_evade": curve,
        "robust_detector": {k: v for k, v in robust.items() if not k.startswith("_")},
        "personas": [p.label for p in personas],
        "summary": summary,
    }
    if save:
        reporting.write_eval_report(report)
        reporting.render_curve(history, curve)
        rid = store.save_run(report)
        report["run_id"] = rid
    return report
