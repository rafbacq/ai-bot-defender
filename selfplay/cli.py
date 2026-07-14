"""Command-line entry: ``python -m selfplay {calibrate,train,evaluate,coevolve,selftest}``.

Mirrors ``crawler_graph``'s CLI style. Heavy work is delegated to the submodules so
this file stays a thin dispatcher.
"""

import argparse
import json

from .config import SelfPlayConfig


def _cfg_from_args(args):
    overrides = {k: v for k, v in vars(args).items()
                 if k in SelfPlayConfig().to_dict() and v is not None}
    return SelfPlayConfig.from_overrides(**overrides)


def cmd_calibrate(args):
    from . import calibration
    from .train import build_env, _load_real_endpoints
    cfg = _cfg_from_args(args)
    real = _load_real_endpoints(cfg)
    env, personas, n_real = build_env(cfg, real)
    sim_eps = calibration.build_endpoints(env.tm.sample_background(240, seed=cfg.seed + 7))
    real_eps = real if len(real) >= 20 else calibration.build_endpoints(
        env.tm.sample_background(240, seed=cfg.seed + 99))
    rep = calibration.indistinguishability_report(real_eps, sim_eps)
    rep["n_real_endpoints"] = len(real)
    print(f"CALIBRATION  passed={rep['passed']}  adversarial_auc={rep['adversarial_auc']}  "
          f"ks={rep['ks_features_passed']}/{rep['ks_features_total']}  n_real={len(real)}")
    if args.verbose:
        print(json.dumps(rep["ks"], indent=2))
    return 0 if rep["passed"] else 1


def cmd_train(args):
    from .train import train_phase1
    cfg = _cfg_from_args(args)
    rep = train_phase1(cfg, calibrate=not args.no_calibrate,
                       on_iter=lambda r: print(
                           f"  it{r['iter']:3d} D={r['mean_D']:.3f} evade={r['evasion_rate']:.2f} "
                           f"harvest={r['mean_harvest']:.1f} lam={r['lambda']:.2f}", flush=True)
                       if args.verbose else None)
    s = rep["summary"]
    print(f"\nTRAIN DONE ({s['duration_s']}s)")
    print(f"  evasion: baseline={s['baseline_evasion_rate']:.2f} -> learned={s['final_evasion_rate']:.2f} "
          f"(lift {s['evasion_lift']:+.2f})")
    print(f"  mean detector D: baseline={s['baseline_mean_D']:.3f} -> learned={s['final_mean_D']:.3f}")
    print(f"  robust detector val_auc={s['robust_val_auc']}")
    print(f"  cost-to-evade:")
    for r in rep["cost_to_evade"]:
        print(f"    {r['stack']:16s} infra={r['infra_cost']:.2f} evasion={r['evasion_rate']:.2f} D={r['mean_D']:.3f}")
    return 0


def cmd_evaluate(args):
    from . import evaluate, config
    from .policy import build_policy
    from .train import build_env, _load_real_endpoints
    from .env import OBS_DIM, ACTION_DIMS
    import torch
    cfg = _cfg_from_args(args)
    if not config.POLICY_CKPT.exists():
        print("No saved policy — run `train` first."); return 1
    env, _, _ = build_env(cfg, _load_real_endpoints(cfg))
    ckpt = torch.load(config.POLICY_CKPT, map_location="cpu", weights_only=False)
    policy = build_policy(ckpt["obs_dim"], ckpt["act_dims"], ckpt["hidden"])
    policy.load_state_dict(ckpt["state_dict"])
    res = evaluate.evaluate_policy(env, policy, cfg.eval_episodes, greedy=True)
    print(json.dumps(res, indent=2))
    return 0


def cmd_coevolve(args):
    from .coevolve import run_psro
    cfg = _cfg_from_args(args)
    rep = run_psro(cfg, verbose=args.verbose)
    print(f"\nPSRO DONE: exploitability {rep['exploitability'][0]:.3f} -> {rep['exploitability'][-1]:.3f}")
    print(f"  robust detector val_auc={rep.get('robust_val_auc')}")
    return 0


def cmd_ingest(args):
    from . import ingestion
    rep = ingestion.run_ingestion_experiment(n_rounds=args.rounds or 60)
    print(f"INGESTION ({rep['membership_backend']})  best={rep['best_arm']['name']} "
          f"flavor={rep['best_arm']['flavor']} membership_p={rep['final_membership']['p_value']}")
    print("  " + rep["recommendation"])
    return 0


def cmd_selftest(args):
    from .tests import test_selfplay
    return test_selfplay.run(full=not args.fast)


def main(argv=None):
    p = argparse.ArgumentParser(prog="selfplay", description="Co-evolving crawler ⇄ honeypot self-play (RL).")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--iterations", type=int)
        sp.add_argument("--episodes-per-iter", dest="episodes_per_iter", type=int)
        sp.add_argument("--horizon-T", dest="horizon_T", type=int)
        sp.add_argument("--cost-budget", dest="cost_budget", type=float)
        sp.add_argument("--seed", type=int)
        sp.add_argument("--risk-mode", dest="risk_mode", choices=["expectation", "cvar"])
        sp.add_argument("--no-gnn", dest="use_frozen_gnn", action="store_const", const=0)
        sp.add_argument("-v", "--verbose", action="store_true")

    c = sub.add_parser("calibrate"); add_common(c); c.set_defaults(func=cmd_calibrate)
    t = sub.add_parser("train"); add_common(t)
    t.add_argument("--no-calibrate", action="store_true"); t.set_defaults(func=cmd_train)
    e = sub.add_parser("evaluate"); add_common(e); e.set_defaults(func=cmd_evaluate)
    co = sub.add_parser("coevolve"); add_common(co)
    co.add_argument("--psro-iterations", dest="psro_iterations", type=int)
    co.add_argument("--psro-br-iterations", dest="psro_br_iterations", type=int); co.set_defaults(func=cmd_coevolve)
    ing = sub.add_parser("ingest")
    ing.add_argument("--rounds", type=int); ing.add_argument("-v", "--verbose", action="store_true")
    ing.set_defaults(func=cmd_ingest)
    st = sub.add_parser("selftest")
    st.add_argument("--fast", action="store_true", help="skip the long training assertions")
    st.add_argument("-v", "--verbose", action="store_true"); st.set_defaults(func=cmd_selftest)

    args = p.parse_args(argv)
    return args.func(args)
