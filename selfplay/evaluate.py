"""Evaluation: evasion metrics, baselines, the cost-to-evade curve, and the
per-action-factor ablation (which lever the attacker learned to exploit).

``rollout_*`` run whole episodes and read the terminal detector verdict. Nothing
here trains; a trained policy is optional (fixed-strategy baselines need no torch).
"""

import numpy as np

from . import actions as A
from .env import ACTION_DIMS


# ------------------------------------------------------------ rollouts
def rollout_policy(env, policy, n_episodes, greedy=True):
    """Roll a trained recurrent policy; return per-episode terminal infos + the
    histogram of stack rungs it chose."""
    import torch
    infos, stack_hist = [], np.zeros(len(A.STACK_PRESETS))
    for _ in range(n_episodes):
        obs, _ = env.reset()
        h = policy.initial_state(1)
        done = False
        while not done:
            ot = torch.as_tensor(obs, dtype=torch.float32).unsqueeze(0)
            action, _, _, _, h = policy.act(ot, h, greedy=greedy)
            stack_hist[action[3] % len(A.STACK_PRESETS)] += 1
            obs, _, done, _, info = env.step(action)
        infos.append(info)
    return infos, stack_hist


def rollout_fixed(env, action, n_episodes):
    infos = []
    for _ in range(n_episodes):
        env.reset()
        done = False
        while not done:
            _, _, done, _, info = env.step(action)
        infos.append(info)
    return infos


def rollout_random(env, n_episodes, seed=0):
    rng = np.random.default_rng(seed)
    infos = []
    for _ in range(n_episodes):
        env.reset()
        done = False
        while not done:
            a = [int(rng.integers(d)) for d in ACTION_DIMS]
            _, _, done, _, info = env.step(a)
        infos.append(info)
    return infos


# ------------------------------------------------------------ metrics
def _agg(infos):
    Ds = [i["detector"]["D"] for i in infos]
    ev = [1.0 if i.get("evaded") else 0.0 for i in infos]
    hv = [i.get("cum_harvest", 0.0) for i in infos]
    return {
        "n": len(infos),
        "evasion_rate": float(np.mean(ev)) if ev else 0.0,
        "mean_D": float(np.mean(Ds)) if Ds else 0.0,
        "mean_harvest": float(np.mean(hv)) if hv else 0.0,
    }


def evaluate_policy(env, policy, n_episodes, greedy=True):
    infos, stack_hist = rollout_policy(env, policy, n_episodes, greedy=greedy)
    out = _agg(infos)
    total = stack_hist.sum() or 1.0
    out["stack_usage"] = {A.STACK_PRESETS[i].name: round(float(stack_hist[i] / total), 3)
                          for i in range(len(A.STACK_PRESETS))}
    return out


# ------------------------------------------------------------ cost-to-evade curve
def cost_to_evade_curve(env, n_episodes=24):
    """For each stack rung (cheapest→priciest), evaluate a fixed strategy that uses
    it (with sensible other factors) and report evasion/harvest/D vs infra cost — the
    headline measurement: how much infrastructure the attacker must buy to evade."""
    rows = []
    for idx, preset in enumerate(A.STACK_PRESETS):
        # rotate_both + slow/regular + high_value gives each rung its best evasion shot
        action = (3, 6, 0, idx)
        m = _agg(rollout_fixed(env, action, n_episodes))
        rows.append({
            "rung": preset.rung, "stack": preset.name, "infra_cost": preset.infra_cost,
            "evasion_rate": round(m["evasion_rate"], 3), "mean_D": round(m["mean_D"], 3),
            "mean_harvest": round(m["mean_harvest"], 2),
        })
    return sorted(rows, key=lambda r: r["infra_cost"])


# ------------------------------------------------------------ ablation
def factor_ablation(env, policy, n_episodes=24):
    """Lock each action factor to the policy's modal choice vs. forcing the *cheapest*
    alternative, and measure the drop in evasion — quantifying each lever's value."""
    import torch
    # discover the policy's modal action factors under greedy rollout
    infos, _ = rollout_policy(env, policy, n_episodes, greedy=True)
    base = _agg(infos)
    # modal factor values from a greedy pass
    modal = _modal_action(env, policy, n_episodes)
    names = ["identity", "timing", "fetch", "stack"]
    cheap = [0, 0, 0, 0]  # cheapest/most-naive per factor (keep, fast/regular, high, declared)
    out = {"policy_evasion": round(base["evasion_rate"], 3), "factors": {}}
    for f in range(4):
        forced = list(modal)
        forced[f] = cheap[f]
        m = _agg(rollout_fixed(env, tuple(forced), n_episodes))
        out["factors"][names[f]] = {
            "modal_value": int(modal[f]),
            "evasion_if_downgraded": round(m["evasion_rate"], 3),
            "evasion_drop": round(base["evasion_rate"] - m["evasion_rate"], 3),
        }
    return out


def _modal_action(env, policy, n_episodes):
    import torch
    from collections import Counter
    counts = [Counter() for _ in ACTION_DIMS]
    for _ in range(n_episodes):
        obs, _ = env.reset()
        h = policy.initial_state(1)
        done = False
        while not done:
            ot = torch.as_tensor(obs, dtype=torch.float32).unsqueeze(0)
            action, _, _, _, h = policy.act(ot, h, greedy=True)
            for f, a in enumerate(action):
                counts[f][a] += 1
            obs, _, done, _, info = env.step(action)
    return [c.most_common(1)[0][0] if c else 0 for c in counts]
