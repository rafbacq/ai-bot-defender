"""PPO-Lagrangian training loop (PyTorch).

Solves the constrained MDP ``max E[Σ r]  s.t.  risk(D_terminal) ≤ δ`` with a learned
dual variable ``λ`` (dual ascent). Two GAE advantage streams — reward (``A_r``) and
cost (``A_c``) — are combined into ``A = A_r − λ·A_c`` for the clipped policy
objective; two value heads are regressed to their respective returns. The recurrent
policy is evaluated per-episode-sequence so the GRU belief state is consistent
between collection and update.

torch is imported lazily inside the functions (package stays importable without it).
"""

import numpy as np

from .env import OBS_DIM, ACTION_DIMS
from .policy import build_policy


def _collect(env, policy, n_episodes):
    import torch
    episodes = []
    for _ in range(n_episodes):
        obs, _ = env.reset()
        h = policy.initial_state(1)
        ep = {"obs": [], "actions": [], "logp": [], "rewards": [], "costs": [],
              "vr": [], "vc": [], "info": None}
        done = False
        while not done:
            ot = torch.as_tensor(obs, dtype=torch.float32).unsqueeze(0)
            action, logp, vr, vc, h = policy.act(ot, h)
            nobs, r, done, _, info = env.step(action)
            ep["obs"].append(obs)
            ep["actions"].append(action)
            ep["logp"].append(logp)
            ep["rewards"].append(float(r))
            ep["costs"].append(float(info.get("cost", 0.0)))
            ep["vr"].append(vr)
            ep["vc"].append(vc)
            obs = nobs
            if done:
                ep["info"] = info
        episodes.append(ep)
    return episodes


def _gae(values, rewards, gamma, lam):
    """Generalized advantage estimation for one episodic stream (bootstrap 0)."""
    T = len(rewards)
    adv = np.zeros(T, dtype=np.float64)
    last = 0.0
    for t in reversed(range(T)):
        next_v = values[t + 1] if t + 1 < T else 0.0
        delta = rewards[t] + gamma * next_v - values[t]
        last = delta + gamma * lam * last
        adv[t] = last
    ret = adv + np.asarray(values, dtype=np.float64)
    return adv, ret


def _prepare(episodes, cfg):
    for ep in episodes:
        a_r, ret_r = _gae(ep["vr"], ep["rewards"], cfg.gamma, cfg.gae_lambda)
        a_c, ret_c = _gae(ep["vc"], ep["costs"], cfg.gamma, cfg.gae_lambda)
        ep["adv_r"], ep["ret_r"] = a_r, ret_r
        ep["adv_c"], ep["ret_c"] = a_c, ret_c
    # normalize each advantage stream across the whole batch
    all_r = np.concatenate([ep["adv_r"] for ep in episodes])
    all_c = np.concatenate([ep["adv_c"] for ep in episodes])
    mr, sr = all_r.mean(), all_r.std() + 1e-8
    mc, sc = all_c.mean(), all_c.std() + 1e-8
    for ep in episodes:
        ep["adv_r_n"] = (ep["adv_r"] - mr) / sr
        ep["adv_c_n"] = (ep["adv_c"] - mc) / sc
    return episodes


def _update(policy, opt, episodes, cfg, lam, entropy_coef=None):
    import torch
    import torch.nn.functional as F
    if entropy_coef is None:
        entropy_coef = cfg.entropy_coef
    stats = {"pg": 0.0, "vf": 0.0, "ent": 0.0, "kl": 0.0, "n": 0}
    for _ in range(cfg.ppo_epochs):
        for ep in episodes:
            obs_seq = torch.as_tensor(np.array(ep["obs"]), dtype=torch.float32)
            act_seq = torch.as_tensor(np.array(ep["actions"]), dtype=torch.long)
            old_logp = torch.as_tensor(np.array(ep["logp"]), dtype=torch.float32)
            adv = torch.as_tensor(ep["adv_r_n"] - lam * ep["adv_c_n"], dtype=torch.float32)
            ret_r = torch.as_tensor(ep["ret_r"], dtype=torch.float32)
            ret_c = torch.as_tensor(ep["ret_c"], dtype=torch.float32)

            logp, ent, vr, vc = policy.evaluate_sequence(obs_seq, act_seq)
            ratio = torch.exp(logp - old_logp)
            unclipped = ratio * adv
            clipped = torch.clamp(ratio, 1 - cfg.clip_eps, 1 + cfg.clip_eps) * adv
            pg = -torch.min(unclipped, clipped).mean()
            vf = F.mse_loss(vr, ret_r) + F.mse_loss(vc, ret_c)
            ent_mean = ent.mean()
            loss = pg + cfg.value_coef * vf - entropy_coef * ent_mean

            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(policy.parameters(), cfg.max_grad_norm)
            opt.step()

            with torch.no_grad():
                stats["pg"] += float(pg)
                stats["vf"] += float(vf)
                stats["ent"] += float(ent_mean)
                stats["kl"] += float((old_logp - logp).mean())
                stats["n"] += 1
    n = max(1, stats["n"])
    return {k: (v / n if k != "n" else v) for k, v in stats.items()}


def train_attacker(env, cfg, on_iter=None):
    """Run PPO-Lagrangian; return ``(policy, history)``. ``env`` must be reset-able."""
    import torch
    torch.manual_seed(cfg.seed)
    np.random.seed(cfg.seed)
    policy = build_policy(OBS_DIM, ACTION_DIMS, cfg.hidden)
    opt = torch.optim.Adam(policy.parameters(), lr=cfg.lr)
    lam = float(cfg.lagrange_init)
    history = []

    for it in range(cfg.iterations):
        episodes = _collect(env, policy, cfg.episodes_per_iter)
        _prepare(episodes, cfg)
        # Anneal exploration: high entropy early (find the evading rung), sharpen
        # late (commit to it) — linear decay to 10% of the coefficient.
        frac = it / max(1, cfg.iterations - 1)
        ent_coef = cfg.entropy_coef * (1.0 - 0.9 * frac)
        upd = _update(policy, opt, episodes, cfg, lam, entropy_coef=ent_coef)

        terminal_D = [ep["info"]["detector"]["D"] for ep in episodes]
        episodic_cost = [float(np.sum(ep["costs"])) for ep in episodes]
        harvests = [ep["info"].get("cum_harvest", 0.0) for ep in episodes]
        evaded = [1.0 if ep["info"].get("evaded") else 0.0 for ep in episodes]
        # dual ascent: constrain the mean episodic cost (dense + terminal D) to the budget
        constraint = env.reward_fn.constraint_value(episodic_cost)
        lam = float(np.clip(lam + cfg.lagrange_lr * (constraint - cfg.cost_budget),
                            0.0, cfg.lagrange_max))

        rec = {
            "iter": it,
            "mean_D": float(np.mean(terminal_D)),
            "constraint": float(constraint),
            "mean_episodic_cost": float(np.mean(episodic_cost)),
            "mean_harvest": float(np.mean(harvests)),
            "evasion_rate": float(np.mean(evaded)),
            "lambda": lam,
            "entropy": upd["ent"],
            "kl": upd["kl"],
            "pg": upd["pg"],
            "vf": upd["vf"],
        }
        history.append(rec)
        if on_iter:
            on_iter(rec)
    return policy, history
