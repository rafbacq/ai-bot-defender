"""Reward + cost signals for the constrained MDP.

Two channels (PPO-Lagrangian consumes both):

* **objective reward** ``r_t`` — content harvested minus the *infrastructure* price
  of the chosen stack rung, minus rotation/slowness costs, plus an optional
  exploration bonus. A small negative *dense consistency* shaping term gives the
  policy per-step gradient toward self-consistency before the terminal detector
  verdict arrives (heuristic; kept small).
* **constraint cost** — the episode-terminal detector score ``D_terminal`` in
  ``[0,1]`` from ``defender.FrozenDetector``. The CMDP bounds ``E[D_terminal] ≤ δ``
  (or ``CVaR_α`` in risk-sensitive mode).

Nothing here imports torch; it operates on plain floats produced by the env.
"""

# Normalizer for the per-endpoint cross-layer consistency score (INCONSISTENCY_FLAG
# ~3; scores rarely exceed ~8). Keeps the dense shaping term in a sane range.
_CONS_NORM = 6.0


class CMDPReward:
    def __init__(self, cfg):
        self.cfg = cfg

    def step_reward(self, step_info, dec, prev_dec):
        """Objective reward for one step — pure economics: content harvested minus
        the infrastructure price of the chosen stack rung and rotation/slowness
        costs. Detectability lives entirely in the *cost* channel (see step_cost)."""
        c = self.cfg
        harvest = c.harvest_weight * float(step_info.get("content_value", 0.0))
        infra = step_info.get("infra_cost", 0.0)
        rotated = 1.0 if (dec.get("rotate_ua") or dec.get("rotate_asn")) else 0.0
        slow = 1.0 if dec.get("speed_name") == "slow" else 0.0
        return harvest - c.rotation_cost * rotated - c.slow_cost * slow - infra

    def step_cost(self, step_info):
        """Dense per-step detectability proxy: the REAL cross-layer consistency score
        of the wave, normalized. Gives the cost critic per-step credit (an evader
        accrues ~0/step; a self-contradicting attacker accrues cost every step)."""
        cons = float((step_info.get("consistency") or {}).get("score", 0.0)) / _CONS_NORM
        return self.cfg.dense_consistency_weight * cons

    def terminal_cost(self, detector_out):
        """The production detector's disguise score in [0,1] — added to the episode's
        terminal cost so the constraint is anchored to the *real* verdict."""
        return float(detector_out.get("D", 0.0))

    def constraint_value(self, episodic_costs):
        """Aggregate episodic costs per the risk mode (E[·] or CVaR_α over the batch)."""
        if not episodic_costs:
            return 0.0
        xs = sorted(episodic_costs)
        if self.cfg.risk_mode == "cvar":
            k = max(1, int(round(self.cfg.cvar_alpha * len(xs))))
            tail = xs[-k:]          # worst (highest-cost) alpha-fraction
            return sum(tail) / len(tail)
        return sum(xs) / len(xs)
