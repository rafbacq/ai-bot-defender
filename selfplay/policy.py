"""Recurrent actor-critic for the attacker (PyTorch).

A GRU policy (the POMDP belief state — the attacker never observes the detector
score, so it must integrate throttle/served-trap/harvest history) with:

* a **factored** (MultiDiscrete) actor: one categorical head per action factor
  ``(identity, timing, fetch, stack)``;
* **two** value heads — ``V_reward`` (objective) and ``V_cost`` (the CMDP
  constraint), as PPO-Lagrangian requires.

torch is imported lazily inside ``build_policy`` (mirroring
``crawler_graph.ml.gnn._build_model``) so importing this module never requires
torch; only the training path (in the app/trainer image) does.
"""


def build_policy(obs_dim, act_dims, hidden=64):
    import torch
    import torch.nn as nn
    from torch.distributions import Categorical

    class RecurrentACPolicy(nn.Module):
        def __init__(self):
            super().__init__()
            self.embed = nn.Sequential(nn.Linear(obs_dim, hidden), nn.Tanh())
            self.gru = nn.GRUCell(hidden, hidden)
            self.heads = nn.ModuleList([nn.Linear(hidden, d) for d in act_dims])
            self.v_reward = nn.Linear(hidden, 1)
            self.v_cost = nn.Linear(hidden, 1)
            self.hidden = hidden
            self.act_dims = list(act_dims)

        def initial_state(self, batch=1, device=None):
            return torch.zeros(batch, self.hidden, device=device)

        def _step(self, obs, h):
            """One timestep: obs (B, obs_dim), h (B, hidden) -> logits list, h'."""
            h = self.gru(self.embed(obs), h)
            logits = [head(h) for head in self.heads]
            return logits, h

        @torch.no_grad()
        def act(self, obs, h, greedy=False):
            """Sample a factored action for a single env step. ``obs`` (1, obs_dim)."""
            logits, h2 = self._step(obs, h)
            action, logp = [], 0.0
            for lg in logits:
                dist = Categorical(logits=lg)
                a = lg.argmax(-1) if greedy else dist.sample()
                logp = logp + dist.log_prob(a)
                action.append(int(a.item()))
            vr = self.v_reward(h2).squeeze(-1)
            vc = self.v_cost(h2).squeeze(-1)
            return action, float(logp.item()), float(vr.item()), float(vc.item()), h2

        def evaluate_sequence(self, obs_seq, actions_seq):
            """Re-run the GRU over one episode's obs sequence and score the taken
            actions. ``obs_seq`` (T, obs_dim), ``actions_seq`` (T, n_factors).
            Returns logp (T,), entropy (T,), v_reward (T,), v_cost (T,)."""
            T = obs_seq.shape[0]
            h = self.initial_state(1, device=obs_seq.device)
            logps, ents, vrs, vcs = [], [], [], []
            for t in range(T):
                logits, h = self._step(obs_seq[t:t + 1], h)
                lp, ent = 0.0, 0.0
                for f, lg in enumerate(logits):
                    dist = Categorical(logits=lg)
                    lp = lp + dist.log_prob(actions_seq[t, f])
                    ent = ent + dist.entropy()
                logps.append(lp)
                ents.append(ent)
                vrs.append(self.v_reward(h).squeeze(-1))
                vcs.append(self.v_cost(h).squeeze(-1))
            return (torch.cat(logps), torch.cat(ents),
                    torch.cat(vrs), torch.cat(vcs))

    return RecurrentACPolicy()
