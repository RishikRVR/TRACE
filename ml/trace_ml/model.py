"""TRACE world model: an MDN-RNN over per-host window states.

Following Ha & Schmidhuber's World Models (2018), a recurrent core reads the
state sequence S_1..S_t and a mixture-density head outputs P(S_t+1 | S_<=t) as a
Gaussian mixture. A stage head maps every (real or imagined) state to an
ATT&CK stage. Forecasts come from Monte Carlo rollouts: sample S_t+1, feed it
back, repeat K times, and read the stage head along each imagined trajectory.

The recurrent cell is a GRU rather than the paper's LSTM: its hidden state is
its whole state, so a rollout can start from any past window.
"""

from __future__ import annotations

import math

import torch
from torch import nn
from torch.nn import functional as F

from .stages import INFILTRATION

INF_IDX = sorted(int(s) for s in INFILTRATION)
LOG_2PI = math.log(2 * math.pi)


class WorldModel(nn.Module):
    def __init__(self, d: int, latent: int = 64, hidden: int = 128, mixtures: int = 5, n_stages: int = 7):
        super().__init__()
        self.d, self.m, self.hidden, self.n_stages = d, mixtures, hidden, n_stages
        self.enc = nn.Sequential(nn.Linear(d + 1, 128), nn.GELU(), nn.Linear(128, latent), nn.GELU())
        self.rnn = nn.GRU(latent, hidden, batch_first=True)
        self.mdn = nn.Linear(hidden, mixtures * (1 + 2 * d))
        self.stage = nn.Sequential(nn.Linear(hidden, 64), nn.GELU(), nn.Linear(64, n_stages))

    def encode(self, x: torch.Tensor, pmask: torch.Tensor) -> torch.Tensor:
        return self.enc(torch.cat([x, pmask], -1))

    def forward(self, x: torch.Tensor, pmask: torch.Tensor, h0: torch.Tensor | None = None) -> torch.Tensor:
        """Teacher-forced pass. x (B, T, d), pmask (B, T, 1) -> hidden states (B, T, H)."""
        h, _ = self.rnn(self.encode(x, pmask), h0)
        return h

    def step(self, x: torch.Tensor, pmask: torch.Tensor, h: torch.Tensor) -> torch.Tensor:
        """One imagined step. x (N, d), pmask (N, 1), h (N, H) -> next h (N, H)."""
        out, _ = self.rnn(self.encode(x, pmask).unsqueeze(1), h.unsqueeze(0))
        return out[:, 0]

    def mdn_params(self, h: torch.Tensor):
        out = self.mdn(h)
        m, d = self.m, self.d
        logit_pi = out[..., :m]
        mu = out[..., m : m + m * d].unflatten(-1, (m, d))
        log_sig = out[..., m + m * d :].unflatten(-1, (m, d)).clamp(-4.0, 2.5)
        return logit_pi, mu, log_sig

    def sample_next(self, h: torch.Tensor, u: torch.Tensor, eps: torch.Tensor) -> torch.Tensor:
        """Draw S_t+1 from the mixture using supplied noise (u: (N,) uniforms for
        the component, eps: (N, d) standard normals), so a caller can reuse the
        same noise across variants and get deterministic comparisons."""
        logit_pi, mu, log_sig = self.mdn_params(h)
        cdf = torch.cumsum(F.softmax(logit_pi, -1), -1)
        comp = torch.searchsorted(cdf.detach().contiguous(), u.unsqueeze(-1).contiguous()).clamp(max=self.m - 1)
        idx = comp.unsqueeze(-1).expand(-1, 1, self.d)
        mu_c = mu.gather(1, idx)[:, 0]
        sig_c = log_sig.gather(1, idx)[:, 0].exp()
        return mu_c + sig_c * eps

    def stage_probs(self, h: torch.Tensor) -> torch.Tensor:
        return F.softmax(self.stage(h), -1)


def mdn_nll(logit_pi, mu, log_sig, y, dim_mask) -> torch.Tensor:
    """Per-dimension-averaged negative log-likelihood of y under the mixture.
    y, dim_mask: (..., d); returns (...)."""
    y = y.unsqueeze(-2)
    lp = -0.5 * ((y - mu) / log_sig.exp()) ** 2 - log_sig - 0.5 * LOG_2PI
    lp = (lp * dim_mask.unsqueeze(-2)).sum(-1)
    lse = torch.logsumexp(F.log_softmax(logit_pi, -1) + lp, -1)
    return -lse / dim_mask.sum(-1).clamp(min=1.0)


def make_noise(samples: int, k: int, d: int, seed: int) -> tuple[torch.Tensor, torch.Tensor]:
    """Fixed rollout noise: the same S trajectories' randomness for every start,
    so forecasts are deterministic and variants (occlusions, what-ifs) differ
    only by their inputs."""
    g = torch.Generator().manual_seed(seed)
    return torch.rand(samples, k, generator=g), torch.randn(samples, k, d, generator=g)


@torch.no_grad()
def rollout(
    model: WorldModel,
    h: torch.Tensor,
    pmask: torch.Tensor,
    noise: tuple[torch.Tensor, torch.Tensor],
    packet_dims: torch.Tensor,
    clamp: dict[int, float] | None = None,
    keep_states: bool = False,
):
    """Imagine K windows ahead, S times, from each of N starts.

    h (N*S, H) holds each start's hidden state repeated S times (start-major).
    noise is make_noise's (S, K) uniforms and (S, K, d) normals. packet_dims (d,)
    marks the p_* features, zeroed where pmask (N*S, 1) is 0. clamp pins feature
    indices to fixed normalised values in every imagined window: that is how a
    what-if intervention ("block admin ports") is applied inside the model.

    Returns stage probabilities (N*S, K, stages), the cumulative infiltration
    probability after each step (N*S, K) and, if keep_states, the imagined
    states (N*S, K, d).
    """
    u_base, eps_base = noise
    s, k = u_base.shape
    n = h.shape[0] // s
    keep = 1.0 - packet_dims * (1.0 - pmask)
    surv = torch.ones(h.shape[0], device=h.device)
    xs, ps, cum = [], [], []
    for j in range(k):
        u = u_base[:, j].to(h.device).repeat(n)
        eps = eps_base[:, j].to(h.device).repeat(n, 1)
        x = model.sample_next(h, u, eps) * keep
        if clamp:
            for i, v in clamp.items():
                x[:, i] = v
        h = model.step(x, pmask, h)
        p = model.stage_probs(h)
        surv = surv * (1.0 - p[:, INF_IDX].sum(-1))
        ps.append(p)
        cum.append(1.0 - surv)
        if keep_states:
            xs.append(x)
    return torch.stack(ps, 1), torch.stack(cum, 1), (torch.stack(xs, 1) if keep_states else None)
