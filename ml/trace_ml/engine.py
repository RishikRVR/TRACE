"""Inference: K-step forecasts, surprise, explanations and what-ifs.

Everything a trained world model does after training lives here, so training,
evaluation and the console share one implementation.
"""

from __future__ import annotations

import json
import pickle
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import torch

from . import glossary
from .data import HostSeq, Normaliser
from .model import WorldModel, make_noise, mdn_nll, rollout
from .stages import Stage

# What-if actions: which features the action removes from the imagined future.
# "isolate" empties every imagined window (the host can no longer talk).
ACTIONS = {
    "block_admin": {
        "label": "Block admin ports (SSH/SMB/RDP/WinRM)",
        "features": ["f_admin_conn_out", "f_admin_conn_in", "f_conn_fail_out", "f_syn_only_out", "f_uniq_dport_out"],
    },
    "rate_limit": {
        "label": "Rate-limit outbound traffic",
        "features": ["f_bytes_out", "f_pkts_out", "f_bytes_ratio", "f_dns_queries_out", "p_payload_bin_1025_1460"],
    },
    "block_scanner": {
        "label": "Block the scanning source",
        "features": ["f_uniq_lport_in", "p_lport_seq_frac_in", "p_lport_entropy_in", "f_tcp_syn_in", "f_flows_new_in", "f_admin_conn_in"],
    },
    "isolate": {"label": "Isolate host (quarantine VLAN)", "features": "*"},
}


def device() -> torch.device:
    return torch.device("cpu")


@dataclass
class Forecast:
    p: np.ndarray  # (T,) calibrated P(infiltration within K) at each window
    p_raw: np.ndarray  # (T,)
    cone: np.ndarray  # (T, K, 3) 10/50/90th percentile of cumulative risk per step
    stage: np.ndarray  # (T, K, stages) mean stage probabilities per imagined step
    now_stage: np.ndarray  # (T, stages) stage of the current window
    surprise: np.ndarray  # (T,) per-dim NLL of the window given the past


class Engine:
    def __init__(self, model: WorldModel, norm: Normaliser, cfg: dict, calib: dict | None = None, ref: np.ndarray | None = None,
                 surprise_ref: np.ndarray | None = None, lr: dict | None = None):
        self.model = model.eval()
        self.norm = norm
        self.cfg = cfg
        self.features = norm.features
        self.fidx = {f: i for i, f in enumerate(self.features)}
        self.k = int(cfg["horizon_k"])
        self.history = int(cfg["history"])
        self.calib = calib
        self.packet_dims = torch.tensor([1.0 if f.startswith("p_") else 0.0 for f in self.features])
        self.ref = ref if ref is not None else np.zeros(len(self.features), dtype=np.float32)
        self.empty = norm.transform(np.zeros((1, len(self.features)), dtype=np.float32))[0]
        self.surprise_ref = surprise_ref
        self.lr = lr or {}
        self.threshold = float(cfg.get("threshold", 0.5))

    # --- loading ------------------------------------------------------------

    @classmethod
    def load(cls, art: str | Path) -> "Engine":
        art = Path(art)
        cfg = json.loads((art / "config.json").read_text())
        norm = Normaliser.load(art / "normaliser.json")
        model = WorldModel(len(norm.features), **cfg["model"])
        model.load_state_dict(torch.load(art / "model.pt", map_location="cpu"))
        calib = json.loads((art / "calibration.json").read_text()) if (art / "calibration.json").exists() else None
        extra = json.loads((art / "reference.json").read_text()) if (art / "reference.json").exists() else {}
        lr = {}
        for name in ("lr_state", "lr_stacked"):
            if (art / f"{name}.pkl").exists():
                lr[name] = pickle.loads((art / f"{name}.pkl").read_bytes())
        return cls(
            model, norm, cfg, calib,
            ref=np.array(extra["benign_ref"], dtype=np.float32) if "benign_ref" in extra else None,
            surprise_ref=np.array(extra["surprise_quantiles"]) if "surprise_quantiles" in extra else None,
            lr=lr,
        )

    # --- basics -------------------------------------------------------------

    def prep(self, seq: HostSeq, packet: bool | None = None) -> tuple[torch.Tensor, torch.Tensor]:
        pm = float(seq.has_packet if packet is None else packet)
        Z = self.norm.transform(seq.X)
        if pm == 0.0:
            Z = Z * (1.0 - self.packet_dims.numpy())
        return torch.from_numpy(Z), torch.full((seq.T, 1), pm)

    def calibrate(self, p: np.ndarray) -> np.ndarray:
        if not self.calib:
            return p
        return np.interp(p, self.calib["x"], self.calib["y"])

    @torch.no_grad()
    def hidden(self, Z: torch.Tensor, pm: torch.Tensor) -> torch.Tensor:
        return self.model(Z.unsqueeze(0), pm.unsqueeze(0))[0]

    def noise(self, samples: int, seed: int | None = None):
        return make_noise(samples, self.k, len(self.features), int(self.cfg.get("seed", 1337) if seed is None else seed))

    @torch.no_grad()
    def _roll(self, h: torch.Tensor, pm: torch.Tensor, samples: int, clamp=None, keep_states=False, chunk: int = 131072):
        """Roll out every row of h (N, H) samples times; returns per-start results."""
        noise = self.noise(samples)
        n = h.shape[0]
        per = max(1, chunk // samples)
        ps, cums, xs = [], [], []
        for a in range(0, n, per):
            hh = h[a : a + per].repeat_interleave(samples, 0)
            pp = pm[a : a + per].repeat_interleave(samples, 0)
            p, cum, x = rollout(self.model, hh, pp, noise, self.packet_dims, clamp=clamp, keep_states=keep_states)
            m = hh.shape[0] // samples
            ps.append(p.view(m, samples, self.k, -1))
            cums.append(cum.view(m, samples, self.k))
            if keep_states:
                xs.append(x.view(m, samples, self.k, -1))
        return torch.cat(ps), torch.cat(cums), (torch.cat(xs) if keep_states else None)

    # --- forecasts ----------------------------------------------------------

    @torch.no_grad()
    def forecast(self, seqs: list[HostSeq], samples: int = 64, packet: bool | None = None) -> list[Forecast]:
        hs, pms, Zs, lens = [], [], [], []
        for s in seqs:
            Z, pm = self.prep(s, packet)
            h = self.hidden(Z, pm)
            hs.append(h)
            pms.append(pm)
            Zs.append(Z)
            lens.append(s.T)
        H, PM = torch.cat(hs), torch.cat(pms)
        ps, cum, _ = self._roll(H, PM, samples)
        p_raw = cum[:, :, -1].mean(1).numpy()
        q = torch.quantile(cum, torch.tensor([0.1, 0.5, 0.9]), dim=1).permute(1, 2, 0).numpy()  # (N, K, 3)
        stage = ps.mean(1).numpy()
        now = self.model.stage_probs(H).numpy()
        out, a = [], 0
        for s, h, Z, pm in zip(seqs, hs, Zs, pms):
            b = a + s.T
            sur = self.surprise(h, Z, pm)
            out.append(Forecast(
                p=self.calibrate(p_raw[a:b]), p_raw=p_raw[a:b], cone=self.calibrate(q[a:b]),
                stage=stage[a:b], now_stage=now[a:b], surprise=sur,
            ))
            a = b
        return out

    @torch.no_grad()
    def surprise(self, h: torch.Tensor, Z: torch.Tensor, pm: torch.Tensor) -> np.ndarray:
        """NLL of each window given the history before it: how unexpected the
        traffic was to the world model."""
        dm = 1.0 - self.packet_dims * (1.0 - pm)
        lp, mu, ls = self.model.mdn_params(h[:-1])
        nll = mdn_nll(lp, mu, ls, Z[1:], dm[1:]).numpy()
        return np.concatenate([[float(np.median(nll)) if len(nll) else 0.0], nll])

    def surprise_pct(self, nll: np.ndarray) -> np.ndarray:
        """Percentile of each NLL against held-out benign traffic."""
        if self.surprise_ref is None:
            return np.zeros_like(nll)
        return np.interp(nll, self.surprise_ref, np.linspace(0, 100, len(self.surprise_ref)))

    # --- baselines ----------------------------------------------------------

    def lr_proba(self, seq: HostSeq, which: str = "lr_state") -> np.ndarray | None:
        m = self.lr.get(which)
        if m is None:
            return None
        Z, _ = self.prep(seq)
        X = stack_history(Z.numpy(), self.history) if which == "lr_stacked" else Z.numpy()
        return m.predict_proba(X)[:, 1]

    # --- explanations -------------------------------------------------------

    @torch.no_grad()
    def explain(self, seq: HostSeq, t: int, samples: int = 64) -> dict:
        """Occlusion attribution at window t: replace a feature (or a feature
        group, or a whole past window) in the last `history` windows with this
        model's picture of normal behaviour, re-run the same fixed-noise
        forecast, and report how far the risk falls."""
        Z, pm = self.prep(seq)
        h_all = self.hidden(Z, pm)
        a = max(0, t - self.history + 1)
        h0 = h_all[a - 1] if a > 0 else torch.zeros(self.model.hidden)
        seg = Z[a : t + 1]  # (n, d)
        n, d = seg.shape
        ref = torch.from_numpy(self.ref)

        variants = [seg]
        names: list[tuple[str, str]] = [("base", "")]
        for i, f in enumerate(self.features):
            if pm[0, 0] == 0 and f.startswith("p_"):
                continue
            v = seg.clone()
            v[:, i] = ref[i]
            variants.append(v)
            names.append(("feature", f))
        # Groups are scored by their strongest member, not by occluding the
        # whole group at once: replacing a dozen correlated features together
        # builds a state the model has never seen (a host with no ports probed
        # but still flooded with data), which can read as *more* anomalous and
        # make a group that plainly matters score zero.
        for j in range(n):
            v = seg.clone()
            v[j] = ref
            variants.append(v)
            names.append(("window", str(a + j)))
        V = torch.stack(variants)  # (m, n, d)
        m = V.shape[0]
        hv, _ = self.model.rnn(self.model.encode(V, pm[0].expand(m, n, 1)), h0.expand(1, m, -1).contiguous())
        _, cum, _ = self._roll(hv[:, -1], pm[0].expand(m, 1), samples)
        p = self.calibrate(cum[:, :, -1].mean(1).numpy())
        base = float(p[0])
        feats, wins = [], []
        raw = seq.X
        for (kind, name), pv in zip(names[1:], p[1:]):
            delta = base - float(pv)
            if kind == "feature":
                i = self.fidx[name]
                past = raw[: max(1, t - 2), i]
                typical = float(np.median(past)) if len(past) >= 5 else float(self.norm.inverse(self.ref[None])[0, i])
                feats.append({
                    "feature": name, "label": glossary.label(name), "level": glossary.level(name), "group": glossary.group_of(name),
                    "delta": delta, "value": float(raw[t, i]), "typical": typical, "without": float(pv),
                    "description": glossary.FEATURES.get(name, ("", "", ""))[1], "unit": glossary.FEATURES.get(name, ("", "", ""))[2],
                })
            else:
                wins.append({"t": int(name), "delta": delta})
        feats.sort(key=lambda r: -r["delta"])
        best: dict[str, float] = {}
        for f in feats:
            best[f["group"]] = max(best.get(f["group"], 0.0), f["delta"])
        groups = sorted(({"group": g, "delta": d, "without": base - d} for g, d in best.items()), key=lambda r: -r["delta"])
        top = [f for f in feats if f["delta"] > 0.01][:5]
        # faithfulness check: remove the top features together
        faith = None
        if top:
            v = seg.clone()
            for f in top:
                v[:, self.fidx[f["feature"]]] = ref[self.fidx[f["feature"]]]
            hv, _ = self.model.rnn(self.model.encode(v[None], pm[0].expand(1, n, 1)), h0.view(1, 1, -1))
            _, cum, _ = self._roll(hv[:, -1], pm[0].expand(1, 1), samples)
            faith = float(self.calibrate(cum[:, :, -1].mean(1).numpy())[0])
        return {"t": t, "p": base, "features": feats[:20], "groups": groups, "windows": wins,
                "sentences": sentences(top), "without_top": faith}

    # --- what-if and imagined futures ---------------------------------------

    @torch.no_grad()
    def whatif(self, seq: HostSeq, t: int, action: str, samples: int = 128) -> dict:
        Z, pm = self.prep(seq)
        h = self.hidden(Z, pm)[t : t + 1]
        _, base, _ = self._roll(h, pm[:1], samples)
        spec = ACTIONS[action]["features"]
        if spec == "*":
            clamp = {i: float(self.empty[i]) for i in range(len(self.features))}
        else:
            clamp = {self.fidx[f]: float(self.ref[self.fidx[f]]) for f in spec if f in self.fidx}
        _, after, _ = self._roll(h, pm[:1], samples, clamp=clamp)
        return {
            "action": action, "label": ACTIONS[action]["label"], "t": t,
            "before": self.calibrate(base[0].mean(0).numpy()).tolist(),
            "after": self.calibrate(after[0].mean(0).numpy()).tolist(),
        }

    @torch.no_grad()
    def imagine(self, seq: HostSeq, t: int, features: list[str], samples: int = 64) -> dict:
        """The world model's imagined next K windows for a few features, in raw
        units: 10/50/90th percentiles across the sampled futures."""
        Z, pm = self.prep(seq)
        h = self.hidden(Z, pm)[t : t + 1]
        _, _, xs = self._roll(h, pm[:1], samples, keep_states=True)
        raw = self.norm.inverse(xs[0].numpy())  # (S, K, d)
        out = {}
        for f in features:
            i = self.fidx[f]
            q = np.quantile(raw[:, :, i], [0.1, 0.5, 0.9], axis=0)  # (3, K)
            a = max(0, t - self.history + 1)
            out[f] = {"label": glossary.label(f), "history": seq.X[a : t + 1, i].tolist(), "q10": q[0].tolist(),
                      "q50": q[1].tolist(), "q90": q[2].tolist()}
        return out


def stack_history(Z: np.ndarray, n: int) -> np.ndarray:
    """Row t = the last n windows' vectors concatenated (zeros before start)."""
    T, d = Z.shape
    P = np.concatenate([np.zeros((n - 1, d), dtype=Z.dtype), Z])
    return np.concatenate([P[i : i + T] for i in range(n)], axis=1)


def _fmt(v: float, unit: str) -> str:
    if unit == "share":
        return f"{100 * v:.0f}%"
    if unit == "bytes":
        for u, s in ((1e6, "MB"), (1e3, "kB")):
            if v >= u:
                return f"{v / u:.1f} {s}"
        return f"{v:.0f} B"
    if abs(v) >= 100 or float(v).is_integer():
        return f"{v:.0f}"
    return f"{v:.2f}"


def sentences(top: list[dict]) -> list[str]:
    out = []
    for f in top:
        cur, typ, unit = f["value"], f["typical"], f["unit"]
        s = f"{f['label']}: {_fmt(cur, unit)}"
        if unit != "share" and typ > 0 and cur / typ >= 2:
            s += f" ({cur / typ:.0f}× this host's normal {_fmt(typ, unit)})"
        elif abs(cur - typ) > 1e-9:
            s += f" (normally {_fmt(typ, unit)})"
        s += f". Without it the forecast drops by {100 * f['delta']:.0f} points."
        out.append(s)
    return out


STAGE_NAMES = {int(s): s.name.replace("_", " ").title().replace("And", "and") for s in Stage}
