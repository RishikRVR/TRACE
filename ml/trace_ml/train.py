"""Train the TRACE world model and its logistic-regression baselines.

    python -m trace_ml.train --data ../data/features/sim --out ../artifacts/sim

Writes model.pt, normaliser.json, config.json, calibration.json,
reference.json, lr_state.pkl, lr_stacked.pkl and train_log.json. The config
copy records the data, split and hyperparameters, so a run can be reproduced.
"""

from __future__ import annotations

import argparse
import json
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import yaml
from sklearn.linear_model import LogisticRegression
from torch.nn import functional as F

from . import data as D
from .engine import Engine, stack_history
from .metrics import best_threshold, binary
from .model import INF_IDX, WorldModel, mdn_nll
from .stages import Stage


def load_dataset(path: Path, min_present: int = 10):
    w = D.read_windows(path / "windows.csv")
    schema = D.load_schema(path / "schema.json")
    tl = pd.read_csv(path / "timeline.csv") if (path / "timeline.csv").exists() else None
    labels = pd.read_csv(path / "labels.csv") if (path / "labels.csv").exists() else None
    row_stage = None
    if labels is not None:
        key = w[["source", "host", "window_start"]].merge(labels, how="left", on=["source", "host", "window_start"])
        row_stage = key["stage"].fillna(0).astype(int)
    seqs = D.build_sequences(w, schema["features"], intervals=tl, row_stage=row_stage, min_present=min_present)
    eps = pd.read_csv(path / "episodes.csv") if (path / "episodes.csv").exists() else None
    return seqs, schema, eps


def split_sources(eps: pd.DataFrame | None, seqs, holdout_exfil: str = "dns_tunnel"):
    """Episode-level split: whole episodes go to one side. Episodes using the
    held-out family never appear in training or validation."""
    sources = sorted({s.source for s in seqs})
    unseen = set()
    if eps is not None and "exfil" in eps:
        unseen = set(eps.loc[eps.exfil == holdout_exfil, "source"])
    rest = [s for s in sources if s not in unseen]
    n = len(rest)
    train, val, test = set(rest[: int(0.6 * n)]), set(rest[int(0.6 * n) : int(0.8 * n)]), set(rest[int(0.8 * n) :])
    return {"train": sorted(train), "val": sorted(val), "test": sorted(test), "unseen": sorted(unseen)}


def batches(items, bs, rng):
    order = rng.permutation(len(items))
    for a in range(0, len(order), bs):
        yield [items[i] for i in order[a : a + bs]]


def collate(batch, d, packet_dims, drop_p, rng, k):
    B = len(batch)
    T = max(it["Z"].shape[0] for it in batch)
    X = np.zeros((B, T, d), np.float32)
    PM = np.zeros((B, T, 1), np.float32)
    ST = np.zeros((B, T), np.int64)
    YI = np.zeros((B, T), np.float32)
    V = np.zeros((B, T), np.float32)
    L = np.zeros(B, np.int64)
    for b, it in enumerate(batch):
        n = it["Z"].shape[0]
        pm = float(it["has_packet"] and rng.random() >= drop_p)
        z = it["Z"] if pm else it["Z"] * (1 - packet_dims)
        X[b, :n], PM[b, :n], ST[b, :n], YI[b, :n], V[b, :n], L[b] = z, pm, it["stage"], it["y"], 1.0, n
    DM = 1.0 - packet_dims[None, None, :] * (1.0 - PM)
    t = lambda a: torch.from_numpy(a)
    return t(X), t(PM), t(DM.astype(np.float32)), t(ST), t(YI), t(V), t(L)


def train_model(items, d, cfg, packet_dims, log):
    m = cfg["model"]
    model = WorldModel(d, latent=m["latent_dim"], hidden=m["hidden_dim"], mixtures=m["mixture_components"])
    opt = torch.optim.Adam(model.parameters(), lr=cfg["train"]["lr"])
    rng = np.random.default_rng(cfg["train"]["seed"])
    torch.manual_seed(cfg["train"]["seed"])
    k = cfg["forecast"]["horizon_k"]
    counts = np.bincount(np.concatenate([it["stage"] for it in items]), minlength=7).astype(np.float64)
    w = np.where(counts > 0, np.sqrt(counts.max() / np.maximum(counts, 1)), 1.0)
    weight = torch.tensor(np.minimum(w, 30.0), dtype=torch.float32)
    pdims = torch.from_numpy(packet_dims)
    pos_w = cfg["train"]["pos_weight"]
    epochs = cfg["train"]["epochs"]
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=cfg["train"]["lr"], total_steps=epochs * (len(items) // 32 + 1))
    for ep in range(epochs):
        t0, tot, nb = time.time(), {"nll": 0.0, "stage": 0.0, "os_stage": 0.0, "forecast": 0.0}, 0
        model.train()
        for batch in batches(items, 32, rng):
            X, PM, DM, ST, YI, V, L = collate(batch, d, packet_dims, m["packet_level_dropout"], rng, k)
            h = model(X, PM)
            lp, mu, ls = model.mdn_params(h[:, :-1])
            nll = mdn_nll(lp, mu, ls, X[:, 1:], DM[:, 1:])
            l_nll = (nll * V[:, 1:]).sum() / V[:, 1:].sum()
            logits = model.stage(h)
            ce = F.cross_entropy(logits.transpose(1, 2), ST, weight=weight, reduction="none")
            l_st = (ce * V).sum() / V.sum()

            # overshooting: imagine K steps from sampled starts, score the imagined
            # stages against the real future and the forecast against the label
            Bn, T = V.shape
            sel = (torch.rand(Bn, T) < cfg["train"]["overshoot_frac"]) & (V > 0)
            bi, ti = sel.nonzero(as_tuple=True)
            hk, pm = h[bi, ti], PM[bi, ti]
            keep = 1.0 - pdims * (1.0 - pm)
            surv = torch.ones(len(bi))
            l_os, l_osn = 0.0, 0.0
            for j in range(1, k + 1):
                tt = ti + j
                valid = (tt < L[bi]).float()
                ttc = tt.clamp(max=T - 1)
                lp, mu, ls = model.mdn_params(hk)
                if j <= cfg["train"]["overshoot_steps"]:
                    nk = mdn_nll(lp, mu, ls, X[bi, ttc], DM[bi, ttc])
                    l_osn = l_osn + (nk * valid).sum() / valid.sum().clamp(min=1)
                comp = torch.multinomial(F.softmax(lp, -1).detach(), 1)[:, 0]
                ar = torch.arange(len(bi))
                x = (mu[ar, comp] + ls[ar, comp].exp() * torch.randn(len(bi), d)) * keep
                hk = model.step(x, pm, hk)
                lg = model.stage(hk)
                ce = F.cross_entropy(lg, ST[bi, ttc], weight=weight, reduction="none")
                l_os = l_os + (ce * valid).sum() / valid.sum().clamp(min=1)
                surv = surv * (1.0 - F.softmax(lg, -1)[:, INF_IDX].sum(-1))
            p_cum = (1.0 - surv).clamp(1e-5, 1 - 1e-5)
            y = YI[bi, ti]
            l_fc = F.binary_cross_entropy(p_cum, y, weight=torch.where(y > 0, pos_w, 1.0))
            loss = l_nll + l_st + l_os / k + 2.0 * l_fc + 0.1 * l_osn / cfg["train"]["overshoot_steps"]
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            for key, val in (("nll", l_nll), ("stage", l_st), ("os_stage", l_os / k), ("forecast", l_fc)):
                tot[key] += float(val)
            nb += 1
        row = {"epoch": ep + 1, **{k2: v / nb for k2, v in tot.items()}, "seconds": time.time() - t0}
        log.append(row)
        print(" ".join(f"{k2}={v:.4f}" if isinstance(v, float) else f"{k2}={v}" for k2, v in row.items()), flush=True)
    return model.eval()


def prepare(seqs, norm, k):
    items = []
    for s in seqs:
        items.append({"Z": norm.transform(s.X), "stage": s.stage, "y": D.infiltration_within(s.stage, k).astype(np.float32),
                      "has_packet": s.has_packet, "seq": s})
    return items


def chunked(items, length: int = 240, stride: int = 120):
    """Split long sequences (a CIC host-day is ~960 windows) into overlapping
    training crops, so long captures give many gradient steps."""
    out = []
    for it in items:
        T = len(it["stage"])
        if T <= length:
            out.append(it)
            continue
        for a in range(0, T - length // 2, stride):
            b = min(T, a + length)
            out.append({**it, "Z": it["Z"][a:b], "stage": it["stage"][a:b], "y": it["y"][a:b]})
    return out


def lr_data(items, n, stacked, early_only=False, neg_keep=1.0, rng=None):
    Xs, ys = [], []
    for it in items:
        Z = it["Z"] if it["has_packet"] else it["Z"]
        X = stack_history(Z, n) if stacked else Z
        y = it["y"]
        m = np.ones(len(y), bool)
        if early_only:
            m[D.first_infiltration(it["stage"]) :] = False
        if rng is not None and neg_keep < 1.0:
            m &= (y > 0) | (rng.random(len(y)) < neg_keep)
        Xs.append(X[m])
        ys.append(y[m])
    return np.concatenate(Xs), np.concatenate(ys)


def platt(p_raw: np.ndarray, y: np.ndarray) -> dict:
    """Monotone calibration: isotonic regression, then linear interpolation
    between the centres of its constant blocks, so the map has no flat steps
    (a what-if that lowers the raw risk always shows as lower)."""
    from sklearn.isotonic import IsotonicRegression

    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(p_raw, y)
    xs, ys = iso.X_thresholds_, iso.y_thresholds_
    cx, cy, a = [], [], 0
    for b in range(1, len(ys) + 1):
        if b == len(ys) or ys[b] != ys[a]:
            cx.append(float((xs[a] + xs[b - 1]) / 2))
            cy.append(float(ys[a]))
            a = b
    cx = [0.0] + cx + [1.0]
    cy = [0.0] + cy + [max(cy[-1], 0.99)]
    return {"type": "isotonic_interpolated", "x": cx, "y": np.maximum.accumulate(cy).tolist()}


def recalibrate(art: Path, data: Path) -> None:
    """Refit calibration and the alarm threshold for an already-trained model."""
    eng = Engine.load(art)
    cfg = eng.cfg
    seqs, _, _ = load_dataset(data)
    val = [s for s in seqs if s.source in set(cfg["split"]["val"])]
    eng.calib = None
    fc = eng.forecast(val, samples=32)
    p_raw = np.concatenate([f.p_raw for f in fc])
    y = np.concatenate([D.infiltration_within(s.stage, eng.k) for s in val])
    calib = platt(p_raw, y)
    (art / "calibration.json").write_text(json.dumps(calib))
    eng.calib = calib
    em = np.concatenate([early_mask(s) for s in val])
    cfg["threshold"] = best_threshold(y[em], eng.calibrate(p_raw)[em])
    cfg.setdefault("thresholds", {})["trace"] = cfg["threshold"]
    (art / "config.json").write_text(json.dumps(cfg, indent=1))
    print("recalibrated", art, "threshold", round(cfg["threshold"], 4), "points", len(calib["x"]))


def early_mask(seq) -> np.ndarray:
    m = np.ones(seq.T, bool)
    m[D.first_infiltration(seq.stage) :] = False
    return m


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--config", default=str(Path(__file__).resolve().parents[1] / "configs" / "default.yaml"))
    ap.add_argument("--epochs", type=int)
    ap.add_argument("--flow-only", action="store_true", help="dataset has no packet-level features")
    ap.add_argument("--recalibrate-only", action="store_true", help="refit calibration and threshold for a trained model")
    args = ap.parse_args(argv)
    if args.recalibrate_only:
        return recalibrate(Path(args.out), Path(args.data))
    cfg = yaml.safe_load(Path(args.config).read_text())
    if args.epochs:
        cfg["train"]["epochs"] = args.epochs
    torch.set_num_threads(max(1, min(12, torch.get_num_threads())))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    seqs, schema, eps = load_dataset(Path(args.data))
    feats = schema["features"]
    split_file = Path(args.data) / "split.json"
    split = json.loads(split_file.read_text()) if split_file.exists() else split_sources(eps, seqs)
    by = {name: [s for s in seqs if s.source in set(src)] for name, src in split.items()}
    print({k2: len(v) for k2, v in by.items()}, "sequences;", f"{time.time() - t0:.1f}s load", flush=True)
    norm = D.Normaliser.fit(by["train"], feats)
    norm.save(out / "normaliser.json")
    k, n = cfg["forecast"]["horizon_k"], cfg["window"]["history"]
    packet_dims = np.array([1.0 if f.startswith("p_") else 0.0 for f in feats], np.float32)
    items = {name: prepare(v, norm, k) for name, v in by.items()}

    log: list[dict] = []
    model = train_model(chunked(items["train"]), len(feats), cfg, packet_dims, log)
    torch.save(model.state_dict(), out / "model.pt")

    m = cfg["model"]
    run_cfg = {
        "model": {"latent": m["latent_dim"], "hidden": m["hidden_dim"], "mixtures": m["mixture_components"]},
        "horizon_k": k, "history": n, "seed": cfg["forecast"]["seed"], "window_s": schema["window_s"],
        "rollouts": cfg["forecast"]["rollouts"], "features": feats, "data": str(args.data), "split": split,
        "flow_only": bool(args.flow_only), "train": cfg["train"],
    }
    (out / "config.json").write_text(json.dumps(run_cfg, indent=1))

    # calibration and threshold on validation
    eng = Engine(model, norm, run_cfg)
    val_fc = eng.forecast(by["val"], samples=32)
    p_val = np.concatenate([f.p_raw for f in val_fc])
    y_val = np.concatenate([it["y"] for it in items["val"]])
    calib = platt(p_val, y_val)
    (out / "calibration.json").write_text(json.dumps(calib))
    eng.calib = calib
    pc_val = eng.calibrate(p_val)
    em_val = np.concatenate([early_mask(s) for s in by["val"]])
    thr = best_threshold(y_val[em_val], pc_val[em_val])

    # reference behaviour and surprise distribution
    benign = np.concatenate([it["Z"][(it["stage"] == 0) & it["seq"].present] for it in items["train"]])
    ref = np.median(benign, axis=0)
    eng.ref = ref.astype(np.float32)
    sur = np.concatenate([f.surprise[(s.stage == 0)] for f, s in zip(val_fc, by["val"])])
    extra = {"benign_ref": ref.tolist(), "surprise_quantiles": np.quantile(sur, np.linspace(0, 1, 101)).tolist()}
    (out / "reference.json").write_text(json.dumps(extra))

    # logistic-regression baselines on the same (normalised) features
    rng = np.random.default_rng(0)
    thresholds = {"trace": thr}
    for name, stacked in (("lr_state", False), ("lr_stacked", True)):
        Xtr, ytr = lr_data(items["train"], n, stacked, neg_keep=0.5 if stacked else 1.0, rng=rng)
        lr = LogisticRegression(max_iter=1000, class_weight="balanced", C=0.5)
        lr.fit(Xtr, ytr)
        (out / f"{name}.pkl").write_bytes(pickle.dumps(lr))
        Xv, yv = lr_data(items["val"], n, stacked)
        pv = lr.predict_proba(Xv)[:, 1]
        thresholds[name] = best_threshold(yv[em_val], pv[em_val])
        print(name, "val", {k2: round(v, 3) for k2, v in binary(yv[em_val], pv[em_val], thresholds[name]).items() if isinstance(v, float)}, flush=True)
    print("trace val", {k2: round(v, 3) for k2, v in binary(y_val[em_val], pc_val[em_val], thr).items() if isinstance(v, float)}, flush=True)
    run_cfg["threshold"] = thr
    run_cfg["thresholds"] = thresholds
    (out / "config.json").write_text(json.dumps(run_cfg, indent=1))
    (out / "train_log.json").write_text(json.dumps({"epochs": log, "seconds": time.time() - t0}, indent=1))
    print(f"done in {time.time() - t0:.0f}s -> {out}")


if __name__ == "__main__":
    main()
