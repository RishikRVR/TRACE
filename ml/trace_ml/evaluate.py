"""Benchmark: world model vs logistic regression on the same features.

    python -m trace_ml.evaluate --art ../artifacts/sim --data ../data/features/sim --sweep ../data/features/slowscan

Thresholds are chosen on the validation split and frozen for test. Writes
benchmark.json (read by the console) and prints a Markdown table.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from sklearn.metrics import f1_score

from . import data as D
from .engine import Engine, stack_history
from .metrics import best_threshold, binary
from .model import mdn_nll
from .train import load_dataset

MODELS = ("trace", "lr_state", "lr_stacked")
NAMES = {"trace": "TRACE world model", "lr_state": "Logistic regression (S_t)", "lr_stacked": "Logistic regression (last 20 windows)"}


def scores(eng: Engine, seqs, samples=32) -> dict[str, list[np.ndarray]]:
    fc = eng.forecast(seqs, samples=samples)
    out = {"trace": [f.p for f in fc], "now": [f.now_stage for f in fc], "surprise": [f.surprise for f in fc]}
    for m in ("lr_state", "lr_stacked"):
        out[m] = [eng.lr_proba(s, m) for s in seqs]
    return out


def labels(seqs, k):
    y = [D.infiltration_within(s.stage, k) for s in seqs]
    early = []
    for s in seqs:
        m = np.ones(s.T, bool)
        m[D.first_infiltration(s.stage):] = False
        early.append(m)
    return y, early


def cat(xs, masks=None):
    if masks is None:
        return np.concatenate(xs)
    return np.concatenate([x[m] for x, m in zip(xs, masks)])


def episode_alarms(seqs, probs, thr, window_s, lookback=20, kinds=None):
    """Early warning per episode, strictly: a warning counts only if it is on
    the host that is compromised first, within `lookback` windows before its
    compromise. Alarms on benign windows that are not in such a lead-up are
    false alarms."""
    by: dict[str, list[int]] = {}
    for i, s in enumerate(seqs):
        by.setdefault(s.source, []).append(i)
    res = {}
    for src, idx in by.items():
        victim, fi_v = None, None
        fp_onsets, benign_windows = 0, 0
        for i in idx:
            s, p = seqs[i], probs[i]
            fi = D.first_infiltration(s.stage)
            if fi < s.T and (fi_v is None or s.t0 + fi * s.window_ms < seqs[victim].t0 + fi_v * seqs[victim].window_ms):
                victim, fi_v = i, fi
            benign = s.stage == 0
            benign[max(0, fi - lookback):] = False  # the lead-up to (and time after) this host's compromise
            alarm = p >= thr
            onset = alarm & ~np.concatenate([[False], alarm[:-1]])
            fp_onsets += int((onset & benign).sum())
            benign_windows += int(benign.sum())
        lead = None
        if victim is not None:
            p = probs[victim]
            a = max(0, fi_v - lookback)
            hits = np.flatnonzero(p[a:fi_v] >= thr)
            if len(hits):
                lead = (fi_v - (a + hits[0])) * window_s / 60
        res[src] = {"attack": victim is not None, "lead_min": lead, "fp_onsets": fp_onsets, "benign_windows": benign_windows,
                    "kind": (kinds or {}).get(src, "")}
    return res


def summarise_alarms(res, window_s=30):
    attacks = [r for r in res.values() if r["attack"]]
    benign_eps = [r for r in res.values() if r["kind"] == "benign"]
    warned = [r for r in attacks if r["lead_min"] is not None]
    hours = sum(r["benign_windows"] for r in res.values()) * window_s / 3600
    return {
        "attack_episodes": len(attacks), "warned_before_compromise": len(warned),
        "warned_frac": len(warned) / len(attacks) if attacks else 0.0,
        "median_lead_min": float(np.median([r["lead_min"] for r in warned])) if warned else 0.0,
        "benign_episodes": len(benign_eps), "false_alarm_episodes": sum(r["fp_onsets"] > 0 for r in benign_eps),
        "false_alarms_per_host_hour": sum(r["fp_onsets"] for r in res.values()) / hours if hours else 0.0,
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--art", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--sweep")
    ap.add_argument("--samples", type=int, default=32)
    args = ap.parse_args(argv)
    eng = Engine.load(args.art)
    cfg = eng.cfg
    k, ws = eng.k, cfg["window_s"]
    seqs, schema, eps = load_dataset(Path(args.data))
    split = cfg["split"]
    by = {name: [s for s in seqs if s.source in set(src)] for name, src in split.items()}
    S = {name: scores(eng, v, args.samples) for name, v in by.items() if v}
    Y = {name: labels(v, k) for name, v in by.items() if v}

    bench = {"dataset": schema.get("source_dataset", "TRACE simulator (labelled kill chains)"), "window_s": ws, "horizon_k": k,
             "split": {n: len(v) for n, v in split.items()}, "tasks": {}, "models": NAMES}
    thr = {}
    for task in ("all", "early"):
        yv, ev = Y["val"]
        yt, et = Y["test"]
        mv = None if task == "all" else ev
        mt = None if task == "all" else et
        bench["tasks"][task] = {}
        for m in MODELS:
            t = best_threshold(cat(yv, mv), cat(S["val"][m], mv))
            thr[(task, m)] = t
            bench["tasks"][task][m] = binary(cat(yt, mt), cat(S["test"][m], mt), t)
    bench["thresholds"] = {f"{a}/{b}": v for (a, b), v in thr.items()}

    # early warning and lead time, at each model's early-warning threshold
    kinds = dict(zip(eps.source, eps.kind)) if eps is not None and "kind" in eps else {}
    bench["early_warning"] = {}
    for m in MODELS:
        res = episode_alarms(by["test"], S["test"][m], thr[("early", m)], ws, kinds=kinds)
        bench["early_warning"][m] = summarise_alarms(res, ws)

    # the same comparison at an equal false-alarm budget: each baseline's
    # threshold is set on validation so it raises no more false alarms per
    # host-hour than TRACE does
    target = summarise_alarms(episode_alarms(by["val"], S["val"]["trace"], thr[("early", "trace")], ws, kinds=kinds), ws)["false_alarms_per_host_hour"]
    thr_fa = {"trace": thr[("early", "trace")]}
    for m in ("lr_state", "lr_stacked"):
        thr_fa[m] = fa_threshold(by["val"], S["val"][m], target, ws, kinds)
    bench["false_alarm_budget_per_host_hour"] = target
    bench["early_warning_matched"] = {m: summarise_alarms(episode_alarms(by["test"], S["test"][m], thr_fa[m], ws, kinds=kinds), ws) for m in MODELS}
    bench["thresholds_matched"] = thr_fa

    # attack-stage mapping of the current window, and next-state likelihood
    st = cat([s.stage for s in by["test"]])
    pred = cat([p.argmax(-1) for p in S["test"]["now"]])
    present = sorted(set(st.tolist()))
    bench["stage_macro_f1"] = float(f1_score(st, pred, labels=present, average="macro"))
    nll_wm, nll_persist = [], []
    diffs = np.concatenate([np.diff(eng.norm.transform(s.X), axis=0) for s in by["train"]])
    sd = diffs.std(0) + 0.05
    dims = np.array([not (f.startswith("p_") and cfg.get("flow_only")) for f in eng.features])
    for s, sur in zip(by["test"], S["test"]["surprise"]):
        nll_wm.append(sur[1:])
        Z = eng.norm.transform(s.X)
        d = (Z[1:] - Z[:-1]) / sd
        nll_persist.append((0.5 * d ** 2 + np.log(sd) + 0.5 * np.log(2 * np.pi))[:, dims].mean(1))
    bench["next_state_nll"] = {"world_model": float(np.mean(np.concatenate(nll_wm))),
                               "persistence_baseline": float(np.mean(np.concatenate(nll_persist)))}

    # unseen attack family (held out of training): recall and surprise
    if by.get("unseen"):
        yu, eu = Y["unseen"]
        un = {}
        for m in MODELS:
            un[m] = binary(cat(yu), cat(S["unseen"][m]), thr[("all", m)])
        ex = [s.stage == 5 for s in by["unseen"]]
        ben = [s.stage == 0 for s in by["unseen"]]
        pct = eng.surprise_pct(cat(S["unseen"]["surprise"], ex))
        pct_b = eng.surprise_pct(cat(S["unseen"]["surprise"], ben))
        un["exfil_windows_flagged"] = {m: float((cat(S["unseen"][m], ex) >= thr[("all", m)]).mean()) for m in MODELS}
        un["surprise_pct_exfil_median"] = float(np.median(pct)) if len(pct) else 0.0
        un["surprise_pct_benign_median"] = float(np.median(pct_b)) if len(pct_b) else 0.0
        un["early_warning"] = {m: summarise_alarms(episode_alarms(by["unseen"], S["unseen"][m], thr[("early", m)], ws, kinds=kinds), ws) for m in MODELS}
        bench["unseen"] = un

    if args.sweep:
        bench["slow_scan"] = slow_scan(eng, Path(args.sweep), thr_fa, args.samples)

    Path(args.art, "benchmark.json").write_text(json.dumps(bench, indent=1))
    print(markdown(bench))


def fa_threshold(seqs, probs, target, ws, kinds):
    """Lowest threshold whose false alarms per host-hour stay within target."""
    cands = np.unique(np.quantile(np.concatenate(probs), np.linspace(0.5, 0.99999, 160)))
    for c in cands:
        if summarise_alarms(episode_alarms(seqs, probs, c, ws, kinds=kinds), ws)["false_alarms_per_host_hour"] <= target:
            return float(c)
    return float(cands[-1])


def slow_scan(eng, path, thr, samples):
    seqs, _, eps = load_dataset(path)
    gap = dict(zip(eps.source, eps.probe_gap_s))
    sc = scores(eng, seqs, samples)
    fi = eng.fidx["f_uniq_lport_in"]
    # classic per-window threshold detector: >= 20 distinct ports probed in one window
    sc["threshold_detector"] = [(s.X[:, fi] >= 20).astype(float) for s in seqs]
    rows = []
    for g in sorted(set(gap.values())):
        idx = [i for i, s in enumerate(seqs) if gap[s.source] == g]
        sub = [seqs[i] for i in idx]
        row = {"probe_gap_s": g}
        for m in (*MODELS, "threshold_detector"):
            t = 0.5 if m == "threshold_detector" else thr[m]
            res = episode_alarms(sub, [sc[m][i] for i in idx], t, eng.cfg["window_s"])
            row[m] = summarise_alarms(res)["warned_frac"]
        rows.append(row)
    return rows


def markdown(b):
    L = [f"Dataset: {b['dataset']} · window {b['window_s']} s · horizon K={b['horizon_k']}", ""]
    for task, title in (("all", "Infiltration within K windows (every window)"), ("early", "Before compromise only (early warning)")):
        L += [f"**{title}**", "", "| Model | F1 | Precision | Recall | FPR | PR-AUC |", "|---|---|---|---|---|---|"]
        for m in MODELS:
            r = b["tasks"][task][m]
            L.append(f"| {b['models'][m]} | {r['f1']:.3f} | {r['precision']:.3f} | {r['recall']:.3f} | {r['fpr']:.4f} | {r['pr_auc']:.3f} |")
        L.append("")
    L += ["**Early warning (test episodes; alarm on the victim within 10 min before compromise)**", "",
          "| Model | Warned before compromise | Median lead (min) | False alarms / host-hour | Benign episodes with an alarm |", "|---|---|---|---|---|"]
    for m in MODELS:
        r = b["early_warning"][m]
        L.append(f"| {b['models'][m]} | {r['warned_before_compromise']}/{r['attack_episodes']} | {r['median_lead_min']:.1f} | {r['false_alarms_per_host_hour']:.3f} | {r['false_alarm_episodes']}/{r['benign_episodes']} |")
    if "early_warning_matched" in b:
        L += ["", f"**Same comparison at an equal false-alarm budget ({b['false_alarm_budget_per_host_hour']:.3f} per host-hour, set on validation)**", "",
              "| Model | Warned before compromise | Median lead (min) | False alarms / host-hour (test) |", "|---|---|---|---|"]
        for m in MODELS:
            r = b["early_warning_matched"][m]
            L.append(f"| {b['models'][m]} | {r['warned_before_compromise']}/{r['attack_episodes']} | {r['median_lead_min']:.1f} | {r['false_alarms_per_host_hour']:.3f} |")
    L += ["", f"Stage macro-F1 (current window): {b['stage_macro_f1']:.3f}",
          f"Next-state NLL: world model {b['next_state_nll']['world_model']:.3f} vs persistence {b['next_state_nll']['persistence_baseline']:.3f}"]
    if "unseen" in b:
        u = b["unseen"]
        L += ["", "**Unseen attack family (DNS-tunnel exfiltration, never in training)**",
              f"Exfil windows flagged: " + ", ".join(f"{b['models'][m]} {100 * u['exfil_windows_flagged'][m]:.0f}%" for m in MODELS),
              f"Surprise percentile on exfil windows: {u['surprise_pct_exfil_median']:.0f} (benign {u['surprise_pct_benign_median']:.0f})"]
    if "slow_scan" in b:
        L += ["", "**Slow-scan sweep: share of chains warned before compromise (baselines at TRACE's false-alarm budget)**", "", "| Probe gap (s) | TRACE | LR (S_t) | LR (stacked) | Per-window threshold |", "|---|---|---|---|---|"]
        for r in b["slow_scan"]:
            L.append(f"| {r['probe_gap_s']:g} | {100 * r['trace']:.0f}% | {100 * r['lr_state']:.0f}% | {100 * r['lr_stacked']:.0f}% | {100 * r['threshold_detector']:.0f}% |")
    return "\n".join(L)


if __name__ == "__main__":
    main()
