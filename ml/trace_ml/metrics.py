"""Benchmark metrics (docs/decisions.md #5): F1, precision, recall, FPR at a
threshold fixed on validation, plus PR-AUC and Brier."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, brier_score_loss


def binary(y: np.ndarray, p: np.ndarray, thr: float) -> dict:
    y = y.astype(bool)
    pred = p >= thr
    tp = int((pred & y).sum())
    fp = int((pred & ~y).sum())
    fn = int((~pred & y).sum())
    tn = int((~pred & ~y).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {
        "f1": f1, "precision": prec, "recall": rec, "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "pr_auc": float(average_precision_score(y, p)) if y.any() else 0.0,
        "brier": float(brier_score_loss(y, np.clip(p, 0, 1))), "threshold": float(thr), "n": int(len(y)), "positives": int(y.sum()),
    }


def best_threshold(y: np.ndarray, p: np.ndarray) -> float:
    """Threshold maximising F1 (chosen on validation, then frozen for test)."""
    cands = np.unique(np.quantile(p, np.linspace(0.5, 0.999, 300)))
    best, thr = -1.0, 0.5
    for c in cands:
        f = binary(y, p, c)["f1"]
        if f > best:
            best, thr = f, float(c)
    return thr
