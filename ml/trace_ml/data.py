"""Load extractor output into per-host sequences, attach stage labels, normalise.

A host sequence is dense: one row per window from the host's first to last
seen window, with windows that carried no traffic filled with zeros
(docs/feature-schema-v1.md, "Only non-empty windows are written").
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from .stages import INFILTRATION, Stage

KEY_COLUMNS = ["schema_version", "source", "host", "window_start", "window_s", "has_packet_level"]

# When a window overlaps several annotated intervals, the rarer, more
# decisive activity wins: a host that beacons (C2) while it moves laterally is
# labelled Lateral Movement for that window.
PRECEDENCE = [
    Stage.EXFILTRATION,
    Stage.LATERAL_MOVEMENT,
    Stage.INITIAL_ACCESS,
    Stage.COMMAND_AND_CONTROL,
    Stage.IMPACT,
    Stage.RECONNAISSANCE,
]
_RANK = {int(s): i for i, s in enumerate(PRECEDENCE)}
INFIL_CODES = np.array(sorted(int(s) for s in INFILTRATION))


def load_schema(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())


def read_windows(path: str | Path) -> pd.DataFrame:
    return pd.read_csv(path, engine="pyarrow")


@dataclass
class HostSeq:
    source: str
    host: str
    t0: int  # first window_start, Unix ms
    window_ms: int
    X: np.ndarray  # (T, D) raw feature values, zeros where no traffic
    present: np.ndarray  # (T,) window had traffic
    stage: np.ndarray  # (T,) int stage codes
    has_packet: bool = True
    meta: dict = field(default_factory=dict)

    @property
    def T(self) -> int:
        return len(self.stage)

    def times(self) -> np.ndarray:
        return self.t0 + np.arange(self.T, dtype=np.int64) * self.window_ms


def label_windows(intervals: pd.DataFrame, host: str, t0: int, T: int, window_ms: int) -> np.ndarray:
    """Stage per window from annotated (host, stage, start_ms, end_ms) intervals."""
    stage = np.zeros(T, dtype=np.int64)
    rank = np.full(T, len(PRECEDENCE), dtype=np.int64)
    for iv in intervals[intervals.host == host].itertuples():
        a = max(0, int((iv.start_ms - t0) // window_ms))
        # The end is exclusive: an interval finishing exactly on a window
        # boundary belongs to the window before it, not the one it touches for
        # a single instant.
        b = min(T - 1, int((max(iv.start_ms, iv.end_ms - 1) - t0) // window_ms))
        if b < a:
            continue
        r = _RANK.get(int(iv.stage), len(PRECEDENCE))
        seg = slice(a, b + 1)
        better = r < rank[seg]
        stage[seg] = np.where(better, int(iv.stage), stage[seg])
        rank[seg] = np.where(better, r, rank[seg])
    return stage


def build_sequences(
    windows: pd.DataFrame,
    features: list[str],
    intervals: pd.DataFrame | None = None,
    row_stage: pd.Series | None = None,
    min_present: int = 1,
    span: dict[str, tuple[int, int]] | None = None,
) -> list[HostSeq]:
    """Group window rows into dense host sequences.

    Labels come either from annotated intervals (simulator timelines, attack
    schedules) or from a per-row stage column (flow-labelled CSV datasets).
    span optionally fixes each source's (first, last) window so every host of a
    capture shares one clock.
    """
    out: list[HostSeq] = []
    wms = int(windows.window_s.iloc[0]) * 1000
    if row_stage is not None:
        windows = windows.assign(_stage=row_stage.values)
    for (source, host), g in windows.groupby(["source", "host"], sort=True):
        g = g.sort_values("window_start")
        t0 = int(g.window_start.iloc[0])
        t1 = int(g.window_start.iloc[-1])
        T = (t1 - t0) // wms + 1
        idx = ((g.window_start.values - t0) // wms).astype(np.int64)
        X = np.zeros((T, len(features)), dtype=np.float32)
        X[idx] = g[features].to_numpy(dtype=np.float32)
        present = np.zeros(T, dtype=bool)
        present[idx] = True
        if int(present.sum()) < min_present:
            continue
        if row_stage is not None:
            stage = np.zeros(T, dtype=np.int64)
            stage[idx] = g["_stage"].to_numpy(dtype=np.int64)
        elif intervals is not None:
            stage = label_windows(intervals[intervals.source == source], host, t0, T, wms)
        else:
            stage = np.zeros(T, dtype=np.int64)
        out.append(
            HostSeq(
                source=str(source), host=str(host), t0=t0, window_ms=wms, X=X, present=present, stage=stage,
                has_packet=bool(g.has_packet_level.iloc[0]),
            )
        )
    return out


def infiltration_within(stage: np.ndarray, k: int) -> np.ndarray:
    """y[t] = 1 if any of stage[t+1 .. t+k] is an infiltration stage."""
    inf = np.isin(stage, INFIL_CODES).astype(np.int8)
    T = len(stage)
    y = np.zeros(T, dtype=np.int8)
    # suffix trick: count of infiltration windows in (t, t+k]
    c = np.concatenate([[0], np.cumsum(inf)])
    for t in range(T):
        hi = min(T, t + k + 1)
        y[t] = 1 if c[hi] - c[t + 1] > 0 else 0
    return y


def first_infiltration(stage: np.ndarray) -> int:
    """Index of the first infiltration window, or len(stage) if none."""
    hits = np.flatnonzero(np.isin(stage, INFIL_CODES))
    return int(hits[0]) if len(hits) else len(stage)


# --- normalisation (docs/feature-schema-v1.md "Normalisation") --------------


def feature_kind(name: str) -> str:
    if name == "f_bytes_ratio":
        return "ratio"
    if name.endswith("_frac") or name.startswith("p_payload_bin_") or "entropy" in name or name.endswith("_frac_out") or name.endswith("_frac_in"):
        return "frac"
    return "count"


@dataclass
class Normaliser:
    features: list[str]
    kinds: list[str]
    mean: np.ndarray
    std: np.ndarray

    @classmethod
    def fit(cls, seqs: list[HostSeq], features: list[str]) -> "Normaliser":
        kinds = [feature_kind(f) for f in features]
        X = np.concatenate([s.X for s in seqs], axis=0)
        Z = _pre(X, kinds)
        mean = Z.mean(axis=0)
        std = Z.std(axis=0)
        std[std < 1e-6] = 1.0
        frac = np.array([k == "frac" for k in kinds])
        mean[frac], std[frac] = 0.0, 1.0  # fractions and entropies stay as they are
        return cls(features, kinds, mean.astype(np.float32), std.astype(np.float32))

    def transform(self, X: np.ndarray) -> np.ndarray:
        return ((_pre(X, self.kinds) - self.mean) / self.std).astype(np.float32)

    def inverse(self, Z: np.ndarray) -> np.ndarray:
        """Back to raw units (for showing imagined future states)."""
        P = Z * self.std + self.mean
        out = P.copy()
        for i, k in enumerate(self.kinds):
            if k == "count":
                out[..., i] = np.expm1(np.clip(P[..., i], 0, 30))
            elif k == "ratio":
                out[..., i] = np.exp(np.clip(P[..., i], -30, 30))
        return out

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps({"features": self.features, "kinds": self.kinds, "mean": self.mean.tolist(), "std": self.std.tolist()})
        )

    @classmethod
    def load(cls, path: str | Path) -> "Normaliser":
        d = json.loads(Path(path).read_text())
        return cls(d["features"], d["kinds"], np.array(d["mean"], dtype=np.float32), np.array(d["std"], dtype=np.float32))


def _pre(X: np.ndarray, kinds: list[str]) -> np.ndarray:
    Z = X.astype(np.float64).copy()
    for i, k in enumerate(kinds):
        if k == "count":
            Z[..., i] = np.log1p(np.maximum(Z[..., i], 0))
        elif k == "ratio":
            Z[..., i] = np.log(np.maximum(Z[..., i], 1e-6))
    return Z
