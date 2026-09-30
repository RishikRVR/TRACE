"""Live mode: keep each host's world-model state and forecast as windows arrive.

A sensor (extractor/cmd/trace-sensor) posts one batch per closed window. For
each host this advances the recurrent state by a single step and rolls out
from there, so the cost per window is independent of how long the sensor has
been running. Raw feature rows are kept in a bounded ring so the existing
explanation, what-if and flagged-flow code can rebuild a HostSeq on demand.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
import torch

from . import analysis as A
from .data import HostSeq
from .engine import Engine

HISTORY_WINDOWS = 240
IDLE_WINDOWS = 20        # stop carrying a host silent this many windows (10 min at 30 s)
MAX_FLOWS = 20000


@dataclass
class HostState:
    host: str
    window_ms: int
    t0: int  # window_start of the oldest row still held
    rows: deque = field(default_factory=lambda: deque(maxlen=HISTORY_WINDOWS))
    starts: deque = field(default_factory=lambda: deque(maxlen=HISTORY_WINDOWS))
    p: deque = field(default_factory=lambda: deque(maxlen=HISTORY_WINDOWS))
    cone: deque = field(default_factory=lambda: deque(maxlen=HISTORY_WINDOWS))
    stage_max: deque = field(default_factory=lambda: deque(maxlen=HISTORY_WINDOWS))
    eta: deque = field(default_factory=lambda: deque(maxlen=HISTORY_WINDOWS))
    now_stage: deque = field(default_factory=lambda: deque(maxlen=HISTORY_WINDOWS))
    surprise: deque = field(default_factory=lambda: deque(maxlen=HISTORY_WINDOWS))
    h: torch.Tensor | None = None  # recurrent state after the latest window
    last_active: int = 0           # window_start of the last window with traffic
    first_alarm: int | None = None  # index into starts
    last_seen: float = 0.0

    def seq(self, engine: Engine) -> HostSeq:
        """Rebuild a HostSeq over the retained history, for explain/what-if."""
        X = np.asarray(self.rows, dtype=np.float32)
        return HostSeq(source="live", host=self.host, t0=int(self.starts[0]), window_ms=self.window_ms,
                       X=X, present=np.ones(len(X), dtype=bool), stage=np.zeros(len(X), dtype=np.int64))


class LiveMonitor:
    """Holds live state for one console. Thread-safe: the ingest endpoint and
    the UI read it from different request threads."""

    def __init__(self, engine: Engine, ledger, on_alarm=None, rollouts: int = 64):
        self.engine = engine
        self.ledger = ledger
        self.on_alarm = on_alarm
        self.rollouts = rollouts
        self.hosts: dict[str, HostState] = {}
        self.flows = deque(maxlen=MAX_FLOWS)
        self.sensors: dict[str, dict] = {}
        self.window_s = engine.cfg["window_s"]
        self.started = time.time()
        self.batches = 0
        self.windows_done = 0
        self.lag = 0
        self.lock = threading.RLock()
        self.queue: deque = deque()
        self.wake = threading.Event()
        self.worker = threading.Thread(target=self._run, daemon=True, name="trace-live")
        self.worker.start()

    # --- ingest -------------------------------------------------------------

    def ingest(self, batch: dict) -> dict:
        """Accept a sensor batch and return at once. Model work happens on the
        worker thread, so a slow forecast can never stall the sensor."""
        name = batch.get("sensor", "sensor")
        with self.lock:
            self.batches += 1
            self.sensors[name] = {"name": name, "last_seen": time.time(),
                                  "window_s": batch.get("window_s", self.window_s), **(batch.get("stats") or {})}
            for f in batch.get("flows") or []:
                self.flows.append(f)
            self.queue.append(batch.get("rows") or [])
            self.lag = sum(len(r) for r in self.queue)
        self.wake.set()
        return {"queued": len(batch.get("rows") or []), "lag_rows": self.lag, "hosts": len(self.hosts)}

    def _run(self) -> None:
        while True:
            self.wake.wait(timeout=1.0)
            self.wake.clear()
            while True:
                with self.lock:
                    if not self.queue:
                        break
                    rows = self.queue.popleft()
                try:
                    self._process(rows)
                except Exception as e:  # a bad batch must not kill the monitor
                    print(f"trace-live: dropped a batch: {e}", flush=True)

    def _process(self, rows: list[dict]) -> None:
        by_window: dict[int, list[dict]] = {}
        for r in rows:
            by_window.setdefault(int(r["window_start"]), []).append(r)
        alarms = []
        for ws in sorted(by_window):
            alarms += self._step_window(ws, by_window[ws])
        for a in alarms:
            self._record_alarm(a)

    @torch.no_grad()
    def _step_window(self, window_start: int, rows: list[dict]) -> list[dict]:
        """Advance every tracked host by one window, in a single batch.

        Hosts with no traffic this window are stepped on a zero vector rather
        than skipped. That matters twice over: it keeps each host's arrays
        dense, so window *n* of a host is always window *n* of the timeline,
        and it feeds the silence to the world model — a host going quiet is
        itself information. A host silent for IDLE_WINDOWS stops being carried.
        """
        from .model import mdn_nll

        eng, H = self.engine, self.engine.model.hidden
        wms = self.window_s * 1000
        d = len(eng.features)
        seen = {r["host"]: np.asarray(r["values"], dtype=np.float32) for r in rows}
        states, X = [], []
        with self.lock:
            for host, values in seen.items():
                st = self.hosts.get(host)
                if st is None:
                    st = HostState(host=host, window_ms=wms, t0=window_start)
                    self.hosts[host] = st
                st.last_active = window_start
                states.append(st)
                X.append(values)
            # carry the quiet ones along on an empty window
            for host, st in self.hosts.items():
                if host in seen or not st.starts:
                    continue
                if st.starts[-1] >= window_start:      # already past this window
                    continue
                if window_start - st.last_active > IDLE_WINDOWS * wms:
                    continue
                states.append(st)
                X.append(np.zeros(d, dtype=np.float32))
        if not states:
            return []
        raw = np.stack(X)
        z = torch.from_numpy(eng.norm.transform(raw))           # (n, d)
        pm = torch.ones(len(states), 1)
        h_prev = torch.stack([st.h[0] if st.h is not None else torch.zeros(H) for st in states])

        lp, mu, ls = eng.model.mdn_params(h_prev)
        nll = mdn_nll(lp, mu, ls, z, torch.ones_like(z)).numpy()
        h = eng.model.step(z, pm, h_prev)                        # (n, H)
        ps, cum, _ = eng._roll(h, pm, self.rollouts)             # (n, S, K, ...)
        p = eng.calibrate(cum[:, :, -1].mean(1).numpy())
        q = eng.calibrate(torch.quantile(cum, torch.tensor([0.1, 0.5, 0.9]), dim=1).permute(1, 2, 0).numpy())
        stage = ps.mean(1).numpy()                               # (n, K, stages)
        now = eng.model.stage_probs(h).numpy()

        alarms = []
        with self.lock:
            for i, st in enumerate(states):
                st.surprise.append(0.0 if st.h is None else float(nll[i]))
                st.h = h[i: i + 1]
                st.rows.append(raw[i])
                st.starts.append(window_start)
                st.p.append(float(p[i]))
                st.cone.append(q[i])
                st.stage_max.append(stage[i].max(0))
                st.eta.append(np.where((stage[i] >= 0.25).any(0), (stage[i] >= 0.25).argmax(0) + 1, 0))
                st.now_stage.append(now[i])
                st.last_seen = time.time()
                if float(p[i]) >= eng.threshold:
                    if st.first_alarm is None:
                        st.first_alarm = len(st.starts) - 1
                        nxt = int(np.argmax(stage[i].max(0)[1:])) + 1
                        alarms.append({"host": st.host, "window": window_start, "p": round(float(p[i]), 3),
                                       "predicted_stage": A.STAGE_NAMES.get(nxt, str(nxt)), "stage_code": nxt})
                elif st.first_alarm is not None and float(p[i]) < eng.threshold * 0.5:
                    st.first_alarm = None  # re-arm once the host is clearly calm again
            self.windows_done += 1
            self.lag = sum(len(r) for r in self.queue)
        return alarms

    def _record_alarm(self, a: dict) -> None:
        self.ledger.append("forecast", analysis="live", host=a["host"], window=a["window"], p=a["p"],
                           predicted_stage=a["predicted_stage"], model=getattr(self.engine, "weights_sha256", "")[:16])
        if self.on_alarm:
            self.on_alarm(a)

    # --- read-out -----------------------------------------------------------

    def state(self, host_limit: int = 40, since: int | None = None, detail: str | None = None) -> dict:
        """The console's view of live state.

        `since` returns only windows at or after that absolute index, so a fast
        refresh stays small; each host carries `from`, the absolute index its
        arrays start at. `detail` is the host whose forecast cone is included —
        the cone is by far the largest field and only one host's is ever drawn.
        """
        eng = self.engine
        with self.lock:
            if not self.hosts:
                return {"live": True, "hosts": [], "T": 0, "sensors": list(self.sensors.values()),
                        "window_s": self.window_s, "threshold": eng.threshold, "k": eng.k, "batches": self.batches,
                        "stages": A.STAGE_NAMES, "t0": int(time.time() * 1000), "since": since, "full": since is None}
            t0 = min(st.starts[0] for st in self.hosts.values())
            wms = self.window_s * 1000
            T = int((max(st.starts[-1] for st in self.hosts.values()) - t0) // wms) + 1
            # Selected by peak risk, which only ever rises, then ordered by
            # name: the membership and the order both stay put between polls,
            # so a delta lines up with what the client already holds. The
            # client re-sorts by current risk for display.
            ranked = sorted(self.hosts.values(), key=lambda st: -max(st.p, default=0))[:host_limit]
            ranked.sort(key=lambda st: st.host)
            if detail is None and ranked:
                detail = ranked[0].host
            out = []
            for st in ranked:
                off = int((st.starts[0] - t0) // wms)
                n = len(st.starts)
                a = 0 if since is None else max(0, min(n, since - off))
                cut = lambda seq: list(seq)[a:]
                out.append({
                    "host": st.host, "role": A.role(st.host), "off": off, "T": n, "from": off + a,
                    "p": A.r3(cut(st.p)), "lr": None,
                    "cone": A.r3(np.asarray(cut(st.cone))) if st.host == detail and a < n else None,
                    "stage_max": A.r3(np.asarray(cut(st.stage_max))) if a < n else [],
                    "eta": np.asarray(cut(st.eta)).tolist() if a < n else [],
                    "now": A.r3(np.asarray(cut(st.now_stage))) if a < n else [],
                    "surprise": A.r3(eng.surprise_pct(np.asarray(cut(st.surprise)))) if a < n else [],
                    "present": [1] * (n - a), "truth": None, "peak": float(max(st.p)),
                    "first_alarm": st.first_alarm, "first_inf": None,
                })
            # Network risk is the maximum over hosts, always computed over the
            # whole timeline even when the response itself is a delta.
            net = np.zeros(T)
            for st in ranked:
                off = int((st.starts[0] - t0) // wms)
                net[off: off + len(st.p)] = np.maximum(net[off: off + len(st.p)], np.asarray(st.p))
            alarm = int(np.flatnonzero(net >= eng.threshold)[0]) if (net >= eng.threshold).any() else None
            return {
                "live": True, "id": "live", "name": "Live capture", "dataset": "live sensor", "t0": int(t0),
                "window_s": self.window_s, "T": T, "k": eng.k, "threshold": eng.threshold, "lr_threshold": 1.0,
                "packet_level": True, "hosts": out, "other_addresses": [], "network": {"p": A.r3(net), "lr": A.r3(net * 0)},
                "events": {"alarm": alarm, "lr_alarm": None, "compromise": None, "lead_min": None},
                "extraction": {"sensors": list(self.sensors.values())}, "truth_known": False,
                "stages": A.STAGE_NAMES, "batches": self.batches, "sensors": list(self.sensors.values()),
                "uptime_s": round(time.time() - self.started, 1), "lag_rows": self.lag, "windows_done": self.windows_done,
                "since": since, "full": since is None, "detail": detail,
            }

    def context(self) -> dict:
        """The shape analysis.flagged_flows expects, over the live flow ring."""
        with self.lock:
            seqs = {h: st.seq(self.engine) for h, st in self.hosts.items() if len(st.rows)}
            flows = pd.DataFrame(list(self.flows)) if self.flows else None
        return {"seqs": seqs, "flows": flows, "t0": 0, "wms": self.window_s * 1000}
