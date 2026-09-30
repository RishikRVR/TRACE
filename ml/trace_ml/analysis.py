"""Turn one capture (PCAP via the Go extractor, or a CSV flow file) into the
JSON the console renders: per-host forecast timelines, forecast cones, stage
forecasts, ground truth when available, and flagged flows on demand."""

from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from pathlib import Path

import numpy as np
import pandas as pd

from . import data as D
from . import glossary
from .adapters import ADMIN, CIC_COLS, flows_to_windows
from .engine import ACTIONS, STAGE_NAMES, Engine
from .stages import INFILTRATION

ROLES = {
    "10.0.2.10": "Domain controller", "10.0.2.11": "File server", "10.0.2.12": "Web server (public)",
    "10.0.2.20": "Monitoring server", "10.0.2.30": "Backup server", "10.0.2.53": "DNS server", "10.0.1.5": "Admin workstation",
    "192.168.10.50": "Web server (public)", "192.168.10.51": "Ubuntu server", "192.168.10.3": "Domain controller / DNS",
}
INF = sorted(int(s) for s in INFILTRATION)


def role(ip: str) -> str:
    if ip in ROLES:
        return ROLES[ip]
    if ip.startswith("10.0.1.") or ip.startswith("192.168.10."):
        return "Workstation"
    return "Host"


def r3(a) -> list:
    return np.round(np.asarray(a, dtype=np.float64), 3).tolist()


def extract_pcap(extractor: Path, pcap: Path, out: Path) -> dict:
    res = subprocess.run(
        [str(extractor), "-pcap", str(pcap), "-out", str(out), "-window", "30s", "-internal", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(res.stdout)


def read_cic_csv(path: Path, internal: str = "192.168.10.0/24") -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """A CIC-IDS2017-format CSV -> (windows, labels, flows)."""
    df = pd.read_csv(path, usecols=list(CIC_COLS), engine="pyarrow").rename(columns=CIC_COLS)
    df["ts"] = pd.to_datetime(df.ts).astype("int64") // 1_000_000
    df = df.dropna(subset=["src", "dst"])
    nets = [ipaddress.ip_network(n) for n in internal.split(",")]
    w, lab = flows_to_windows(df, path.stem, 30, nets)
    state = np.where(df.rst_f + df.rst_b > 0, "RST", np.where(df.bp == 0, "S0", np.where(df.fin > 0, "FIN", "EST")))
    flows = pd.DataFrame({
        "first_seen": df.ts, "src_ip": df.src, "src_port": df.sport, "dst_ip": df.dst, "dst_port": df.dport,
        "proto": df.proto.map({6: "TCP", 17: "UDP", 1: "ICMP"}).fillna("OTHER"), "pkts_fwd": df.fp, "pkts_bwd": df.bp,
        "bytes_fwd": df.fb, "bytes_bwd": df.bb, "tcp_state_final": state, "ttl_mean_bwd": np.nan, "label": df.label,
    })
    w["schema_version"], w["window_s"], w["has_packet_level"] = 1, 30, 0
    return w, lab, flows


def build(engine: Engine, windows: pd.DataFrame, flows: pd.DataFrame | None, *, name: str, aid: str,
          timeline: pd.DataFrame | None = None, labels: pd.DataFrame | None = None, extraction: dict | None = None,
          dataset: str = "", samples: int | None = None) -> tuple[dict, dict]:
    """Returns (analysis JSON, context kept server-side for explain/what-if)."""
    t_start = time.time()
    feats = engine.features
    for f in feats:
        if f not in windows:
            windows[f] = 0.0
    row_stage = None
    if labels is not None:
        key = windows[["source", "host", "window_start"]].merge(labels, how="left", on=["source", "host", "window_start"])
        row_stage = key["stage"].fillna(0).astype(int)
    seqs = D.build_sequences(windows, feats, intervals=timeline, row_stage=row_stage, min_present=1)
    t0 = min(s.t0 for s in seqs)
    wms = seqs[0].window_ms
    T = max((s.t0 - t0) // wms + s.T for s in seqs)
    main = [s for s in seqs if s.present.sum() >= 5]
    others = sorted(s.host for s in seqs if s.present.sum() < 5)
    if samples is None:
        samples = 100 if T <= 400 else 48
    fc = engine.forecast(main, samples=samples)
    truth_known = timeline is not None or labels is not None
    thr = float(engine.cfg.get("thresholds", {}).get("trace", engine.threshold))
    hosts = []
    net = np.zeros(T)
    net_lr = np.zeros(T)
    for s, f in zip(main, fc):
        off = (s.t0 - t0) // wms
        lr = engine.lr_proba(s, "lr_state")
        stage_max = f.stage.max(1)  # (T, stages): chance of each stage within the horizon
        eta = np.where((f.stage >= 0.25).any(1), (f.stage >= 0.25).argmax(1) + 1, 0)  # first imagined step above 25%
        net[off : off + s.T] = np.maximum(net[off : off + s.T], f.p)
        if lr is not None:
            net_lr[off : off + s.T] = np.maximum(net_lr[off : off + s.T], lr)
        hosts.append({
            "host": s.host, "role": role(s.host), "off": int(off), "T": int(s.T), "p": r3(f.p),
            "lr": r3(lr) if lr is not None else None, "cone": r3(f.cone), "stage_max": r3(stage_max), "eta": eta.tolist(),
            "now": r3(f.now_stage), "surprise": r3(engine.surprise_pct(f.surprise)), "present": s.present.astype(int).tolist(),
            "truth": s.stage.tolist() if truth_known else None, "peak": float(f.p.max()),
            "first_alarm": int(np.flatnonzero(f.p >= thr)[0]) if (f.p >= thr).any() else None,
            "first_inf": int(D.first_infiltration(s.stage)) if truth_known and D.first_infiltration(s.stage) < s.T else None,
        })
    hosts.sort(key=lambda h: -h["peak"])
    alarm = int(np.flatnonzero(net >= thr)[0]) if (net >= thr).any() else None
    comp = None
    if truth_known:
        cands = [h["off"] + h["first_inf"] for h in hosts if h["first_inf"] is not None]
        comp = min(cands) if cands else None
    lr_thr = float(engine.cfg.get("thresholds", {}).get("lr_state", 0.5))
    lr_alarm = int(np.flatnonzero(net_lr >= lr_thr)[0]) if (net_lr >= lr_thr).any() else None
    out = {
        "id": aid, "name": name, "dataset": dataset, "t0": int(t0), "window_s": wms // 1000, "T": int(T), "k": engine.k,
        "threshold": thr, "lr_threshold": lr_thr, "packet_level": bool(main[0].has_packet) if main else False,
        "hosts": hosts, "other_addresses": others, "network": {"p": r3(net), "lr": r3(net_lr)},
        "events": {"alarm": alarm, "lr_alarm": lr_alarm, "compromise": comp,
                   "lead_min": (comp - alarm) * wms / 60000 if alarm is not None and comp is not None and alarm < comp else None},
        "extraction": extraction, "truth_known": truth_known, "stages": STAGE_NAMES, "samples": samples,
        "analysis_seconds": round(time.time() - t_start, 2),
    }
    ctx = {"seqs": {s.host: s for s in main}, "flows": flows, "t0": t0, "wms": wms}
    return out, ctx


FLAG_RULES = [
    # (feature group, predicate(df, host) -> mask, reason)
    ("scan_in", lambda f, h: (f.dst_ip == h) & (f.pkts_fwd <= 3) & f.tcp_state_final.isin(["RST", "S0"]), "Probe to port {dst_port} (refused or unanswered)"),
    ("admin_in", lambda f, h: (f.dst_ip == h) & f.dst_port.isin(ADMIN), "Connection to admin port {dst_port} from {src_ip}"),
    ("admin_out", lambda f, h: (f.src_ip == h) & f.dst_port.isin(ADMIN) & f.dst_ip.str.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"), "East-west connection to admin port {dst_port}"),
    ("fail_out", lambda f, h: (f.src_ip == h) & f.tcp_state_final.isin(["S0", "RST"]), "Failed outbound connection to {dst_ip}:{dst_port}"),
    ("bulk_out", lambda f, h: (f.src_ip == h) & (f.bytes_fwd >= 500_000), "Large upload: {mb:.1f} MB to {dst_ip}"),
    ("dns", lambda f, h: (f.src_ip == h) & (f.dst_port == 53), "DNS query to {dst_ip}"),
    ("beacon", lambda f, h: (f.src_ip == h) & ~f.dst_ip.str.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)") & f.dst_ip.duplicated(keep=False), "Repeated connections to {dst_ip}:{dst_port} (beacon-like)"),
]
GROUP_RULES = {
    "Port scanning": ["scan_in", "fail_out"], "Failed connections": ["fail_out", "scan_in"],
    "Admin ports / east-west": ["admin_in", "admin_out"], "Traffic volume": ["bulk_out", "beacon"],
    "Timing and beaconing": ["beacon"], "DNS behaviour": ["dns"], "Packet fingerprint (TTL, TCP window)": ["scan_in", "admin_in"],
    "Payload and flags": ["beacon", "bulk_out", "admin_in"],
}


def flagged_flows(ctx: dict, host: str, t: int, groups: list[dict], history: int, limit: int = 30) -> list[dict]:
    flows = ctx["flows"]
    s = ctx["seqs"][host]
    if flows is None or not len(flows):
        return []
    a_ms = s.t0 + max(0, t - history + 1) * s.window_ms
    b_ms = s.t0 + (t + 1) * s.window_ms
    f = flows[(flows.first_seen >= a_ms) & (flows.first_seen < b_ms) & ((flows.src_ip == host) | (flows.dst_ip == host))]
    if not len(f):
        return []
    weight = {}
    for g in groups:
        for rule in GROUP_RULES.get(g["group"], []):
            weight[rule] = max(weight.get(rule, 0.0), g["delta"])
    rows = []
    seen = set()
    for rule, pred, why in sorted(FLAG_RULES, key=lambda r: -weight.get(r[0], 0.0)):
        w = weight.get(rule, 0.0)
        if w <= 0.005:
            continue
        hit = f[pred(f, host)]
        # the same peer behind many of these flows is what makes them suspicious
        per_peer = hit.groupby(np.where(hit.src_ip == host, hit.dst_ip, hit.src_ip)).size()
        hit = hit.assign(peer_n=np.where(hit.src_ip == host, hit.dst_ip, hit.src_ip))
        hit = hit.assign(peer_n=hit.peer_n.map(per_peer)).sort_values(["peer_n", "first_seen"], ascending=[False, False])
        for r in hit.head(limit).itertuples():
            k = (r.first_seen, r.src_ip, r.src_port, r.dst_ip, r.dst_port)
            if k in seen:
                continue
            seen.add(k)
            rows.append({
                "time": int(r.first_seen), "src": f"{r.src_ip}:{r.src_port}", "dst": f"{r.dst_ip}:{r.dst_port}", "proto": r.proto,
                "pkts": int(r.pkts_fwd + r.pkts_bwd), "bytes": int(r.bytes_fwd + r.bytes_bwd), "state": r.tcp_state_final,
                "ttl": None if pd.isna(getattr(r, "ttl_mean_bwd", np.nan)) else round(float(r.ttl_mean_bwd), 1),
                "why": why.format(dst_port=r.dst_port, src_ip=r.src_ip, dst_ip=r.dst_ip, mb=r.bytes_fwd / 1e6) + (f" · {r.peer_n} such flows with this peer" if r.peer_n > 2 else ""),
                "weight": w + 0.001 * min(r.peer_n, 50),
            })
    rows.sort(key=lambda r: (-r["weight"], -r["time"]))
    return rows[:limit]


def recommend(p: float, groups: list[dict]) -> dict:
    """Map the risk band (from the deck: <40 monitor, 40-70 restrict, 70-90
    isolate, >90 block) and the top driver to an action. A forecast alone
    never acts: the analyst approves."""
    band = "Low" if p < 0.4 else "Medium" if p < 0.7 else "High" if p < 0.9 else "Critical"
    top = groups[0]["group"] if groups and groups[0]["delta"] > 0.01 else ""
    if band == "Low":
        action = None
    elif top in ("Port scanning", "Packet fingerprint (TTL, TCP window)"):
        action = "block_scanner"
    elif top in ("Admin ports / east-west", "Failed connections"):
        action = "block_admin"
    elif top in ("Traffic volume", "DNS behaviour", "Timing and beaconing"):
        action = "rate_limit"
    else:
        action = "isolate"
    if band in ("High", "Critical") and top in ("Admin ports / east-west",):
        action = "isolate"
    return {"band": band, "action": action, "label": ACTIONS[action]["label"] if action else "Keep monitoring"}


KEY_FEATURES = ["f_uniq_lport_in", "f_admin_conn_in", "f_admin_conn_out", "f_conn_fail_out", "f_bytes_out", "f_dns_queries_out"]


def pick_imagined(explanation: dict, packet: bool) -> list[str]:
    feats = [f["feature"] for f in explanation["features"] if f["delta"] > 0.005 and (packet or f["feature"].startswith("f_"))]
    out = [f for f in feats if f.startswith("f_")][:3]
    for f in KEY_FEATURES:
        if len(out) >= 3:
            break
        if f not in out:
            out.append(f)
    return out


def glossary_json() -> dict:
    return {k: {"label": v[0], "description": v[1], "unit": v[2], "level": glossary.level(k), "group": glossary.group_of(k)}
            for k, v in glossary.FEATURES.items()}
