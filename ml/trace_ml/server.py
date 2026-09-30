"""TRACE console backend: serves the offline single-page UI and the models.

    cd ml && .venv/bin/python -m trace_ml.server      # http://127.0.0.1:8000

No cloud calls: the UI's only script dependency (ECharts) is vendored in ui/.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import uuid
from pathlib import Path

import pandas as pd
from fastapi import Body, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import analysis as A
from . import data as D
from .engine import ACTIONS, Engine
from .enforce import Enforcer
from .ledger import Ledger
from .live import LiveMonitor

ROOT = Path(__file__).resolve().parents[2]
ART = ROOT / "artifacts"
UI = ROOT / "ui"
DEMO = ROOT / "data" / "demo"
EXTRACTOR = ROOT / "extractor" / "bin" / "trace-extract"
CACHE = ART / "analyses"
CIC_THURSDAY = ROOT / "data" / "raw" / "cic-ids2017-improved" / "thursday.csv"

SCENARIOS = [
    {"id": "demo-killchain", "name": "Full kill chain", "kind": "pcap", "model": "sim", "file": str(DEMO / "demo-killchain.pcap"),
     "description": "Port scan → SSH brute force → C2 beaconing → SMB lateral movement → HTTPS exfiltration"},
    {"id": "demo-slowscan", "name": "Slow-and-low recon", "kind": "pcap", "model": "sim", "file": str(DEMO / "demo-slowscan.pcap"),
     "description": "A scan spread over ~20 minutes to stay under per-window thresholds, then a web exploit"},
    {"id": "demo-benign", "name": "Quiet office day", "kind": "pcap", "model": "sim", "file": str(DEMO / "demo-benign.pcap"),
     "description": "Normal traffic only, including admin SSH/RDP, backups and a cloud upload: should raise no alarm"},
    {"id": "demo-unseen", "name": "Unseen attack", "kind": "pcap", "model": "sim", "file": str(DEMO / "demo-unseen.pcap"),
     "description": "Phishing → C2 → RDP lateral movement → DNS-tunnel exfiltration (a family never seen in training)"},
    {"id": "cic2017-thursday", "name": "CIC-IDS2017 Thursday (real data)", "kind": "csv", "model": "cic2017", "file": str(CIC_THURSDAY),
     "description": "Public dataset, flow-only: web attacks, then an infiltration and internal port scan. Never trained on"},
]

app = FastAPI(title="TRACE")
ledger = Ledger(ART / "ledger.jsonl")
# Enforcement is dry-run unless TRACE_ENFORCE=1: a firewall rule is only ever
# applied after an analyst approves, and never from a forecast alone.
enforcer = Enforcer(ledger, enforce=os.environ.get("TRACE_ENFORCE") == "1")
live: LiveMonitor | None = None
engines: dict[str, Engine] = {}
analyses: dict[str, dict] = {}
contexts: dict[str, dict] = {}
uploads: dict[str, dict] = {}
_locks: dict[str, threading.Lock] = {}
_glock = threading.RLock()


def engine(name: str) -> Engine:
    with _glock:
        if name not in engines:
            art = ART / name
            if not (art / "model.pt").exists():
                raise HTTPException(503, f"model {name} is not trained yet")
            engines[name] = Engine.load(art)
            engines[name].weights_sha256 = hashlib.sha256((art / "model.pt").read_bytes()).hexdigest()
        return engines[name]


def scenario(aid: str) -> dict:
    for s in SCENARIOS:
        if s["id"] == aid:
            return s
    if aid in uploads:
        return uploads[aid]
    raise HTTPException(404, f"unknown analysis {aid}")


def run_analysis(aid: str) -> dict:
    with _glock:
        lock = _locks.setdefault(aid, threading.Lock())
    with lock:
        if aid in analyses:
            return analyses[aid]
        sc = scenario(aid)
        eng = engine(sc["model"])
        path = Path(sc["file"])
        if not path.exists():
            raise HTTPException(404, f"missing input {path}")
        if sc["kind"] == "pcap":
            out = CACHE / aid / "features"
            summary = A.extract_pcap(EXTRACTOR, path, out)
            windows = D.read_windows(out / "windows.csv")
            flows = pd.read_csv(out / "flows.csv", engine="pyarrow")
            tl_path = path.with_suffix(".timeline.csv")
            timeline = pd.read_csv(tl_path) if tl_path.exists() else None
            if timeline is not None:  # the annotations describe this capture, whatever it is named
                timeline["source"] = windows.source.iloc[0]
            res, ctx = A.build(eng, windows, flows, name=sc["name"], aid=aid, timeline=timeline, extraction=summary,
                               dataset="TRACE simulator (both feature levels)" if sc["model"] == "sim" else "")
        else:
            windows, labels, flows = A.read_cic_csv(path)
            res, ctx = A.build(eng, windows, flows, name=sc["name"], aid=aid, labels=labels,
                               extraction={"flows": int(len(flows)), "window_rows": int(len(windows))},
                               dataset="CIC-IDS2017 corrected release (flow-only)")
        res["model"] = {"name": sc["model"], "weights_sha256": eng.weights_sha256[:16]}
        res["description"] = sc.get("description", "")
        analyses[aid], contexts[aid] = res, ctx
        log_forecasts(res)
        return res


def log_forecasts(res: dict) -> None:
    """Every alarm onset goes into the ledger once, so it can later be shown to
    predate the compromise."""
    done = {(r.get("analysis"), r.get("host")) for r in ledger.records() if r.get("kind") == "forecast"}
    for h in res["hosts"]:
        if h["first_alarm"] is None or (res["id"], h["host"]) in done:
            continue
        t = h["first_alarm"]
        stage_row = h["stage_max"][t]
        nxt = max((s for s in range(1, len(stage_row))), key=lambda s: stage_row[s])
        ledger.append("forecast", analysis=res["id"], host=h["host"], window=int(res["t0"] + (h["off"] + t) * res["window_s"] * 1000),
                      p=h["p"][t], predicted_stage=res["stages"][nxt], model=res["model"]["weights_sha256"])


def warm() -> None:
    for s in SCENARIOS:
        try:
            run_analysis(s["id"])
            print(f"trace: ready {s['id']}", flush=True)
        except Exception as e:  # a missing model or input just leaves that scenario cold
            print(f"trace: skipped {s['id']}: {e}", flush=True)


@app.on_event("startup")
def _startup() -> None:
    threading.Thread(target=warm, daemon=True).start()


@app.get("/")
def index():
    return FileResponse(UI / "index.html")


@app.get("/api/meta")
def meta():
    models = {}
    for name in ("sim", "cic2017"):
        cfg = ART / name / "config.json"
        if cfg.exists():
            c = json.loads(cfg.read_text())
            models[name] = {"horizon_k": c["horizon_k"], "window_s": c["window_s"], "features": len(c["features"]),
                            "flow_only": c.get("flow_only", False), "threshold": c.get("threshold")}
    sc = [{k: v for k, v in s.items() if k != "file"} | {"ready": s["id"] in analyses} for s in SCENARIOS + list(uploads.values())]
    return {"models": models, "scenarios": sc, "glossary": A.glossary_json(),
            "actions": {k: v["label"] for k, v in ACTIONS.items()},
            "enforcement": enforcer.state(), "live": {"sensors": list(live.sensors.values()) if live else [], "active": bool(live and live.hosts)}}


def strip_cones(res: dict, detail: str | None) -> dict:
    """The forecast cone is ~95% of the payload and only the selected host's is
    ever drawn, so ship one host's and let the client fetch others on demand."""
    if detail is None and res["hosts"]:
        detail = res["hosts"][0]["host"]
    hosts = [(h if h["host"] == detail else {**h, "cone": None}) for h in res["hosts"]]
    return {**res, "hosts": hosts, "detail": detail}


@app.get("/api/analysis/{aid}")
def get_analysis(aid: str, detail: str | None = None):
    return strip_cones(run_analysis(aid), detail)


@app.get("/api/cone/{aid}/{host}")
def get_cone(aid: str, host: str):
    """One host's forecast cone, fetched when the analyst selects that host."""
    res = live_monitor().state(detail=host) if aid == "live" else run_analysis(aid)
    for h in res["hosts"]:
        if h["host"] == host:
            return {"host": host, "cone": h["cone"]}
    raise HTTPException(404, f"unknown host {host}")


@app.get("/api/health")
def health():
    """Cheap liveness probe the console polls to show its connection state."""
    return {"ok": True, "live_hosts": len(live.hosts) if live else 0,
            "live_batches": live.batches if live else 0, "enforcement": enforcer.mode()}


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    name = file.filename or "capture"
    ext = Path(name).suffix.lower()
    if ext not in (".pcap", ".cap", ".csv"):
        raise HTTPException(400, "upload a classic .pcap file or a CIC-IDS2017-format .csv")
    aid = "upload-" + uuid.uuid4().hex[:8]
    dest = CACHE / "uploads" / f"{aid}{ext}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("wb") as f:
        shutil.copyfileobj(file.file, f)
    kind = "csv" if ext == ".csv" else "pcap"
    uploads[aid] = {"id": aid, "name": name, "kind": kind, "model": "cic2017" if kind == "csv" else "sim", "file": str(dest),
                    "description": f"Uploaded {kind.upper()}"}
    try:
        run_analysis(aid)
    except Exception as e:
        uploads.pop(aid, None)
        raise HTTPException(422, f"could not analyse {name}: {e}")
    return {"id": aid}


def _ctx(aid: str, host: str, t: int):
    if aid == "live":
        ctx = live_monitor().context()
        if host not in ctx["seqs"]:
            raise HTTPException(404, f"no live data for host {host}")
        seq = ctx["seqs"][host]
        return ctx, seq, max(0, min(seq.T - 1, t))
    run_analysis(aid)
    ctx = contexts[aid]
    if host not in ctx["seqs"]:
        raise HTTPException(404, f"unknown host {host}")
    seq = ctx["seqs"][host]
    return ctx, seq, max(0, min(seq.T - 1, t))


@app.get("/api/explain/{aid}/{host}/{t}")
def explain(aid: str, host: str, t: int, rehearse_actions: bool = True):
    ctx, seq, t = _ctx(aid, host, t)
    eng = live_monitor().engine if aid == "live" else engine(scenario(aid)["model"])
    ex = eng.explain(seq, t)
    ex["flows"] = A.flagged_flows(ctx, host, t, ex["groups"], eng.history)
    # Rehearsing every response costs four extra rollouts. A live tick asks for
    # the cheap rule-based recommendation; a deliberate selection rehearses.
    ex["recommendation"] = rehearse(eng, seq, t, ex["p"]) if rehearse_actions else {
        **A.recommend(ex["p"], ex["groups"]), "band": band_of(ex["p"], eng.threshold), "ranking": None}
    ex["imagined"] = eng.imagine(seq, t, A.pick_imagined(ex, seq.has_packet))
    return ex


# least to most disruptive: a response is only escalated when it buys clearly more safety
DISRUPTION = ["block_scanner", "rate_limit", "block_admin", "isolate"]


def band_of(p: float, thr: float) -> str:
    """Bands start at the alarm threshold: the forecast is a calibrated
    probability of compromise within 5 minutes, so the alarm line is 'Medium'."""
    return "Low" if p < thr else "Medium" if p < 0.5 else "High" if p < 0.85 else "Critical"


def rehearse(eng: Engine, seq, t: int, p: float) -> dict:
    """Try every response inside the world model and recommend the least
    disruptive one that achieves most of the best achievable risk reduction."""
    band = band_of(p, eng.threshold)
    results = {a: eng.whatif(seq, t, a, samples=64) for a in DISRUPTION}
    after = {a: r["after"][-1] for a, r in results.items()}
    before = results["isolate"]["before"][-1]
    best = max(before - v for v in after.values())
    ranking = sorted(({"action": a, "label": ACTIONS[a]["label"], "after": after[a], "drop": before - after[a]} for a in DISRUPTION), key=lambda r: -r["drop"])
    if band == "Low":
        return {"band": band, "action": None, "label": "Keep monitoring", "ranking": ranking, "before": before}
    if best < 0.02:  # nothing changes the outcome: the host is already compromised
        return {"band": band, "action": "isolate", "label": "Isolate host: already compromised, contain and investigate",
                "ranking": ranking, "before": before, "after": after["isolate"]}
    pick = next(a for a in DISRUPTION if before - after[a] >= 0.7 * best)
    return {"band": band, "action": pick, "label": ACTIONS[pick]["label"], "ranking": ranking, "before": before, "after": after[pick]}


@app.get("/api/whatif/{aid}/{host}/{t}/{action}")
def whatif(aid: str, host: str, t: int, action: str):
    if action not in ACTIONS:
        raise HTTPException(404, f"unknown action {action}")
    _, seq, t = _ctx(aid, host, t)
    eng = live_monitor().engine if aid == "live" else engine(scenario(aid)["model"])
    return eng.whatif(seq, t, action)


# --- live mode ------------------------------------------------------------


def live_monitor() -> LiveMonitor:
    global live
    with _glock:
        if live is None:
            live = LiveMonitor(engine("sim"), ledger)
        return live


@app.post("/api/live/ingest")
def live_ingest(batch: dict = Body(...)):
    """One closed window per host, pushed by trace-sensor."""
    return live_monitor().ingest(batch)


@app.get("/api/live/state")
def live_state(since: int | None = None, detail: str | None = None):
    """`since` returns only windows at or after that index, so a 1 s refresh
    stays a few kilobytes instead of re-sending the whole history."""
    return live_monitor().state(since=since, detail=detail)


@app.get("/api/enforce/state")
def enforce_state():
    return enforcer.state()


@app.post("/api/enforce/block")
def enforce_block(body: dict = Body(...)):
    """Apply an analyst-approved block. Refused for addresses TRACE depends on."""
    return enforcer.block(str(body.get("ip", "")), reason=str(body.get("reason", "analyst approved")),
                          host=str(body.get("host", "")), ttl=body.get("ttl"))


@app.post("/api/enforce/unblock")
def enforce_unblock(body: dict = Body(...)):
    return enforcer.unblock(str(body.get("ip", "")))


@app.get("/api/benchmark")
def benchmark():
    out = {}
    for name in ("sim", "cic2017"):
        p = ART / name / "benchmark.json"
        if p.exists():
            out[name] = json.loads(p.read_text())
    return out


@app.get("/api/ledger")
def get_ledger():
    recs = ledger.records()
    return {"records": recs[-200:][::-1], "verify": Ledger.verify(recs)}


@app.post("/api/ledger/approve")
def approve(body: dict = Body(...)):
    rec = ledger.append("approval", analysis=body.get("aid"), host=body.get("host"), window=body.get("window"),
                        action=body.get("action"), p=body.get("p"), note="Analyst approved; model-only forecasts never auto-block")
    return {"record": rec, "verify": Ledger.verify(ledger.records())}


@app.post("/api/ledger/tamper-test")
def tamper_test():
    """Edit one past record in a copy of the chain and show verification fail."""
    recs = [dict(r) for r in ledger.records()]
    if len(recs) < 2:
        return {"ok": True, "message": "need at least two records"}
    victim = recs[len(recs) // 2]
    if "p" in victim and isinstance(victim["p"], (int, float)):
        victim["p"] = round(max(0.0, victim["p"] - 0.5), 3)
    else:
        victim["kind"] = victim["kind"] + "-edited"
    res = Ledger.verify(recs)
    return {"edited_seq": victim["seq"], **res}


app.mount("/", StaticFiles(directory=UI), name="ui")


def main():
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")


if __name__ == "__main__":
    main()
