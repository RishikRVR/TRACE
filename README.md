# TRACE: Temporal Risk & Attack Chain Estimation

Team White_Hats' solution to Smart India Hackathon 2026 problem statement **SIH26153:
AI based Network Attack Forecasting from Network Traffic Data** (NTRO). The full statement
is in [docs/problem-statement.md](docs/problem-statement.md).

TRACE is a weather forecast for a network. A world model learns how each host's traffic
evolves, P(S_t+1 | S_≤t), and rolls it forward 10 windows (5 minutes) in 100 imagined
futures. From those it reports the probability that an attacker gets in, the ATT&CK stage
that comes next, and the traffic features driving the forecast, before the compromise.

## Setup

TRACE runs fully offline: no cloud APIs, no internet access at runtime.

### 1. Prerequisites

| Need | Version | Install |
|---|---|---|
| Go | 1.26 or newer | `brew install go` · `sudo apt install golang-go` · [go.dev/dl](https://go.dev/dl/) |
| Python | 3.11 or newer | `brew install python@3.11` · `sudo apt install python3.11` |
| uv | any | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

Check them:

```sh
go version     # go1.26 or newer
uv --version
```

Linux also needs `libpcap` **only** if you build the macOS-style live path;
the Linux sensor is pure Go and needs nothing. `make docker` needs Docker.

### 2. Install and run (about 2 minutes)

```sh
git clone <this-repo> && cd TRACE
make setup     # creates ml/.venv and installs dependencies
make demo      # generates the 4 demo captures (~2 s, from a fixed seed)
make serve     # console on http://127.0.0.1:8000
```

Open **http://127.0.0.1:8000**. No training is needed: the trained weights are
in `artifacts/sim/` and `artifacts/cic2017/`.

The first load of each scenario extracts features and runs the world model,
which takes a few seconds; the console says so while it works.

### 3. Optional: reproduce the training and the numbers

```sh
make sim       # 320 labelled episodes + the slow-scan sweep (~2 min)
make train     # retrains both models (~5 min on a laptop, CPU only)
make bench     # rewrites artifacts/*/benchmark.md
make test      # Go tests; cd ml && .venv/bin/python -m pytest tests/ for Python
```

`make reproduce` runs the whole chain. Everything is seeded, so the generated
dataset is identical on every machine.

`make cic` additionally needs the CIC-IDS2017 download described in
[data/README.md](data/README.md); nothing else depends on it.

### If something goes wrong

| Symptom | Fix |
|---|---|
| `make setup` fails on Python version | `uv venv ml/.venv --python 3.11` then rerun |
| Port 8000 already in use | `pkill -f trace_ml.server`, or serve elsewhere: `cd ml && .venv/bin/python -c "import uvicorn;from trace_ml.server import app;uvicorn.run(app,port=8001)"` |
| Console shows "model is not trained yet" | `make train`, or check that `artifacts/sim/model.pt` exists |
| No scenarios in the dropdown | `make demo` was not run |
| `trace-sensor` exits with a permissions error | Linux: `sudo setcap cap_net_raw+ep extractor/bin/trace-sensor`. macOS: run it with `sudo` |

## Submission documents

| Deliverable | Where |
|---|---|
| Architecture document (2 pages) | [docs/architecture.md](docs/architecture.md) · `make doc` builds `docs/architecture.html`; open it and print to PDF |
| Setup instructions | this file, §Setup |
| Source code | this repository |
| Design decisions and their reasons | [docs/decisions.md](docs/decisions.md) |
| Benchmark output | [artifacts/sim/benchmark.md](artifacts/sim/benchmark.md), [artifacts/cic2017/benchmark.md](artifacts/cic2017/benchmark.md) |

## Live mode and prevention

TRACE also runs as a live sensor. The sensor captures on an interface, builds
the same windows, and streams each one to the console as it closes; the console
advances each host's world-model state by a single step, so cost per window does
not grow with uptime.

```sh
make serve                       # console
make sensor IFACE=eth0           # live capture (Linux: CAP_NET_RAW; macOS: /dev/bpf)
make replay SPEED=60             # rehearse from a recorded capture instead
```

Then choose **Live capture** in the console. `make replay` drives the identical
code path from a recorded file, which is how the live demo is rehearsed without
putting traffic on a network. Live and batch runs produce byte-identical
features for the same capture (there is a test for it).

On Linux the sensor uses a pure-Go AF_PACKET socket, so `make linux` produces a
static binary with no libpcap. macOS uses libpcap.

**Prevention.** An approved decision can install a firewall rule: nftables on
Linux, pf on macOS. Four rules govern it:

1. A forecast never enforces by itself. Only an analyst approval reaches the
   enforcer.
2. **Dry run is the default.** Nothing touches a firewall unless the console is
   started with `TRACE_ENFORCE=1`, and the header badge always shows the mode.
3. Some addresses are never blocked: this host, loopback, the default gateway
   and its DNS servers. Blocking those would cut the sensor off.
4. Every rule has a TTL, can be undone from the console, and both the block and
   the undo go into the hash-chained ledger.

The whole stack runs in containers with only `NET_RAW` and `NET_ADMIN`, never
`--privileged`:

```sh
make docker     # console + sensor + replay traffic, all inside Docker
```

## The console

Choose one of the preloaded captures, or upload a classic `.pcap` or a CIC-IDS2017-format `.csv`.

- **Forecast timeline:** P(infiltration within 5 min) per host, the logistic-regression
  baseline on the same features, the forecast cone from 100 rollouts, and ground-truth
  stages. **▶ Replay as live** plays the capture window by window.
- **ATT&CK kill chain:** the current stage, and each stage's chance and ETA within the
  horizon. It also shows a surprise meter: the world model's own likelihood of the traffic,
  which flags attacks it never saw.
- **Why this forecast?** Plain-English reasons with baseline multiples, feature and
  past-window attributions (occlusion), and a deletion test showing the explanation is
  faithful.
- **What-if:** every response (block scanner, rate-limit, block admin ports, isolate) is
  rehearsed inside the world model. The least disruptive action that works is recommended.
  An analyst approves; a forecast alone never blocks.
- **Flagged flows, imagined futures, executive mode, benchmark, tamper-evident ledger and a
  problem-statement checklist.**

## Results

**Simulated kill chains**, both feature levels. Test episodes are never trained on, and
thresholds are fixed on validation. Details in `artifacts/sim/benchmark.md`.

| | TRACE | LR (S_t) | LR (last 20 windows) |
|---|---|---|---|
| F1, infiltration within 5 min (every window) | **0.865** | 0.622 | 0.803 |
| F1, windows before compromise only | **0.275** | 0.096 | 0.210 |
| Attacks warned before compromise, same false-alarm budget | **21/31** | 15/31 | 19/31 |
| False alarms per host-hour (own best threshold) | 0.20 | 2.45 | 0.24 |
| Benign episodes with any alarm | **0/17** | 17/17 | 5/17 |
| Unseen family (DNS-tunnel exfiltration) windows flagged | **100%** | 1% | 28% |
| Slow scans (probe gap 2–40 s) warned, same false-alarm budget | **100%** | 25–75% | 88–100% |

- A per-window "≥ 20 ports" threshold catches no scan with probes 2 s or more apart.
- Stage macro-F1 is 0.94.
- Next-state NLL is −1.42 for the world model vs 0.80 for a persistence baseline.

**CIC-IDS2017, real traffic, flow-only.** Training uses Monday–Wednesday and Friday,
validation Thursday morning, and test Thursday afternoon's infiltration chain, an attack
family never trained on. This is the hard setting, and TRACE does not beat the stacked
logistic regression yet:

| | TRACE | LR (S_t) | LR (last 20 windows) |
|---|---|---|---|
| F1 | 0.00 | 0.04 | 0.17 |
| PR-AUC | 0.04 | 0.02 | 0.39 |

TRACE warned the infiltrated host 10 minutes early, but with 2.4 false alarms per
host-hour. More real multi-stage training data is the next step.

## System requirements

Measured on an Apple M5 Pro (18 cores, 24 GB). Linux figures are the target;
the deployment path is `deploy/compose.yaml`.

**Running TRACE** (sensor + console)

| | Minimum | Recommended |
|---|---|---|
| OS | 64-bit Linux, kernel 5.x with nftables (or macOS 13+) | Ubuntu 22.04/24.04 LTS, Debian 12 |
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4 GB |
| Disk | 2 GB | 5 GB |
| GPU | none | none |
| Privileges | `CAP_NET_RAW` to capture, `CAP_NET_ADMIN` to enforce | separate unprivileged console |
| Network | 1 NIC (the host itself, or a mirror/SPAN port) | 2 NICs inline, to isolate other hosts |

Extractor throughput is ~780k packets/s on one core. A forecast costs ~1 ms per
host-window on 4 threads, so 1,000 hosts need about 1 s of CPU per 30 s window.
The console holds ~1.1 GB with both models loaded; the model itself is 0.8 MB
(199k parameters). Install the CPU-only PyTorch wheel: the default build pulls
in ~3 GB of CUDA libraries that are never used.

**Building and training** (only where models are made): Go 1.26+, uv, Python
3.11, and 8 GB RAM — training peaks at 5.0 GB and takes about 3.5 minutes.

## How it works

| Stage | What | Where |
|---|---|---|
| Extract | PCAP/pcapng or live capture → flows + one state vector per internal host per 30 s window: 43 flow-level and 32 packet-level features, ~780k packets/s on one core | `extractor/` (Go) |
| Simulate | Seeded office network with benign traffic and multi-stage attack chains, through the same extractor, plus ground-truth timelines | `extractor/cmd/trace-sim` |
| Learn | MDN-RNN: a GRU core with a 5-component Gaussian mixture over the next state, a stage head, and multi-step overshooting | `ml/trace_ml/model.py`, `train.py` |
| Forecast | 100 rollouts × 10 windows under fixed noise, then calibration | `ml/trace_ml/engine.py` |
| Explain and act | Occlusion attribution, what-if interventions and a hash-chained ledger | `engine.py`, `ledger.py`, `server.py` |
| Live | Sensor streams closed windows; the console advances each host's state incrementally | `extractor/cmd/trace-sensor`, `ml/trace_ml/live.py` |
| Prevent | Analyst-approved nftables/pf block with a TTL, an undo and a never-block list | `ml/trace_ml/enforce.py` |
| Console | FastAPI and a vendored single-page UI | `ml/trace_ml/server.py`, `ui/` |

Design decisions and what changed during the build are in [docs/decisions.md](docs/decisions.md).
The feature definitions are in [docs/feature-schema-v1.md](docs/feature-schema-v1.md).

## Layout

| Path | What |
|---|---|
| `extractor/` | Go: capture, decode, flows, features, simulator, live sensor (`cmd/trace-extract`, `cmd/trace-sim`, `cmd/trace-sensor`) |
| `ml/` | Python: data, world model, training, evaluation, explanations, server |
| `ui/` | Offline console (ECharts vendored, Apache-2.0) |
| `deploy/` | Dockerfile and compose stack for Linux |
| `docs/` | Problem statement, decisions, feature schema |
| `data/`, `artifacts/` | Datasets, features, trained models, benchmarks; not in git |

## Limitations

- The headline numbers come from simulated traffic. On real CIC-IDS2017 data TRACE does not
  yet beat logistic regression.
- Per-host state only; a graph model over the host-to-host graph is next.
- Live mode has been exercised by replaying recorded captures and inside
  containers, not yet on a busy production network.
- Once a host is already compromised, no what-if action lowers its forecast:
  the model is telling you containment, not prevention, is what is left.
- The ledger is a local hash chain, not a distributed blockchain. Anchoring the
  head hash to an external timestamp authority is the next step.
- No Talos/Sourcefire rules are included: their licence forbids redistribution. The repo's
  own licence is still to be chosen (see `docs/decisions.md`).
