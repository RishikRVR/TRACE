.PHONY: setup demo build test smoke sim cic train bench serve reproduce sensor replay linux docker doc

PY := .venv/bin/python -W ignore

setup:
	cd ml && uv venv .venv --python 3.11 && uv pip install --python .venv/bin/python -e '.[app,dev]'

build:
	cd extractor && go build -o bin/trace-extract ./cmd/trace-extract && go build -o bin/trace-sim ./cmd/trace-sim && go build -o bin/trace-sensor ./cmd/trace-sensor

# static Linux sensor binaries (no cgo, no libpcap): copy to the target host
linux:
	cd extractor && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/trace-sensor-linux-amd64 ./cmd/trace-sensor
	cd extractor && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bin/trace-sensor-linux-arm64 ./cmd/trace-sensor

test:
	cd extractor && go vet ./... && test -z "$$(gofmt -l .)" && go test ./...

smoke:
	cd extractor && go run ./cmd/trace-extract -pcap testdata/pcaps/mixed_traffic.pcap -out /tmp/trace-smoke

# the four demo captures only (~30 s). Everything is generated from a fixed
# seed, so these files are identical on every machine.
demo: build
	./extractor/bin/trace-sim -demo data/demo

# labelled kill-chain traffic: training set, slow-scan sweep, demo pcaps (seeded, reproducible)
sim: build
	./extractor/bin/trace-sim -out data/features/sim -episodes 320 -seed 1
	./extractor/bin/trace-sim -out data/features/slowscan -sweep 0.05,0.5,2,5,10,20,40 -per 8 -seed 7
	./extractor/bin/trace-sim -demo data/demo

# CIC-IDS2017 corrected release (data/raw/cic-ids2017-improved/*.csv) -> flow-only windows
cic:
	cd ml && $(PY) -m trace_ml.adapters cic2017 ../data/raw/cic-ids2017-improved ../data/features/cic2017

train:
	cd ml && $(PY) -m trace_ml.train --data ../data/features/sim --out ../artifacts/sim --epochs 30
	cd ml && $(PY) -m trace_ml.train --data ../data/features/cic2017 --out ../artifacts/cic2017 --epochs 25 --flow-only

bench:
	cd ml && $(PY) -m trace_ml.evaluate --art ../artifacts/sim --data ../data/features/sim --sweep ../data/features/slowscan | tee ../artifacts/sim/benchmark.md
	cd ml && $(PY) -m trace_ml.evaluate --art ../artifacts/cic2017 --data ../data/features/cic2017 | tee ../artifacts/cic2017/benchmark.md

# offline console on http://127.0.0.1:8000
serve: build
	cd ml && $(PY) -m trace_ml.server

# live sensor on a real interface (Linux: needs CAP_NET_RAW; macOS: /dev/bpf access)
#   make sensor IFACE=eth0
IFACE ?= eth0
sensor: build
	./extractor/bin/trace-sensor -iface $(IFACE) -server http://127.0.0.1:8000

# rehearse live mode from a recorded capture: puts no traffic on any network
SPEED ?= 60
CAPTURE ?= data/demo/demo-killchain.pcap
replay: build
	./extractor/bin/trace-sensor -replay $(CAPTURE) -speed $(SPEED) -internal 10.0.0.0/8 -server http://127.0.0.1:8000

# print-ready architecture doc: open docs/architecture.html and print to PDF
doc:
	cd ml && $(PY) ../docs/build_doc.py ../docs/architecture.md

# whole stack on Linux, in containers
docker:
	docker compose -f deploy/compose.yaml up --build

reproduce: sim cic train bench
