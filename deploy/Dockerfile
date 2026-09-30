# TRACE on Linux: the sensor is a static binary, the console carries the model.
#
#   docker build -f deploy/Dockerfile -t trace .
#
# The sensor needs CAP_NET_RAW to capture and CAP_NET_ADMIN to enforce; see
# deploy/compose.yaml, which grants only those two rather than --privileged.

# --- build the Go sensor and tools (no cgo, so the result is static) --------
FROM golang:1.26-bookworm AS go-build
WORKDIR /src
COPY extractor/go.mod extractor/go.sum ./
RUN go mod download
COPY extractor/ ./
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/trace-sensor  ./cmd/trace-sensor && \
    go build -trimpath -ldflags="-s -w" -o /out/trace-extract ./cmd/trace-extract && \
    go build -trimpath -ldflags="-s -w" -o /out/trace-sim     ./cmd/trace-sim && \
    go vet ./... && go test ./...

# --- console: Python, CPU-only torch ---------------------------------------
FROM python:3.11-slim-bookworm AS console
# nftables is what the enforcer drives; iproute2 gives it the route table it
# reads to work out which addresses it must never block.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nftables iproute2 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# The CPU wheel keeps the image ~3 GB smaller than the default CUDA build.
COPY ml/pyproject.toml ml/
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch && \
    pip install --no-cache-dir "fastapi" "uvicorn" "python-multipart" \
        "numpy" "pandas" "pyarrow" "pyyaml" "scikit-learn"
COPY ml/ ml/
COPY ui/ ui/
COPY --from=go-build /out/ extractor/bin/
RUN pip install --no-cache-dir -e ./ml
ENV PYTHONUNBUFFERED=1 TRACE_ENFORCE=0
EXPOSE 8000
CMD ["python", "-m", "trace_ml.server"]

# --- sensor-only image: tiny, nothing but the static binary ----------------
FROM gcr.io/distroless/static-debian12 AS sensor
COPY --from=go-build /out/trace-sensor /trace-sensor
ENTRYPOINT ["/trace-sensor"]
