// Command trace-extract turns a packet capture into TRACE's feature matrix:
// windows.csv (one state vector per internal host per window), flows.csv and
// schema.json, as defined in docs/feature-schema-v1.md. It prints a JSON
// summary, including throughput, to stdout.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/RishikRVR/trace/extractor/internal/capture"
	"github.com/RishikRVR/trace/extractor/internal/decode"
	"github.com/RishikRVR/trace/extractor/internal/features"
	"github.com/RishikRVR/trace/extractor/internal/flow"
)

type summary struct {
	Pcap             string  `json:"pcap"`
	Out              string  `json:"out"`
	PacketsProcessed int     `json:"packets_processed"`
	PacketsSkipped   int     `json:"packets_skipped"`
	Flows            int     `json:"flows"`
	WindowRows       int     `json:"window_rows"`
	Hosts            int     `json:"hosts"`
	FirstPacket      string  `json:"first_packet,omitempty"`
	LastPacket       string  `json:"last_packet,omitempty"`
	Seconds          float64 `json:"seconds"`
	PacketsPerSecond float64 `json:"packets_per_second"`
}

func main() {
	pcapPath := flag.String("pcap", "", "classic pcap file to read (required)")
	out := flag.String("out", "", "directory for windows.csv, flows.csv and schema.json (required)")
	window := flag.Duration("window", 30*time.Second, "window length")
	internal := flag.String("internal", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", "comma-separated internal ranges")
	source := flag.String("source", "", "value of the source column (default: pcap file name)")
	flag.Parse()
	if *pcapPath == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: trace-extract -pcap <file.pcap> -out <dir> [-window 30s] [-internal cidrs]")
		os.Exit(2)
	}
	nets, err := features.ParseCIDRs(*internal)
	if err == nil && *window <= 0 {
		err = errors.New("-window must be positive")
	}
	if err == nil {
		name := *source
		if name == "" {
			name = filepath.Base(*pcapPath)
		}
		err = run(*pcapPath, *out, features.Config{Window: *window, Internal: nets, Source: name})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "trace-extract:", err)
		os.Exit(1)
	}
}

func run(path, outDir string, cfg features.Config) error {
	start := time.Now()
	src, err := capture.NewFileSource(path)
	if err != nil {
		return err
	}
	defer src.Close()

	// No sweeping during a replay: every flow stays tracked to the end.
	table := flow.NewTable(flow.DefaultConfig())
	x := features.New(cfg)
	s := summary{Pcap: path, Out: outDir}
	for pkt := range src.Packets() {
		ev, err := decode.FromPacket(pkt, table)
		if err != nil {
			if errors.Is(err, decode.ErrUnsupportedPacket) {
				s.PacketsSkipped++
				continue
			}
			return err
		}
		x.Add(&ev)
		ts := ev.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z")
		if s.FirstPacket == "" {
			s.FirstPacket = ts
		}
		s.LastPacket = ts
	}
	x.Close()

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(outDir, "windows.csv"), func(f *os.File) error {
		return features.WriteWindows(f, x.Rows(), cfg.Window, true)
	}); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(outDir, "flows.csv"), func(f *os.File) error {
		return features.WriteFlows(f, cfg.Source, x.Flows(), true)
	}); err != nil {
		return err
	}
	if err := features.WriteSchema(filepath.Join(outDir, "schema.json"), cfg); err != nil {
		return err
	}

	hosts := map[string]bool{}
	for _, r := range x.Rows() {
		hosts[r.Host] = true
	}
	s.PacketsProcessed = x.Packets()
	s.Flows = len(x.Flows())
	s.WindowRows = len(x.Rows())
	s.Hosts = len(hosts)
	s.Seconds = time.Since(start).Seconds()
	if s.Seconds > 0 {
		s.PacketsPerSecond = float64(s.PacketsProcessed) / s.Seconds
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

func writeFile(path string, write func(*os.File) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
