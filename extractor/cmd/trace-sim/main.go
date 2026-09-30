// Command trace-sim generates labelled attack-chain traffic (internal/sim) and
// runs it through the same decoder and feature extractor as trace-extract, so
// training data and uploaded captures share one code path.
//
//	trace-sim -out data/features/sim -episodes 240          training set
//	trace-sim -out data/features/slowscan -sweep 0.05,2,10  slow-scan experiment
//	trace-sim -demo data/demo                               demo pcaps + timelines
package main

import (
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RishikRVR/trace/extractor/internal/decode"
	"github.com/RishikRVR/trace/extractor/internal/features"
	"github.com/RishikRVR/trace/extractor/internal/flow"
	"github.com/RishikRVR/trace/extractor/internal/pktgen"
	"github.com/RishikRVR/trace/extractor/internal/sim"
)

func main() {
	out := flag.String("out", "", "directory for windows.csv, timeline.csv, episodes.csv, schema.json")
	n := flag.Int("episodes", 240, "number of episodes")
	seed := flag.Int64("seed", 1, "base random seed")
	window := flag.Duration("window", 30*time.Second, "window length")
	mix := flag.String("mix", "full=0.45,scan_only=0.15,phish=0.15,benign=0.25", "episode kind proportions")
	sweep := flag.String("sweep", "", "comma-separated recon probe gaps in seconds: generate full chains at each gap instead of -mix")
	per := flag.Int("per", 8, "episodes per sweep gap")
	demo := flag.String("demo", "", "write the demo scenarios as pcaps + timelines into this directory")
	flag.Parse()

	var err error
	switch {
	case *demo != "":
		err = writeDemos(*demo, *window)
	case *out != "":
		var specs []sim.Spec
		specs, err = buildSpecs(*n, *seed, *mix, *sweep, *per)
		if err == nil {
			err = generate(*out, specs, *window)
		}
	default:
		err = errors.New("need -out or -demo")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "trace-sim:", err)
		os.Exit(1)
	}
}

var trainBase = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

func buildSpecs(n int, seed int64, mix, sweep string, per int) ([]sim.Spec, error) {
	var specs []sim.Spec
	if sweep != "" {
		i := 0
		for _, s := range strings.Split(sweep, ",") {
			gap, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
			if err != nil {
				return nil, fmt.Errorf("-sweep: %w", err)
			}
			for k := 0; k < per; k++ {
				specs = append(specs, sim.Spec{
					ID: fmt.Sprintf("sweep-%04d", i), Kind: "full", Seed: seed*1_000_003 + int64(i),
					Variant: sim.Variant{ProbeGap: time.Duration(gap * float64(time.Second)), Exfil: "https_bulk"},
					Start:   trainBase.Add(time.Duration(i) * 3 * time.Hour),
				})
				i++
			}
		}
		return specs, nil
	}
	type share struct {
		kind string
		p    float64
	}
	var shares []share
	for _, part := range strings.Split(mix, ",") {
		k, v, ok := strings.Cut(part, "=")
		p, err := strconv.ParseFloat(v, 64)
		if !ok || err != nil {
			return nil, fmt.Errorf("-mix: bad entry %q", part)
		}
		shares = append(shares, share{strings.TrimSpace(k), p})
	}
	// deterministic stratified assignment: kind counts follow the shares exactly
	var kinds []string
	for _, s := range shares {
		for c := 0; c < int(s.p*float64(n)+0.5); c++ {
			kinds = append(kinds, s.kind)
		}
	}
	for len(kinds) < n {
		kinds = append(kinds, shares[0].kind)
	}
	perm := rand.New(rand.NewSource(seed)).Perm(n) // shuffle so any split keeps the mix
	for i := 0; i < n; i++ {
		k := kinds[perm[i]]
		specs = append(specs, sim.Spec{
			ID: fmt.Sprintf("ep-%04d", i), Kind: k, Seed: seed*1_000_003 + int64(i),
			Start: trainBase.Add(time.Duration(i) * 3 * time.Hour),
		})
	}
	return specs, nil
}

type result struct {
	ep   *sim.Episode
	rows []features.Row
	err  error
}

func extract(ep *sim.Episode, window time.Duration) ([]features.Row, []*features.Flow, error) {
	nets, _ := features.ParseCIDRs("10.0.0.0/8")
	table := flow.NewTable(flow.DefaultConfig())
	x := features.New(features.Config{Window: window, Internal: nets, Source: ep.Spec.ID})
	for _, p := range ep.Packets {
		ev, err := decode.FromPacket(pktgen.AsPacket(p), table)
		if err != nil {
			if errors.Is(err, decode.ErrUnsupportedPacket) {
				continue
			}
			return nil, nil, err
		}
		x.Add(&ev)
	}
	x.Close()
	return x.Rows(), x.Flows(), nil
}

func generate(out string, specs []sim.Spec, window time.Duration) error {
	start := time.Now()
	results := make([]result, len(specs))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				ep, err := sim.Generate(specs[i])
				if err != nil {
					results[i] = result{err: err}
					continue
				}
				rows, _, err := extract(ep, window)
				ep.Packets = ep.Packets[:0:0] // drop packets; keep only the counts below
				results[i] = result{ep: ep, rows: rows, err: err}
			}
		}()
	}
	for i := range specs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	wf, err := os.Create(filepath.Join(out, "windows.csv"))
	if err != nil {
		return err
	}
	defer wf.Close()
	tf, err := os.Create(filepath.Join(out, "timeline.csv"))
	if err != nil {
		return err
	}
	defer tf.Close()
	ef, err := os.Create(filepath.Join(out, "episodes.csv"))
	if err != nil {
		return err
	}
	defer ef.Close()

	tw, ew := csv.NewWriter(tf), csv.NewWriter(ef)
	tw.Write([]string{"source", "host", "stage", "family", "start_ms", "end_ms"})
	ew.Write([]string{"source", "kind", "recon_speed", "recon_order", "probe_gap_s", "access", "lateral", "exfil", "start_ms", "end_ms", "seed"})
	var rows int
	for i, r := range results {
		if r.err != nil {
			return fmt.Errorf("episode %s: %w", specs[i].ID, r.err)
		}
		if err := features.WriteWindows(wf, r.rows, window, i == 0); err != nil {
			return err
		}
		rows += len(r.rows)
		writeTimeline(tw, r.ep)
		v := r.ep.Spec.Variant
		ew.Write([]string{r.ep.Spec.ID, r.ep.Spec.Kind, v.ReconSpeed, v.ReconOrder, ff(v.ProbeGap.Seconds()), v.Access, v.Lateral, v.Exfil,
			ms(r.ep.Spec.Start), ms(r.ep.End), strconv.FormatInt(r.ep.Spec.Seed, 10)})
	}
	tw.Flush()
	ew.Flush()
	if err := tw.Error(); err != nil {
		return err
	}
	nets, _ := features.ParseCIDRs("10.0.0.0/8")
	if err := features.WriteSchema(filepath.Join(out, "schema.json"), features.Config{Window: window, Internal: nets}); err != nil {
		return err
	}
	fmt.Printf("trace-sim: %d episodes, %d window rows -> %s (%.1fs)\n", len(specs), rows, out, time.Since(start).Seconds())
	return nil
}

func writeTimeline(w *csv.Writer, ep *sim.Episode) {
	iv := append([]sim.Interval(nil), ep.Timeline...)
	sort.SliceStable(iv, func(i, j int) bool { return iv[i].Start.Before(iv[j].Start) })
	for _, t := range iv {
		w.Write([]string{ep.Spec.ID, t.Host, strconv.Itoa(t.Stage), t.Family, ms(t.Start), ms(t.End)})
	}
}

func ms(t time.Time) string { return strconv.FormatInt(t.UnixMilli(), 10) }
func ff(v float64) string   { return strconv.FormatFloat(v, 'g', 6, 64) }
func istAt(h, m int) time.Time {
	return time.Date(2026, 9, 30, h, m, 0, 0, time.FixedZone("IST", 5*3600+1800))
}

// Demos are fixed scenarios for the console. demo-unseen uses DNS-tunnel
// exfiltration, which ml/ holds out of training.
var demos = []sim.Spec{
	{ID: "demo-killchain", Kind: "full", Seed: 20260930, Start: istAt(10, 0),
		Variant: sim.Variant{ReconSpeed: "medium", ReconOrder: "sequential", Access: "ssh_bruteforce", Lateral: "smb", Exfil: "https_bulk"}},
	{ID: "demo-slowscan", Kind: "full", Seed: 20260931, Start: istAt(11, 0),
		Variant: sim.Variant{ReconSpeed: "slow", ReconOrder: "random", Access: "web_exploit", Lateral: "winrm", Exfil: "https_bulk"}},
	{ID: "demo-benign", Kind: "benign", Seed: 20260932, Start: istAt(12, 0)},
	{ID: "demo-unseen", Kind: "phish", Seed: 20260933, Start: istAt(13, 0),
		Variant: sim.Variant{Lateral: "rdp", Exfil: "dns_tunnel"}},
}

func writeDemos(dir string, window time.Duration) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, spec := range demos {
		ep, err := sim.Generate(spec)
		if err != nil {
			return err
		}
		if err := pktgen.WritePcap(filepath.Join(dir, spec.ID+".pcap"), ep.Packets); err != nil {
			return err
		}
		f, err := os.Create(filepath.Join(dir, spec.ID+".timeline.csv"))
		if err != nil {
			return err
		}
		w := csv.NewWriter(f)
		w.Write([]string{"source", "host", "stage", "family", "start_ms", "end_ms"})
		writeTimeline(w, ep)
		w.Flush()
		f.Close()
		fmt.Printf("trace-sim: %s: %d packets, %s -> %s\n", spec.ID, len(ep.Packets), ep.End.Sub(ep.Spec.Start).Round(time.Second), filepath.Join(dir, spec.ID+".pcap"))
	}
	return nil
}
