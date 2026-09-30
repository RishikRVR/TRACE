// Command trace-sensor is TRACE's live sensor. It captures traffic from an
// interface (or replays a capture file at wall-clock pace through the same
// code path), builds the per-host window features of
// docs/feature-schema-v1.md, and streams each window to the console as it
// closes.
//
//	trace-sensor -iface eth0 -server http://127.0.0.1:8000
//	trace-sensor -replay data/demo/demo-killchain.pcap -speed 60   # no live traffic
//
// On Linux capture uses a pure-Go AF_PACKET socket and needs CAP_NET_RAW
// (setcap cap_net_raw+ep ./trace-sensor) or root; on macOS it uses libpcap
// and needs /dev/bpf access.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/RishikRVR/trace/extractor/internal/capture"
	"github.com/RishikRVR/trace/extractor/internal/decode"
	"github.com/RishikRVR/trace/extractor/internal/features"
	"github.com/RishikRVR/trace/extractor/internal/flow"
)

// batch is one push to the console: the windows that closed since the last
// push, plus the flows that expired in the same period.
type batch struct {
	Sensor   string         `json:"sensor"`
	Schema   int            `json:"schema_version"`
	WindowS  int            `json:"window_s"`
	Features []string       `json:"features,omitempty"` // first batch only
	Rows     []row          `json:"rows"`
	Flows    []flowRec      `json:"flows"`
	Stats    map[string]any `json:"stats"`
	Now      int64          `json:"now_ms"`
}

type row struct {
	Host        string    `json:"host"`
	WindowStart int64     `json:"window_start"`
	Values      []float64 `json:"values"`
}

type flowRec struct {
	First    int64   `json:"first_seen"`
	Last     int64   `json:"last_seen"`
	SrcIP    string  `json:"src_ip"`
	SrcPort  uint16  `json:"src_port"`
	DstIP    string  `json:"dst_ip"`
	DstPort  uint16  `json:"dst_port"`
	Proto    string  `json:"proto"`
	PktsFwd  uint64  `json:"pkts_fwd"`
	PktsBwd  uint64  `json:"pkts_bwd"`
	BytesFwd uint64  `json:"bytes_fwd"`
	BytesBwd uint64  `json:"bytes_bwd"`
	State    string  `json:"tcp_state_final"`
	TTLBwd   float64 `json:"ttl_mean_bwd"`
}

func main() {
	iface := flag.String("iface", "", "interface to capture from (live mode)")
	replay := flag.String("replay", "", "capture file to replay at wall-clock pace instead of live capture")
	speed := flag.Float64("speed", 1, "replay speed multiplier (60 = a minute per second)")
	server := flag.String("server", "http://127.0.0.1:8000", "console base URL; empty writes NDJSON to stdout")
	window := flag.Duration("window", 30*time.Second, "window length")
	internal := flag.String("internal", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", "comma-separated internal ranges")
	name := flag.String("name", "", "sensor name shown in the console (default: hostname or file name)")
	snaplen := flag.Int("snaplen", 262144, "bytes captured per packet")
	promisc := flag.Bool("promisc", true, "put the interface in promiscuous mode")
	flowIdle := flag.Duration("flow-idle", 120*time.Second, "expire a flow after this long with no packet")
	flag.Parse()

	if (*iface == "") == (*replay == "") {
		fmt.Fprintln(os.Stderr, "usage: trace-sensor (-iface eth0 | -replay file.pcap) [-server URL]")
		os.Exit(2)
	}
	if err := run(*iface, *replay, *speed, *server, *name, *window, *internal, *snaplen, *promisc, *flowIdle); err != nil {
		fmt.Fprintln(os.Stderr, "trace-sensor:", err)
		os.Exit(1)
	}
}

func run(iface, replay string, speed float64, server, name string, window time.Duration, internal string, snaplen int, promisc bool, flowIdle time.Duration) error {
	nets, err := features.ParseCIDRs(internal)
	if err != nil {
		return err
	}
	if window <= 0 {
		return errors.New("-window must be positive")
	}
	if name == "" {
		if replay != "" {
			name = "replay:" + trimPath(replay)
		} else if h, err := os.Hostname(); err == nil {
			name = h + ":" + iface
		} else {
			name = iface
		}
	}

	var src capture.Source
	if replay != "" {
		src, err = capture.NewReplaySource(replay, speed)
		log.Printf("replaying %s at %gx through the live pipeline as %q", replay, speed, name)
	} else {
		src, err = capture.NewLiveSource(iface, int32(snaplen), promisc, time.Second)
		log.Printf("capturing on %s via %s as %q", iface, capture.LiveBackend, name)
	}
	if err != nil {
		return err
	}
	defer src.Close()

	cfg := features.Config{Window: window, Internal: nets, Source: name}
	x := features.New(cfg).Live(flowIdle)
	table := flow.NewTable(flow.DefaultConfig())

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	sweep := time.NewTicker(30 * time.Second)
	defer sweep.Stop()

	pkts := src.Packets()
	first := true
	var seen, skipped uint64
	// Replay keeps recorded timestamps, so windows must close on capture time;
	// a live capture uses the wall clock.
	var lastTS time.Time
	clock := func() time.Time {
		if replay == "" {
			return time.Now()
		}
		return lastTS
	}
	for {
		select {
		case pkt, ok := <-pkts:
			if !ok { // replay finished
				x.Tick(clock().Add(2 * window))
				push(server, buildBatch(x, name, window, seen, skipped, src, &first))
				log.Printf("capture ended after %d packets", seen)
				return nil
			}
			ev, err := decode.FromPacket(pkt, table)
			if err != nil {
				if errors.Is(err, decode.ErrUnsupportedPacket) {
					skipped++
					continue
				}
				log.Printf("decode: %v", err)
				continue
			}
			seen++
			lastTS = ev.Timestamp
			x.Add(&ev)

		case <-tick.C:
			x.Tick(clock())
			if b := buildBatch(x, name, window, seen, skipped, src, &first); b != nil {
				push(server, b)
			}

		case <-sweep.C:
			table.Sweep(clock())

		case <-stop:
			log.Printf("stopping after %d packets", seen)
			return nil
		}
	}
}

// buildBatch drains whatever has completed, returning nil when there is
// nothing to send.
func buildBatch(x *features.Extractor, name string, window time.Duration, seen, skipped uint64, src capture.Source, first *bool) *batch {
	rows, flows := x.Drain()
	if len(rows) == 0 && len(flows) == 0 {
		return nil
	}
	nFlows, nHosts := x.Pending()
	st, _ := src.Stats()
	b := &batch{
		Sensor: name, Schema: features.SchemaVersion, WindowS: int(window.Seconds()), Now: time.Now().UnixMilli(),
		Stats: map[string]any{
			"packets": seen, "skipped": skipped, "active_flows": nFlows, "open_hosts": nHosts,
			"captured": st.PacketsReceived, "dropped": st.PacketsDropped,
		},
	}
	if *first {
		b.Features = features.Names
		*first = false
	}
	for _, r := range rows {
		b.Rows = append(b.Rows, row{Host: r.Host, WindowStart: r.WindowStart, Values: r.Values})
	}
	for _, f := range flows {
		b.Flows = append(b.Flows, flowRec{
			First: f.First.UnixMilli(), Last: f.Last.UnixMilli(),
			SrcIP: f.SrcIP, SrcPort: f.SrcPort, DstIP: f.DstIP, DstPort: f.DstPort, Proto: string(f.Proto),
			PktsFwd: f.Pkts[0], PktsBwd: f.Pkts[1], BytesFwd: f.Bytes[0], BytesBwd: f.Bytes[1],
			State: f.State(), TTLBwd: f.TTLMeanBwd(),
		})
	}
	return b
}

var client = &http.Client{Timeout: 30 * time.Second}

// push sends a batch to the console, or to stdout when no server is set. A
// failed push is logged and dropped: the sensor must not block on the UI.
func push(server string, b *batch) {
	if b == nil {
		return
	}
	body, err := json.Marshal(b)
	if err != nil {
		log.Printf("encode batch: %v", err)
		return
	}
	if server == "" {
		os.Stdout.Write(append(body, '\n'))
		return
	}
	resp, err := client.Post(strings.TrimRight(server, "/")+"/api/live/ingest", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("push to %s: %v", server, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("push rejected: %s", resp.Status)
		return
	}
	log.Printf("sent %d window rows, %d expired flows", len(b.Rows), len(b.Flows))
}

func trimPath(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}
