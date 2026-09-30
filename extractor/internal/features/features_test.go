package features

import (
	"math"
	"net"
	"testing"
	"time"

	"github.com/RishikRVR/trace/extractor/internal/decode"
	"github.com/RishikRVR/trace/extractor/internal/flow"
	"github.com/RishikRVR/trace/extractor/internal/pktgen"
)

const base = "2026-01-01T00:00:00Z"

func at(t *testing.T, offset time.Duration) time.Time {
	t.Helper()
	b, err := time.Parse(time.RFC3339, base)
	if err != nil {
		t.Fatal(err)
	}
	return b.Add(offset)
}

func testConfig(t *testing.T) Config {
	t.Helper()
	nets, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	return Config{Window: 30 * time.Second, Internal: nets, Source: "test"}
}

// feed builds packets with pktgen, decodes them exactly as the sensor does,
// and returns the extractor holding the result.
func feed(t *testing.T, x *Extractor, pkts []pktgen.Packet) {
	t.Helper()
	table := flow.NewTable(flow.DefaultConfig())
	for _, p := range pkts {
		ev, err := decode.FromPacket(pktgen.AsPacket(p), table)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		x.Add(&ev)
	}
}

func value(t *testing.T, r Row, name string) float64 {
	t.Helper()
	i, ok := nameIndex[name]
	if !ok {
		t.Fatalf("unknown feature %q", name)
	}
	return r.Values[i]
}

func rowFor(t *testing.T, rows []Row, host string) Row {
	t.Helper()
	for _, r := range rows {
		if r.Host == host {
			return r
		}
	}
	t.Fatalf("no row for host %s", host)
	return Row{}
}

// A sequential port scan must show up as many probed ports, near-perfect
// sequentiality and failed connections on the victim's row.
func TestSequentialScanFeatures(t *testing.T) {
	x := New(testConfig(t))
	var pkts []pktgen.Packet
	for i := 0; i < 20; i++ {
		data, err := pktgen.TCPWith("203.0.113.9", "10.0.0.5", 40000, uint16(1000+i), 1,
			pktgen.TCPFlags{SYN: true}, nil, pktgen.Opts{TTL: 50, Window: 1024})
		if err != nil {
			t.Fatal(err)
		}
		pkts = append(pkts, pktgen.Packet{Data: data, Timestamp: at(t, time.Duration(i)*100*time.Millisecond)})
	}
	feed(t, x, pkts)
	x.Close()

	r := rowFor(t, x.Rows(), "10.0.0.5")
	if got := value(t, r, "f_uniq_lport_in"); got != 20 {
		t.Errorf("f_uniq_lport_in = %v, want 20", got)
	}
	if got := value(t, r, "p_lport_seq_frac_in"); got != 1 {
		t.Errorf("p_lport_seq_frac_in = %v, want 1 (strictly sequential)", got)
	}
	if got := value(t, r, "f_tcp_syn_in"); got != 20 {
		t.Errorf("f_tcp_syn_in = %v, want 20", got)
	}
	// The scanner's SYN window (1024) is a tool fingerprint the schema keeps.
	if got := value(t, r, "p_tcp_syn_win_mean"); got != 1024 {
		t.Errorf("p_tcp_syn_win_mean = %v, want 1024", got)
	}
	if got := value(t, r, "p_ttl_in_mean"); got != 50 {
		t.Errorf("p_ttl_in_mean = %v, want 50", got)
	}
}

// A randomised scan over the same number of ports must be distinguishable
// from the sequential one by entropy and sequentiality, not by volume.
func TestRandomScanIsNotSequential(t *testing.T) {
	x := New(testConfig(t))
	ports := []uint16{5432, 81, 9200, 22, 3389, 143, 8080, 6379, 445, 25}
	var pkts []pktgen.Packet
	for i, p := range ports {
		data, err := pktgen.TCPWith("203.0.113.9", "10.0.0.5", 40000, p, 1,
			pktgen.TCPFlags{SYN: true}, nil, pktgen.DefaultOpts)
		if err != nil {
			t.Fatal(err)
		}
		pkts = append(pkts, pktgen.Packet{Data: data, Timestamp: at(t, time.Duration(i)*time.Second)})
	}
	feed(t, x, pkts)
	x.Close()

	r := rowFor(t, x.Rows(), "10.0.0.5")
	if got := value(t, r, "p_lport_seq_frac_in"); got != 0 {
		t.Errorf("p_lport_seq_frac_in = %v, want 0 for a randomised scan", got)
	}
	want := math.Log2(float64(len(ports))) // each port touched once
	if got := value(t, r, "p_lport_entropy_in"); math.Abs(got-want) > 1e-6 {
		t.Errorf("p_lport_entropy_in = %v, want %v", got, want)
	}
}

// Windows must be cut on absolute boundaries, and a host's traffic must land
// in the window its packets belong to.
func TestWindowBoundaries(t *testing.T) {
	x := New(testConfig(t))
	var pkts []pktgen.Packet
	for _, off := range []time.Duration{0, 29 * time.Second, 31 * time.Second, 75 * time.Second} {
		data, err := pktgen.TCPWith("10.0.0.5", "203.0.113.9", 5000, 443, 1,
			pktgen.TCPFlags{SYN: true}, nil, pktgen.DefaultOpts)
		if err != nil {
			t.Fatal(err)
		}
		pkts = append(pkts, pktgen.Packet{Data: data, Timestamp: at(t, off)})
	}
	feed(t, x, pkts)
	x.Close()

	var starts []int64
	for _, r := range x.Rows() {
		if r.Host == "10.0.0.5" {
			starts = append(starts, r.WindowStart)
		}
	}
	if len(starts) != 3 {
		t.Fatalf("got %d windows, want 3 (0-30, 30-60, 60-90)", len(starts))
	}
	for i, s := range starts {
		if s%30000 != 0 {
			t.Errorf("window %d starts at %d, which is not on a 30 s boundary", i, s)
		}
		if i > 0 && s <= starts[i-1] {
			t.Errorf("windows are not in order: %v", starts)
		}
	}
}

// Only internal hosts get rows; an external scanner's own behaviour appears
// in the victim's *_in features instead.
func TestOnlyInternalHostsGetRows(t *testing.T) {
	x := New(testConfig(t))
	data, err := pktgen.TCPWith("203.0.113.9", "10.0.0.5", 40000, 22, 1,
		pktgen.TCPFlags{SYN: true}, nil, pktgen.DefaultOpts)
	if err != nil {
		t.Fatal(err)
	}
	feed(t, x, []pktgen.Packet{{Data: data, Timestamp: at(t, 0)}})
	x.Close()

	for _, r := range x.Rows() {
		if r.Host != "10.0.0.5" {
			t.Errorf("row for non-internal host %s", r.Host)
		}
	}
	if len(x.Rows()) != 1 {
		t.Fatalf("got %d rows, want 1", len(x.Rows()))
	}
}

// Live mode must emit the same rows as batch mode, and expire idle flows so a
// long-running sensor stays bounded.
func TestLiveDrainMatchesBatchAndExpiresFlows(t *testing.T) {
	cfg := testConfig(t)
	var pkts []pktgen.Packet
	for i := 0; i < 6; i++ {
		data, err := pktgen.TCPWith("10.0.0.5", "203.0.113.9", uint16(5000+i), 443, 1,
			pktgen.TCPFlags{SYN: true}, nil, pktgen.DefaultOpts)
		if err != nil {
			t.Fatal(err)
		}
		pkts = append(pkts, pktgen.Packet{Data: data, Timestamp: at(t, time.Duration(i)*20*time.Second)})
	}

	batch := New(cfg)
	feed(t, batch, pkts)
	batch.Close()

	live := New(cfg).Live(30 * time.Second)
	feed(t, live, pkts)
	live.Tick(at(t, 200*time.Second)) // close the last window and expire flows
	rows, expired := live.Drain()

	if len(rows) != len(batch.Rows()) {
		t.Fatalf("live produced %d rows, batch %d", len(rows), len(batch.Rows()))
	}
	for i := range rows {
		if rows[i].Host != batch.Rows()[i].Host || rows[i].WindowStart != batch.Rows()[i].WindowStart {
			t.Fatalf("row %d differs: live %s@%d, batch %s@%d", i, rows[i].Host, rows[i].WindowStart,
				batch.Rows()[i].Host, batch.Rows()[i].WindowStart)
		}
		for j := range rows[i].Values {
			if rows[i].Values[j] != batch.Rows()[i].Values[j] {
				t.Fatalf("row %d feature %s: live %v, batch %v", i, Names[j], rows[i].Values[j], batch.Rows()[i].Values[j])
			}
		}
	}
	if len(expired) != len(pkts) {
		t.Errorf("expired %d flows, want %d", len(expired), len(pkts))
	}
	if n, _ := live.Pending(); n != 0 {
		t.Errorf("%d flows still tracked after expiry; live mode must stay bounded", n)
	}
	if rows2, _ := live.Drain(); len(rows2) != 0 {
		t.Errorf("Drain returned %d rows twice", len(rows2))
	}
}

// Tick must keep emitting on a quiet network without inventing rows.
func TestTickOnQuietNetworkEmitsNothing(t *testing.T) {
	live := New(testConfig(t)).Live(time.Minute)
	live.Tick(at(t, 0))
	live.Tick(at(t, 10*time.Minute))
	if rows, flows := live.Drain(); len(rows) != 0 || len(flows) != 0 {
		t.Errorf("quiet network produced %d rows and %d flows, want none", len(rows), len(flows))
	}
}

func TestParseCIDRsRejectsGarbage(t *testing.T) {
	if _, err := ParseCIDRs("10.0.0.0/8,not-a-cidr"); err == nil {
		t.Error("want an error for an invalid range")
	}
	nets, err := ParseCIDRs(" 10.0.0.0/8 , 192.168.0.0/16 ")
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 2 || !nets[0].Contains(net.ParseIP("10.1.2.3")) {
		t.Errorf("parsed ranges are wrong: %v", nets)
	}
}
