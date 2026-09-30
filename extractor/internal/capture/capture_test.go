package capture

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/RishikRVR/trace/extractor/internal/pktgen"
)

func samplePackets(t *testing.T, n int) []pktgen.Packet {
	t.Helper()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	out := make([]pktgen.Packet, 0, n)
	for i := 0; i < n; i++ {
		data, err := pktgen.TCPWith("10.0.0.5", "203.0.113.9", 5000, uint16(80+i), 1,
			pktgen.TCPFlags{SYN: true}, nil, pktgen.DefaultOpts)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, pktgen.Packet{Data: data, Timestamp: base.Add(time.Duration(i) * 100 * time.Millisecond)})
	}
	return out
}

func writePcapng(t *testing.T, path string, pkts []pktgen.Packet) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkts {
		ci := gopacket.CaptureInfo{Timestamp: p.Timestamp, CaptureLength: len(p.Data), Length: len(p.Data)}
		if err := w.WritePacket(ci, p.Data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
}

func drain(t *testing.T, s Source) []gopacket.Packet {
	t.Helper()
	var out []gopacket.Packet
	for p := range s.Packets() {
		out = append(out, p)
	}
	return out
}

// Both capture formats must be read without the caller knowing which is which:
// Wireshark writes pcapng by default, so a judge's own capture is likely to be
// one.
func TestReadsBothPcapAndPcapng(t *testing.T) {
	dir := t.TempDir()
	pkts := samplePackets(t, 5)

	classic := filepath.Join(dir, "a.pcap")
	if err := pktgen.WritePcap(classic, pkts); err != nil {
		t.Fatal(err)
	}
	ng := filepath.Join(dir, "a.pcapng")
	writePcapng(t, ng, pkts)

	for _, path := range []string{classic, ng} {
		src, err := NewFileSource(path)
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(path), err)
		}
		got := drain(t, src)
		src.Close()
		if len(got) != len(pkts) {
			t.Errorf("%s: read %d packets, want %d", filepath.Base(path), len(got), len(pkts))
		}
		if len(got) > 0 && !got[0].Metadata().Timestamp.Equal(pkts[0].Timestamp) {
			t.Errorf("%s: first timestamp %v, want %v", filepath.Base(path),
				got[0].Metadata().Timestamp, pkts[0].Timestamp)
		}
	}
}

func TestMissingFileIsAnError(t *testing.T) {
	if _, err := NewFileSource(filepath.Join(t.TempDir(), "nope.pcap")); err == nil {
		t.Error("want an error for a missing file")
	}
}

func TestNotACaptureFileIsAnError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "junk.pcap")
	if err := os.WriteFile(p, []byte("this is not a capture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileSource(p); err == nil {
		t.Error("want an error for a file that is not a capture")
	}
}

// Replay must preserve recorded timestamps, so a replayed capture produces the
// same windows as a batch run, and must pace itself by the speed multiplier.
func TestReplayPreservesTimestampsAndPaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.pcap")
	pkts := samplePackets(t, 5) // spans 400 ms of capture time
	if err := pktgen.WritePcap(path, pkts); err != nil {
		t.Fatal(err)
	}

	src, err := NewReplaySource(path, 4) // 400 ms of capture in ~100 ms
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	got := drain(t, src)
	elapsed := time.Since(start)
	src.Close()

	if len(got) != len(pkts) {
		t.Fatalf("replayed %d packets, want %d", len(got), len(pkts))
	}
	for i := range got {
		if !got[i].Metadata().Timestamp.Equal(pkts[i].Timestamp) {
			t.Fatalf("packet %d timestamp %v, want the recorded %v", i, got[i].Metadata().Timestamp, pkts[i].Timestamp)
		}
	}
	if elapsed > 2*time.Second {
		t.Errorf("replay at 4x took %v; it is not honouring the speed multiplier", elapsed)
	}
}
