// Package capture provides a single Source interface behind which live
// packet capture and offline pcap/pcapng replay are indistinguishable to the
// rest of the pipeline.
//
// File replay and the Linux live path are both pure Go, so the sensor builds
// with CGO_ENABLED=0 into a static binary. Only the non-Linux live path
// (macOS) needs libpcap; see live_libpcap.go.
package capture

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Stats reports capture-level counters. Always the zero value for a
// FileSource, since a capture file has no "dropped" concept.
type Stats struct {
	PacketsReceived uint64
	PacketsDropped  uint64
}

// Source is implemented by both the live and file capture paths. Everything
// downstream of capture consumes only this interface, so live vs. replay is
// invisible to decode/flow/features.
type Source interface {
	Packets() <-chan gopacket.Packet
	LinkType() layers.LinkType
	Stats() (Stats, error)
	Close() error
}

// --- File (offline replay) source --------------------------------------

type fileSource struct {
	f    *os.File
	ps   *gopacket.PacketSource
	link layers.LinkType
}

// pcapng files start with a Section Header Block (type 0x0A0D0D0A); classic
// pcap starts with one of the four byte orders of magic 0xA1B2C3D4.
func isPcapng(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x0A && b[1] == 0x0D && b[2] == 0x0D && b[3] == 0x0A
}

// NewFileSource opens a classic pcap or pcapng file for replay using pcapgo,
// a pure-Go reader with no libpcap dependency. This is the path used for
// tests and CI, where there may be no capture permissions at all.
func NewFileSource(path string) (Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open capture file %s: %w", path, err)
	}
	br := bufio.NewReaderSize(f, 1<<20)
	magic, err := br.Peek(4)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var (
		src  gopacket.PacketDataSource
		link layers.LinkType
	)
	if isPcapng(magic) {
		r, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("read pcapng header %s: %w", path, err)
		}
		src, link = r, r.LinkType()
	} else {
		r, err := pcapgo.NewReader(br)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("read pcap header %s: %w", path, err)
		}
		src, link = r, r.LinkType()
	}
	return &fileSource{f: f, ps: gopacket.NewPacketSource(src, link), link: link}, nil
}

func (s *fileSource) Packets() <-chan gopacket.Packet { return s.ps.Packets() }
func (s *fileSource) LinkType() layers.LinkType       { return s.link }
func (s *fileSource) Stats() (Stats, error)           { return Stats{}, nil }
func (s *fileSource) Close() error                    { return s.f.Close() }

// --- Replay at wall-clock pace ------------------------------------------

// NewReplaySource replays a capture file through the live code path, pacing
// packets by their recorded gaps divided by speed (speed 1 = real time). It
// is how the live pipeline is exercised without putting traffic on a network.
//
// Recorded timestamps are preserved, so windows fall on the same boundaries
// as a batch run over the same file and a fast replay simply advances the
// forecast timeline faster.
func NewReplaySource(path string, speed float64) (Source, error) {
	inner, err := NewFileSource(path)
	if err != nil {
		return nil, err
	}
	if speed <= 0 {
		speed = 1
	}
	out := make(chan gopacket.Packet, 1024)
	r := &replaySource{inner: inner, out: out}
	go r.run(speed)
	return r, nil
}

type replaySource struct {
	inner Source
	out   chan gopacket.Packet
	seen  uint64
}

func (r *replaySource) run(speed float64) {
	defer close(r.out)
	var first, start time.Time
	for pkt := range r.inner.Packets() {
		ts := pkt.Metadata().CaptureInfo.Timestamp
		if first.IsZero() {
			first, start = ts, time.Now()
		}
		if d := time.Duration(float64(ts.Sub(first))/speed) - time.Since(start); d > 0 {
			time.Sleep(d)
		}
		r.seen++
		r.out <- pkt
	}
}

func (r *replaySource) Packets() <-chan gopacket.Packet { return r.out }
func (r *replaySource) LinkType() layers.LinkType       { return r.inner.LinkType() }
func (r *replaySource) Stats() (Stats, error)           { return Stats{PacketsReceived: r.seen}, nil }
func (r *replaySource) Close() error                    { return r.inner.Close() }

// --- shared live plumbing ------------------------------------------------

// packetChan turns a data source into the channel Source exposes, stopping on
// the first non-recoverable read error.
func packetChan(src gopacket.PacketDataSource, link layers.LinkType, stop <-chan struct{}) <-chan gopacket.Packet {
	ps := gopacket.NewPacketSource(src, link)
	ps.NoCopy = false
	out := make(chan gopacket.Packet, 4096)
	go func() {
		defer close(out)
		for {
			pkt, err := ps.NextPacket()
			if err != nil {
				if err == io.EOF {
					return
				}
				continue // a malformed frame must not kill a live sensor
			}
			select {
			case out <- pkt:
			case <-stop:
				return
			}
		}
	}()
	return out
}
