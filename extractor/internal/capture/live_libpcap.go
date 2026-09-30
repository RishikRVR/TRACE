//go:build !linux

package capture

import (
	"fmt"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// LiveBackend names the capture mechanism this build uses, for the sensor's
// startup banner and the console's status line.
const LiveBackend = "libpcap"

type liveSource struct {
	handle *pcap.Handle
	ps     *gopacket.PacketSource
}

// NewLiveSource opens iface for live capture via libpcap (macOS and other
// non-Linux platforms; Linux uses the pure-Go AF_PACKET path instead). On
// macOS this requires read access to /dev/bpf*, via ChmodBPF or root.
func NewLiveSource(iface string, snaplen int32, promisc bool, timeout time.Duration) (Source, error) {
	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		return nil, fmt.Errorf("open live capture on %s (needs /dev/bpf access): %w", iface, err)
	}
	return &liveSource{handle: handle, ps: gopacket.NewPacketSource(handle, handle.LinkType())}, nil
}

func (s *liveSource) Packets() <-chan gopacket.Packet { return s.ps.Packets() }
func (s *liveSource) LinkType() layers.LinkType       { return s.handle.LinkType() }

func (s *liveSource) Stats() (Stats, error) {
	st, err := s.handle.Stats()
	if err != nil {
		return Stats{}, err
	}
	return Stats{PacketsReceived: uint64(st.PacketsReceived), PacketsDropped: uint64(st.PacketsDropped)}, nil
}

func (s *liveSource) Close() error {
	s.handle.Close()
	return nil
}
