//go:build linux

package capture

import (
	"fmt"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// LiveBackend names the capture mechanism this build uses, for the sensor's
// startup banner and the console's status line.
const LiveBackend = "AF_PACKET (pure Go)"

type liveSource struct {
	h    *pcapgo.EthernetHandle
	pkts <-chan gopacket.Packet
	stop chan struct{}
}

// NewLiveSource opens iface for live capture using a Linux AF_PACKET socket
// through pcapgo — no cgo and no libpcap, so the sensor ships as a static
// binary. It needs CAP_NET_RAW (setcap cap_net_raw+ep, or root).
//
// timeout is accepted for interface compatibility with the libpcap path and
// is not used: AF_PACKET reads block until a frame arrives.
func NewLiveSource(iface string, snaplen int32, promisc bool, timeout time.Duration) (Source, error) {
	h, err := pcapgo.NewEthernetHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("open live capture on %s (needs CAP_NET_RAW or root): %w", iface, err)
	}
	if snaplen > 0 {
		if err := h.SetCaptureLength(int(snaplen)); err != nil {
			h.Close()
			return nil, fmt.Errorf("set snaplen on %s: %w", iface, err)
		}
	}
	if err := h.SetPromiscuous(promisc); err != nil {
		h.Close()
		return nil, fmt.Errorf("set promiscuous mode on %s: %w", iface, err)
	}
	stop := make(chan struct{})
	return &liveSource{h: h, pkts: packetChan(h, layers.LinkTypeEthernet, stop), stop: stop}, nil
}

func (s *liveSource) Packets() <-chan gopacket.Packet { return s.pkts }
func (s *liveSource) LinkType() layers.LinkType       { return layers.LinkTypeEthernet }

func (s *liveSource) Stats() (Stats, error) {
	st, err := s.h.Stats()
	if err != nil {
		return Stats{}, err
	}
	return Stats{PacketsReceived: uint64(st.Packets), PacketsDropped: uint64(st.Drops)}, nil
}

func (s *liveSource) Close() error {
	close(s.stop)
	return s.h.Close()
}
