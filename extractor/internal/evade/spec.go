// Package evade defines base attack scenarios and a taxonomy of realizable,
// problem-space network evasions, plus a deterministic generator that turns
// them into byte-reproducible packet captures. Evasions here preserve the
// attack's realizability (they emit protocol-valid packets), so a measured
// "evaded" result reflects a real detector gap, not an artifact of an
// impossible perturbation.
package evade

import (
	"time"

	"github.com/RishikRVR/trace/extractor/internal/pktgen"
)

// Proto selects how a PacketSpec is serialized.
type Proto int

const (
	ProtoTCP Proto = iota // Ethernet/IPv4/TCP, with optional payload
	ProtoDNS              // Ethernet/IPv4/UDP:53 DNS A-query for QueryName
)

// PacketSpec is a semantic, pre-serialization description of one packet.
// Transforms manipulate slices of PacketSpec (splitting payloads, retiming,
// rewriting DNS names) before anything is serialized, which is what lets an
// evasion stay protocol-valid.
type PacketSpec struct {
	Proto            Proto
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Seq              uint32 // TCP sequence number (contiguous across segments)
	Flags            pktgen.TCPFlags
	Payload          []byte        // TCP payload bytes
	QueryName        string        // DNS query name (ProtoDNS only)
	Offset           time.Duration // capture-time offset from the scenario's base time
}

// clone deep-copies a spec so transforms never mutate shared scenario state.
func (p PacketSpec) clone() PacketSpec {
	cp := p
	if p.Payload != nil {
		cp.Payload = append([]byte(nil), p.Payload...)
	}
	return cp
}

// cloneSpecs deep-copies a spec slice.
func cloneSpecs(in []PacketSpec) []PacketSpec {
	out := make([]PacketSpec, len(in))
	for i, s := range in {
		out[i] = s.clone()
	}
	return out
}

// Serialize turns specs into timestamped pcap packets, with each packet's
// capture time set to base + its Offset.
func Serialize(specs []PacketSpec, base time.Time) ([]pktgen.Packet, error) {
	out := make([]pktgen.Packet, 0, len(specs))
	for _, s := range specs {
		var (
			data []byte
			err  error
		)
		switch s.Proto {
		case ProtoDNS:
			data, err = pktgen.DNSQuery(s.SrcIP, s.DstIP, s.SrcPort, s.QueryName)
		default:
			data, err = pktgen.TCPSeq(s.SrcIP, s.DstIP, s.SrcPort, s.DstPort, s.Seq, s.Flags, s.Payload)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, pktgen.Packet{Data: data, Timestamp: base.Add(s.Offset)})
	}
	return out, nil
}
