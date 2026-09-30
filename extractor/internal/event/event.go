// Package event defines the canonical structured record produced by the
// decode layer and consumed by the detection engines.
package event

import (
	"math"
	"net"
	"time"
)

// Protocol is the L4 protocol of a FiveTuple. Only the values below are
// populated in Phase 1; ICMP and OTHER exist so the type doesn't need to
// change shape when more protocols are decoded later.
type Protocol string

const (
	ProtoTCP   Protocol = "TCP"
	ProtoUDP   Protocol = "UDP"
	ProtoICMP  Protocol = "ICMP"
	ProtoOther Protocol = "OTHER"
)

// FiveTuple identifies a connection/datagram exchange.
type FiveTuple struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol Protocol
}

// FlowID is derived from flow.Key and is stable across both packet
// directions of the same connection.
type FlowID string

// PayloadRef references the L4 payload bytes actually retained for
// signature matching, bounded by the capture snaplen.
type PayloadRef struct {
	Data      []byte
	Length    int
	Truncated bool
}

// TCPFlags mirrors the flags on a TCP segment. Nil on non-TCP events.
type TCPFlags struct {
	SYN, ACK, FIN, RST, PSH, URG bool
}

// DNSMeta carries the fields the DNS heuristic detector needs. EntropyBits
// is Shannon entropy of QueryName in bits/char, precomputed once here so
// detectors never recompute it.
type DNSMeta struct {
	QueryName   string
	QueryType   string
	Length      int
	EntropyBits float64
}

// NewDNSMeta builds a DNSMeta from a query name/type, computing entropy once.
func NewDNSMeta(queryName, queryType string) DNSMeta {
	return DNSMeta{
		QueryName:   queryName,
		QueryType:   queryType,
		Length:      len(queryName),
		EntropyBits: shannonEntropy(queryName),
	}
}

// shannonEntropy returns the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// ATTACKTag is a placeholder for future MITRE ATT&CK coverage tagging.
// Always nil in Phase 0/1 — the field exists now so adding tags later
// isn't a breaking schema change.
type ATTACKTag struct {
	TechniqueID string
	Tactic      string
}

// Flow states, as rule.FlowEstablished / rule.FlowNotEstablished spell them.
const (
	FlowEstablished    = "established"
	FlowNotEstablished = "not_established"
)

// NetworkEvent is the canonical record produced by decode.FromPacket and
// consumed by every detector in internal/detect.
type NetworkEvent struct {
	ID         string
	Timestamp  time.Time // capture timestamp from packet metadata, not wall-clock
	FlowID     FlowID
	FiveTuple  FiveTuple
	L7Protocol string // "DNS" | "" — empty if no L7 protocol was decoded
	Direction  string // "C2S" | "S2C" | ""
	FlowState  string // FlowEstablished | FlowNotEstablished | "" (no flow tracking)
	Payload    PayloadRef
	PacketLen  int
	TCPSeq     uint32          // TCP sequence number of this segment (0 for non-TCP)
	FlowBits   map[string]bool // reference to the flow's Snort flowbits (nil if no flow)
	TCPFlags   *TCPFlags
	DNS        *DNSMeta
	TLS        *TLSMeta     // nil unless the payload carries a TLS/SSL record
	DNP3       *DNP3Meta    // nil unless the payload carries a DNP3 frame
	HTTP       *HTTPBuffers // nil unless the payload starts an HTTP message
	ATTACK     *ATTACKTag

	// Header fields used by Snort's non-payload keywords (seq/ack/window/ttl/
	// itype/icode/ip_proto/fragbits). These let rules that carry no payload
	// pattern — scan and malformed-packet signatures — be evaluated.
	Header PacketHeader
}

// PacketHeader carries raw header fields for non-payload rule keywords. Each
// pointer is nil when the field does not exist on this packet, so a rule
// constraining it can fail closed rather than match on a zero value.
type PacketHeader struct {
	TCPAck    *uint32
	TCPWindow *uint16
	IPTTL     *uint8
	IPProto   uint8 // transport protocol number (6 TCP, 17 UDP, 1 ICMP, ...)
	ICMPType  *uint8
	ICMPCode  *uint8
	FragBits  *IPFragBits
}

// IPFragBits mirrors the IPv4 fragmentation flags and offset.
type IPFragBits struct {
	MoreFragments bool
	DontFragment  bool
	Reserved      bool
	Offset        uint16
}
