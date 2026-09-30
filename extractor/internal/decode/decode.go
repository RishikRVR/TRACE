// Package decode walks a gopacket.Packet's layers and produces the
// canonical event.NetworkEvent record, updating flow state as it goes.
package decode

import (
	"errors"
	"net"

	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/RishikRVR/trace/extractor/internal/event"
	"github.com/RishikRVR/trace/extractor/internal/flow"
)

// ErrUnsupportedPacket is returned for packets with no IPv4/IPv6 network
// layer (e.g. ARP) — callers should skip these rather than treat them as
// a hard failure.
var ErrUnsupportedPacket = errors.New("decode: no IPv4/IPv6 network layer")

// maxPayloadRetain bounds how many payload bytes are copied into the event
// for signature matching, so a single jumbo packet can't force an
// unbounded allocation.
const maxPayloadRetain = 4096

// FromPacket builds a NetworkEvent from pkt, looking up (and updating) its
// flow state in table. table may be nil to skip flow tracking entirely.
func FromPacket(pkt gopacket.Packet, table *flow.Table) (event.NetworkEvent, error) {
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return event.NetworkEvent{}, ErrUnsupportedPacket
	}
	srcIP := net.IP(netLayer.NetworkFlow().Src().Raw())
	dstIP := net.IP(netLayer.NetworkFlow().Dst().Raw())

	var (
		proto    event.Protocol
		protoNum uint8
		srcPort  uint16
		dstPort  uint16
		tcpFlags *event.TCPFlags
		tcpSeq   uint32
		payload  []byte
		hdr      event.PacketHeader
	)

	// IPv4 header fields (TTL and fragmentation) feed the ttl/fragbits keywords.
	if ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		ttl := ip4.TTL
		hdr.IPTTL = &ttl
		hdr.FragBits = &event.IPFragBits{
			MoreFragments: ip4.Flags&layers.IPv4MoreFragments != 0,
			DontFragment:  ip4.Flags&layers.IPv4DontFragment != 0,
			Reserved:      ip4.Flags&layers.IPv4EvilBit != 0,
			Offset:        ip4.FragOffset,
		}
	} else if ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		hop := ip6.HopLimit
		hdr.IPTTL = &hop
	}

	switch t := pkt.Layer(layers.LayerTypeTCP).(type) {
	case *layers.TCP:
		proto, protoNum = event.ProtoTCP, 6
		srcPort, dstPort = uint16(t.SrcPort), uint16(t.DstPort)
		tcpFlags = &event.TCPFlags{SYN: t.SYN, ACK: t.ACK, FIN: t.FIN, RST: t.RST, PSH: t.PSH, URG: t.URG}
		tcpSeq = t.Seq
		payload = t.Payload
		ack, win := t.Ack, t.Window
		hdr.TCPAck, hdr.TCPWindow = &ack, &win
	default:
		switch u := pkt.Layer(layers.LayerTypeUDP).(type) {
		case *layers.UDP:
			proto, protoNum = event.ProtoUDP, 17
			srcPort, dstPort = uint16(u.SrcPort), uint16(u.DstPort)
			payload = u.Payload
		default:
			switch ic := pkt.Layer(layers.LayerTypeICMPv4).(type) {
			case *layers.ICMPv4:
				proto, protoNum = event.ProtoICMP, 1
				typ, code := ic.TypeCode.Type(), ic.TypeCode.Code()
				hdr.ICMPType, hdr.ICMPCode = &typ, &code
				payload = ic.Payload
			default:
				if ic6, ok := pkt.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6); ok {
					proto, protoNum = event.ProtoICMP, 58
					typ, code := ic6.TypeCode.Type(), ic6.TypeCode.Code()
					hdr.ICMPType, hdr.ICMPCode = &typ, &code
					payload = ic6.Payload
				} else {
					proto = event.ProtoOther
				}
			}
		}
	}
	hdr.IPProto = protoNum

	var flowID event.FlowID
	var direction, flowState string
	var flowBits map[string]bool
	if table != nil {
		key := flow.NewKey(srcIP, dstIP, srcPort, dstPort, protoNum)
		ts := pkt.Metadata().CaptureInfo.Timestamp
		state, _ := table.GetOrCreate(key, ts, srcIP)
		flowID = event.FlowID(state.ID)
		direction = state.Direction(srcIP)
		flowBits = state.Bits
		isTCP := proto == event.ProtoTCP && tcpFlags != nil
		if isTCP {
			state.UpdateTCPState(srcIP, tcpFlags.SYN, tcpFlags.ACK, tcpFlags.FIN, tcpFlags.RST, len(payload))
		} else {
			state.CountPacket(srcIP, len(payload))
		}
		flowState = event.FlowNotEstablished
		if state.Established(isTCP) {
			flowState = event.FlowEstablished
		}
	}

	// TLS/SSL metadata for the ssl_state and ssl_version rule keywords.
	var tlsMeta *event.TLSMeta
	var dnp3Meta *event.DNP3Meta
	var httpBufs *event.HTTPBuffers
	if proto == event.ProtoTCP && len(payload) > 0 {
		tlsMeta = event.ParseTLS(payload)
		dnp3Meta = event.ParseDNP3(payload)
		httpBufs = event.ParseHTTP(payload)
	}

	var dnsMeta *event.DNSMeta
	l7 := ""
	if dnsLayer, ok := pkt.Layer(layers.LayerTypeDNS).(*layers.DNS); ok && len(dnsLayer.Questions) > 0 {
		q := dnsLayer.Questions[0]
		meta := event.NewDNSMeta(string(q.Name), q.Type.String())
		dnsMeta = &meta
		l7 = "DNS"
	}

	retainLen := len(payload)
	truncated := false
	if retainLen > maxPayloadRetain {
		retainLen = maxPayloadRetain
		truncated = true
	}
	var payloadCopy []byte
	if retainLen > 0 {
		payloadCopy = append([]byte(nil), payload[:retainLen]...)
	}

	ev := event.NetworkEvent{
		ID:        uuid.NewString(),
		Timestamp: pkt.Metadata().CaptureInfo.Timestamp,
		FlowID:    flowID,
		FiveTuple: event.FiveTuple{
			SrcIP: srcIP, DstIP: dstIP,
			SrcPort: srcPort, DstPort: dstPort,
			Protocol: proto,
		},
		L7Protocol: l7,
		Direction:  direction,
		FlowState:  flowState,
		Payload:    event.PayloadRef{Data: payloadCopy, Length: len(payload), Truncated: truncated},
		PacketLen:  pkt.Metadata().CaptureInfo.Length,
		TCPSeq:     tcpSeq,
		Header:     hdr,
		TLS:        tlsMeta,
		DNP3:       dnp3Meta,
		HTTP:       httpBufs,
		FlowBits:   flowBits,
		TCPFlags:   tcpFlags,
		DNS:        dnsMeta,
	}
	return ev, nil
}
