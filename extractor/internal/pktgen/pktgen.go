// Package pktgen deterministically builds synthetic Ethernet/IPv4/TCP/UDP/DNS
// packets and writes them to classic pcap files. It is the shared,
// production-importable packet-construction layer used both by the fixture
// generator (testdata/gen) and by the evasion benchmark (internal/evade).
//
// It was promoted out of testdata/ specifically so non-test code can import
// it without depending on a test-only directory.
package pktgen

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var (
	srcMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
)

// Packet pairs serialized packet bytes with the capture timestamp to write
// alongside them in the pcap file.
type Packet struct {
	Data      []byte
	Timestamp time.Time
}

// TCPFlags selects which TCP control bits are set on a built packet.
type TCPFlags struct {
	SYN, ACK, FIN, RST, PSH bool
}

func ipv4(srcIP, dstIP string) (net.IP, net.IP) {
	return net.ParseIP(srcIP).To4(), net.ParseIP(dstIP).To4()
}

// Opts sets the header fields that TCP, UDP and DNSQuery fix (TTL 64, TCP
// window 65535, DF clear), so simulated hosts and attack tools can carry
// realistic OS and tool fingerprints. Window is used as given; TTL 0 means 64.
type Opts struct {
	TTL    uint8
	Window uint16
	DF     bool
	Ack    uint32
}

// DefaultOpts is what the builders without an Opts argument use.
var DefaultOpts = Opts{TTL: 64, Window: 65535}

func ipHeader(srcIP, dstIP string, proto layers.IPProtocol, o Opts) *layers.IPv4 {
	sip, dip := ipv4(srcIP, dstIP)
	ttl := o.TTL
	if ttl == 0 {
		ttl = 64
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: ttl, Protocol: proto, SrcIP: sip, DstIP: dip}
	if o.DF {
		ip.Flags = layers.IPv4DontFragment
	}
	return ip
}

// TCP builds a single Ethernet/IPv4/TCP packet with the given payload.
func TCP(srcIP, dstIP string, srcPort, dstPort uint16, flags TCPFlags, payload []byte) ([]byte, error) {
	return tcpSeq(srcIP, dstIP, srcPort, dstPort, 1, flags, payload)
}

// tcpSeq is TCP with an explicit sequence number, so callers that build
// multi-segment streams (e.g. evasion transforms) can lay segments out
// contiguously.
func tcpSeq(srcIP, dstIP string, srcPort, dstPort uint16, seq uint32, flags TCPFlags, payload []byte) ([]byte, error) {
	return TCPWith(srcIP, dstIP, srcPort, dstPort, seq, flags, payload, DefaultOpts)
}

// TCPWith is TCPSeq with explicit header options.
func TCPWith(srcIP, dstIP string, srcPort, dstPort uint16, seq uint32, flags TCPFlags, payload []byte, o Opts) ([]byte, error) {
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := ipHeader(srcIP, dstIP, layers.IPProtocolTCP, o)
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     o.Ack,
		Window:  o.Window,
		SYN:     flags.SYN,
		ACK:     flags.ACK,
		FIN:     flags.FIN,
		RST:     flags.RST,
		PSH:     flags.PSH,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, fmt.Errorf("set tcp checksum network layer: %w", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("serialize tcp packet: %w", err)
	}
	return append([]byte(nil), buf.Bytes()...), nil
}

// TCPSeq exposes explicit-sequence TCP construction for evasion transforms
// that segment a payload across multiple packets.
func TCPSeq(srcIP, dstIP string, srcPort, dstPort uint16, seq uint32, flags TCPFlags, payload []byte) ([]byte, error) {
	return tcpSeq(srcIP, dstIP, srcPort, dstPort, seq, flags, payload)
}

// UDP builds a single Ethernet/IPv4/UDP packet with the given payload.
func UDP(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	return UDPWith(srcIP, dstIP, srcPort, dstPort, payload, DefaultOpts)
}

// UDPWith is UDP with explicit header options (Window and Ack are ignored).
func UDPWith(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, o Opts) ([]byte, error) {
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := ipHeader(srcIP, dstIP, layers.IPProtocolUDP, o)
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, fmt.Errorf("set udp checksum network layer: %w", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("serialize udp packet: %w", err)
	}
	return append([]byte(nil), buf.Bytes()...), nil
}

// DNSQuery builds a single Ethernet/IPv4/UDP/DNS query packet (dst port 53)
// asking for an A record for queryName.
func DNSQuery(srcIP, dstIP string, srcPort uint16, queryName string) ([]byte, error) {
	return DNSQueryWith(srcIP, dstIP, srcPort, queryName, DefaultOpts)
}

// DNSQueryWith is DNSQuery with explicit header options.
func DNSQueryWith(srcIP, dstIP string, srcPort uint16, queryName string, o Opts) ([]byte, error) {
	return dnsPacket(srcIP, dstIP, srcPort, 53, queryName, nil, o)
}

// DNSResponseWith builds the answer to a DNSQueryWith: from port 53 back to
// dstPort, carrying one A record for queryName.
func DNSResponseWith(srcIP, dstIP string, dstPort uint16, queryName string, answer net.IP, o Opts) ([]byte, error) {
	return dnsPacket(srcIP, dstIP, 53, dstPort, queryName, answer.To4(), o)
}

func dnsPacket(srcIP, dstIP string, srcPort, dstPort uint16, queryName string, answer net.IP, o Opts) ([]byte, error) {
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := ipHeader(srcIP, dstIP, layers.IPProtocolUDP, o)
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, fmt.Errorf("set udp checksum network layer: %w", err)
	}
	dns := &layers.DNS{
		ID:      0x1234,
		QR:      answer != nil,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      true,
		QDCount: 1,
		Questions: []layers.DNSQuestion{
			{Name: []byte(queryName), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}
	if answer != nil {
		dns.RA = true
		dns.ANCount = 1
		dns.Answers = []layers.DNSResourceRecord{
			{Name: []byte(queryName), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 300, IP: answer},
		}
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
		return nil, fmt.Errorf("serialize dns query packet: %w", err)
	}
	return append([]byte(nil), buf.Bytes()...), nil
}

// AsPacket parses a built packet back into a gopacket.Packet stamped with its
// capture time, exactly as a pcap reader would hand it to the decoder. It lets
// the simulator feed the extractor in-process without a pcap round trip.
func AsPacket(p Packet) gopacket.Packet {
	pkt := gopacket.NewPacket(p.Data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	md := pkt.Metadata()
	md.Timestamp = p.Timestamp
	md.CaptureLength = len(p.Data)
	md.Length = len(p.Data)
	return pkt
}

// WritePcap writes pkts, in order, to a classic pcap file at path.
func WritePcap(path string, pkts []Packet) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return fmt.Errorf("write pcap header %s: %w", path, err)
	}
	for i, p := range pkts {
		ci := gopacket.CaptureInfo{
			Timestamp:     p.Timestamp,
			CaptureLength: len(p.Data),
			Length:        len(p.Data),
		}
		if err := w.WritePacket(ci, p.Data); err != nil {
			return fmt.Errorf("write packet %d to %s: %w", i, path, err)
		}
	}
	return nil
}
