package evade

import (
	"time"

	"github.com/RishikRVR/trace/extractor/internal/pktgen"
)

// EICARString is the standard, safe antivirus test string, used as a known
// content-signature payload (matches rule IDPS-2001).
const EICARString = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// highEntropyDNSName is a long, high-entropy label that trips the DNS
// heuristic (rule IDPS-3001) on both its length and entropy sub-conditions.
const highEntropyDNSName = "kq3xf9wprz7mvb2nc8hj4tls6oy1dua5g7pq2xn9m4v8e1w6.tunnel.example.com"

// Scenario is a base attack designed to trip exactly one detector, expressed
// as PacketSpecs so evasions can transform it. AttackID/AttackName are the
// (precise) MITRE ATT&CK technique of the attack itself.
type Scenario struct {
	Name       string
	TargetRule string // rule ID the unmodified attack is expected to trigger
	AttackID   string
	AttackName string
	specs      []PacketSpec
}

// Base returns a fresh deep copy of the scenario's base packet specs, so a
// caller (or transform) can mutate it without disturbing the scenario.
func (s Scenario) Base() []PacketSpec { return cloneSpecs(s.specs) }

// DefaultScenarios returns one base attack per starter detector.
func DefaultScenarios() []Scenario {
	return []Scenario{
		contentEICARScenario(),
		portScanScenario(),
		dnsTunnelScenario(),
	}
}

// contentEICARScenario: a single TCP segment carrying the EICAR string.
// Targets the content signature IDPS-2001. ATT&CK T1105 (tool transfer).
func contentEICARScenario() Scenario {
	return Scenario{
		Name:       "content-eicar",
		TargetRule: "IDPS-2001",
		AttackID:   "T1105",
		AttackName: "Ingress Tool Transfer",
		specs: []PacketSpec{{
			Proto: ProtoTCP,
			SrcIP: "10.0.1.1", DstIP: "10.0.1.2",
			SrcPort: 54321, DstPort: 8080,
			Seq:     1,
			Flags:   pktgen.TCPFlags{PSH: true, ACK: true},
			Payload: []byte(EICARString),
			Offset:  0,
		}},
	}
}

// portScanScenario: 25 SYNs from one source to 25 distinct destination
// ports, 100ms apart (all inside the 5s/20-port window). Targets the
// threshold detector IDPS-1001. ATT&CK T1046.
func portScanScenario() Scenario {
	const n = 25
	specs := make([]PacketSpec, 0, n)
	for i := 0; i < n; i++ {
		specs = append(specs, PacketSpec{
			Proto: ProtoTCP,
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 40000, DstPort: uint16(2000 + i),
			Seq:    1,
			Flags:  pktgen.TCPFlags{SYN: true},
			Offset: time.Duration(i) * 100 * time.Millisecond,
		})
	}
	return Scenario{
		Name:       "portscan",
		TargetRule: "IDPS-1001",
		AttackID:   "T1046",
		AttackName: "Network Service Discovery",
		specs:      specs,
	}
}

// dnsTunnelScenario: one long, high-entropy DNS query. Targets the DNS
// heuristic IDPS-3001. ATT&CK T1071.004.
func dnsTunnelScenario() Scenario {
	return Scenario{
		Name:       "dns-tunnel",
		TargetRule: "IDPS-3001",
		AttackID:   "T1071.004",
		AttackName: "Application Layer Protocol: DNS",
		specs: []PacketSpec{{
			Proto: ProtoDNS,
			SrcIP: "10.0.2.1", DstIP: "10.0.2.2",
			SrcPort:   53001,
			QueryName: highEntropyDNSName,
			Offset:    0,
		}},
	}
}
