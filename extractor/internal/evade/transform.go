package evade

import (
	"strings"
	"time"
)

// Transform is one realizable, problem-space evasion. Category names the
// evasion class from the literature (precise); AttackRef is a best-effort
// MITRE ATT&CK technique for the evasion itself and may be approximate or
// empty — the base attack's ATT&CK mapping (on Scenario) is the precise one.
type Transform struct {
	Name      string
	Category  string
	Tactic    string
	AttackRef string
	apply     func([]PacketSpec) ([]PacketSpec, bool)
}

// Apply runs the transform against a defensive copy of specs. It returns
// (variant, true) when the transform is applicable and changed the traffic,
// or (nil, false) when it does not apply to this scenario.
func (t Transform) Apply(specs []PacketSpec) ([]PacketSpec, bool) {
	return t.apply(cloneSpecs(specs))
}

// DefaultTransforms returns the starter evasion taxonomy.
func DefaultTransforms() []Transform {
	return []Transform{
		tcpSegment(2),
		timingSpread(400 * time.Millisecond),
		portReduce(19),
		dnsWordEncode(),
		dnsLowProfile(),
	}
}

// tcpSegment splits every TCP payload across n contiguous segments (same
// 5-tuple, contiguous sequence numbers). Because the sensor matches
// signatures per packet and does not reassemble TCP streams, a pattern
// straddling a segment boundary is not seen — a functionality-preserving
// evasion (the bytes on the wire are unchanged, only their framing differs).
func tcpSegment(n int) Transform {
	return Transform{
		Name:      "tcp-segment",
		Category:  "TCP segmentation (payload split across segments)",
		Tactic:    "Defense Evasion",
		AttackRef: "T1027", // Obfuscated Files or Information (approx.)
		apply: func(specs []PacketSpec) ([]PacketSpec, bool) {
			var out []PacketSpec
			changed := false
			for _, s := range specs {
				if s.Proto != ProtoTCP || len(s.Payload) < 2 {
					out = append(out, s)
					continue
				}
				parts := splitBytes(s.Payload, n)
				if len(parts) < 2 {
					out = append(out, s)
					continue
				}
				changed = true
				seq := s.Seq
				for i, part := range parts {
					seg := s.clone()
					seg.Payload = part
					seg.Seq = seq
					// PSH only on the final segment; keep ACK throughout.
					seg.Flags.PSH = i == len(parts)-1
					seg.Flags.ACK = true
					seg.Offset = s.Offset + time.Duration(i)*time.Millisecond
					seq += uint32(len(part))
					out = append(out, seg)
				}
			}
			return out, changed
		},
	}
}

// timingSpread re-times a multi-packet scenario so successive packets are
// spacing apart, defeating time-window threshold detectors (the classic
// slow-and-low scan). Functionality-preserving: same packets, slower.
func timingSpread(spacing time.Duration) Transform {
	return Transform{
		Name:      "timing-spread",
		Category:  "Timing (slow-and-low)",
		Tactic:    "Defense Evasion",
		AttackRef: "", // no clean ATT&CK technique for scan timing
		apply: func(specs []PacketSpec) ([]PacketSpec, bool) {
			if len(specs) < 2 {
				return nil, false
			}
			for i := range specs {
				specs[i].Offset = time.Duration(i) * spacing
			}
			return specs, true
		},
	}
}

// portReduce keeps only the first `keep` TCP packets, dropping a scan below
// a count-based threshold (threshold-adjacent evasion). Reduces coverage
// per source — the attacker would spread the scan across sources/time.
func portReduce(keep int) Transform {
	return Transform{
		Name:      "port-reduce",
		Category:  "Threshold-adjacent (sub-threshold volume)",
		Tactic:    "Defense Evasion",
		AttackRef: "",
		apply: func(specs []PacketSpec) ([]PacketSpec, bool) {
			var tcp []PacketSpec
			for _, s := range specs {
				if s.Proto == ProtoTCP {
					tcp = append(tcp, s)
				}
			}
			if len(tcp) <= keep {
				return nil, false
			}
			return tcp[:keep], true
		},
	}
}

// dnsWordEncode rewrites a DNS query to a long, low-entropy dictionary-word
// name. It targets the entropy sub-condition of the DNS heuristic — but the
// rule triggers on length OR entropy, so a long name still fires. Included
// to measure that the OR semantics defeat entropy-only evasion.
func dnsWordEncode() Transform {
	words := []string{"data", "node", "sync", "edge", "link", "host", "peer", "core", "mesh", "gate"}
	return Transform{
		Name:      "dns-word-encode",
		Category:  "Entropy reduction (dictionary encoding)",
		Tactic:    "Defense Evasion",
		AttackRef: "T1027",
		apply: func(specs []PacketSpec) ([]PacketSpec, bool) {
			changed := false
			for i := range specs {
				if specs[i].Proto != ProtoDNS {
					continue
				}
				var b strings.Builder
				j := 0
				for b.Len() < 48 {
					if j > 0 {
						b.WriteByte('-')
					}
					b.WriteString(words[j%len(words)])
					j++
				}
				specs[i].QueryName = b.String() + ".example.com"
				changed = true
			}
			return specs, changed
		},
	}
}

// dnsLowProfile rewrites a DNS query to a short, low-entropy name that
// clears both the length and entropy sub-conditions. Functionality is
// reduced (far less data per query), which is the real cost of this evasion.
func dnsLowProfile() Transform {
	return Transform{
		Name:      "dns-lowprofile",
		Category:  "Low-profile query (length + entropy reduction)",
		Tactic:    "Defense Evasion",
		AttackRef: "T1027",
		apply: func(specs []PacketSpec) ([]PacketSpec, bool) {
			changed := false
			for i := range specs {
				if specs[i].Proto != ProtoDNS {
					continue
				}
				specs[i].QueryName = "cdn.example.com"
				changed = true
			}
			return specs, changed
		},
	}
}

// splitBytes divides b into n roughly-equal, non-empty parts (fewer if b is
// shorter than n).
func splitBytes(b []byte, n int) [][]byte {
	if n < 1 {
		n = 1
	}
	if len(b) < n {
		n = len(b)
	}
	if n < 1 {
		return [][]byte{b}
	}
	out := make([][]byte, 0, n)
	size := len(b) / n
	rem := len(b) % n
	start := 0
	for i := 0; i < n; i++ {
		end := start + size
		if i < rem {
			end++
		}
		out = append(out, append([]byte(nil), b[start:end]...))
		start = end
	}
	return out
}
