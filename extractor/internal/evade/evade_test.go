package evade

import (
	"testing"

	"github.com/RishikRVR/trace/extractor/internal/event"
)

func scenarioByName(t *testing.T, name string) Scenario {
	t.Helper()
	for _, s := range DefaultScenarios() {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("scenario %q not found", name)
	return Scenario{}
}

func transformByName(t *testing.T, name string) Transform {
	t.Helper()
	for _, tr := range DefaultTransforms() {
		if tr.Name == name {
			return tr
		}
	}
	t.Fatalf("transform %q not found", name)
	return Transform{}
}

func TestTCPSegment_SplitsPayloadPreservingBytesAndSeq(t *testing.T) {
	base := scenarioByName(t, "content-eicar").Base()
	out, ok := transformByName(t, "tcp-segment").Apply(base)
	if !ok {
		t.Fatal("tcp-segment should apply to a content scenario")
	}
	if len(out) < 2 {
		t.Fatalf("expected payload split into >=2 segments, got %d", len(out))
	}

	var reassembled []byte
	wantSeq := out[0].Seq
	for _, s := range out {
		if s.Proto != ProtoTCP {
			t.Fatalf("expected TCP segments, got proto %v", s.Proto)
		}
		if s.Seq != wantSeq {
			t.Fatalf("non-contiguous seq: got %d want %d", s.Seq, wantSeq)
		}
		wantSeq += uint32(len(s.Payload))
		reassembled = append(reassembled, s.Payload...)
	}
	if string(reassembled) != EICARString {
		t.Fatalf("reassembled payload != original\n got: %q\nwant: %q", reassembled, EICARString)
	}
}

func TestTimingSpread_RetimesAndIsInapplicableToSinglePacket(t *testing.T) {
	scan := scenarioByName(t, "portscan").Base()
	out, ok := transformByName(t, "timing-spread").Apply(scan)
	if !ok {
		t.Fatal("timing-spread should apply to a multi-packet scan")
	}
	for i := 1; i < len(out); i++ {
		if !(out[i].Offset > out[i-1].Offset) {
			t.Fatalf("offsets not strictly increasing at %d: %v vs %v", i, out[i-1].Offset, out[i].Offset)
		}
	}

	content := scenarioByName(t, "content-eicar").Base()
	if _, ok := transformByName(t, "timing-spread").Apply(content); ok {
		t.Fatal("timing-spread should be inapplicable to a single-packet scenario")
	}
}

func TestPortReduce_DropsBelowThresholdCount(t *testing.T) {
	scan := scenarioByName(t, "portscan").Base()
	out, ok := transformByName(t, "port-reduce").Apply(scan)
	if !ok {
		t.Fatal("port-reduce should apply to the scan")
	}
	if len(out) != 19 {
		t.Fatalf("expected 19 packets after port-reduce, got %d", len(out))
	}
}

func TestDNSLowProfile_ClearsBothLengthAndEntropy(t *testing.T) {
	dns := scenarioByName(t, "dns-tunnel").Base()
	out, ok := transformByName(t, "dns-lowprofile").Apply(dns)
	if !ok {
		t.Fatal("dns-lowprofile should apply to a DNS scenario")
	}
	name := out[0].QueryName
	// IDPS-3001 fires on length>=45 OR entropy>=3.7, so an evasion must clear
	// BOTH sub-conditions. This asserts the transform actually does.
	if len(name) >= 45 {
		t.Fatalf("low-profile name should be < 45 chars, got %d (%q)", len(name), name)
	}
	ent := event.NewDNSMeta(name, "A").EntropyBits
	if ent >= 3.7 {
		t.Fatalf("low-profile name entropy should be < 3.7, got %.3f (%q)", ent, name)
	}
}

func TestApplicability_CrossProtocolIsNA(t *testing.T) {
	content := scenarioByName(t, "content-eicar").Base()
	scan := scenarioByName(t, "portscan").Base()

	if _, ok := transformByName(t, "tcp-segment").Apply(scan); ok {
		t.Fatal("tcp-segment should be n/a to payload-less SYN scan packets")
	}
	if _, ok := transformByName(t, "dns-lowprofile").Apply(content); ok {
		t.Fatal("dns-lowprofile should be n/a to a non-DNS scenario")
	}
	if _, ok := transformByName(t, "port-reduce").Apply(content); ok {
		t.Fatal("port-reduce should be n/a to a single-packet scenario")
	}
}
