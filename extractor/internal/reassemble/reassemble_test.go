package reassemble

import (
	"net"
	"testing"
)

func testMeta() StreamMeta {
	return StreamMeta{
		FlowID: "f1", Dir: "C2S",
		Src: net.ParseIP("10.0.0.1"), Dst: net.ParseIP("10.0.0.2"),
		SrcPort: 1234, DstPort: 80,
	}
}

// collect returns a scanner that records the latest reassembled buffer.
func collect(last *[]byte) *Scanner {
	return NewScanner(func(meta StreamMeta, data []byte, fired map[string]bool) error {
		*last = append([]byte(nil), data...)
		return nil
	}, 1024)
}

func TestReassemble_InOrderSegments(t *testing.T) {
	var last []byte
	s := collect(&last)
	m := testMeta()
	// seq 1 "AB" (covers 1-2), then seq 3 "CD" (covers 3-4).
	if err := s.Segment(m, 1, []byte("AB")); err != nil {
		t.Fatal(err)
	}
	if err := s.Segment(m, 3, []byte("CD")); err != nil {
		t.Fatal(err)
	}
	if string(last) != "ABCD" {
		t.Fatalf("expected reassembled ABCD, got %q", last)
	}
}

func TestReassemble_OutOfOrderThenContiguous(t *testing.T) {
	var last []byte
	s := collect(&last)
	m := testMeta()
	// Arrival order: seq1, then seq5 (ahead — queued), then seq3 (fills the
	// gap and drains the queued seq5).
	s.Segment(m, 1, []byte("AB")) // covers 1-2, next=3
	s.Segment(m, 5, []byte("EF")) // future, queued
	s.Segment(m, 3, []byte("CD")) // contiguous, then drains seq5
	if string(last) != "ABCDEF" {
		t.Fatalf("expected reassembled ABCDEF, got %q", last)
	}
}

func TestReassemble_SplitPatternIsWholeInBuffer(t *testing.T) {
	// The point of reassembly: a pattern split across segments appears whole
	// in the reassembled buffer.
	var last []byte
	s := collect(&last)
	m := testMeta()
	s.Segment(m, 1, []byte("ATT"))
	s.Segment(m, 4, []byte("ACK"))
	if string(last) != "ATTACK" {
		t.Fatalf("expected ATTACK, got %q", last)
	}
}
