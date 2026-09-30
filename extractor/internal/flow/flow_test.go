package flow

import (
	"net"
	"testing"
	"time"
)

func TestNewKey_DirectionAgnostic(t *testing.T) {
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")

	k1 := NewKey(ipA, ipB, 1234, 80, 6)
	k2 := NewKey(ipB, ipA, 80, 1234, 6)

	if k1 != k2 {
		t.Fatalf("expected direction-agnostic keys to be equal:\n k1=%+v\n k2=%+v", k1, k2)
	}
}

func TestGetOrCreate_ReturnsSameStateForBothDirections(t *testing.T) {
	tbl := NewTable(DefaultConfig())
	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	k1 := NewKey(ipA, ipB, 1234, 80, 6)
	s1, isNew1 := tbl.GetOrCreate(k1, now, ipA)
	if !isNew1 {
		t.Fatal("expected first lookup to report isNew=true")
	}

	k2 := NewKey(ipB, ipA, 80, 1234, 6)
	s2, isNew2 := tbl.GetOrCreate(k2, now.Add(time.Second), ipB)
	if isNew2 {
		t.Fatal("expected second lookup (reverse direction) to report isNew=false")
	}
	if s1 != s2 {
		t.Fatal("expected both directions to resolve to the same *State")
	}

	// s1's originator was ipA, so a packet from ipB should read as S2C.
	if got := s1.Direction(ipB); got != "S2C" {
		t.Fatalf("expected S2C for reverse-direction packet, got %s", got)
	}
	if got := s1.Direction(ipA); got != "C2S" {
		t.Fatalf("expected C2S for originator packet, got %s", got)
	}
}

func TestSweep_EvictsIdleFlowsAfterTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPTimeout = 5 * time.Second
	tbl := NewTable(cfg)

	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	k := NewKey(ipA, ipB, 4000, 53, 17) // UDP
	tbl.GetOrCreate(k, t0, ipA)

	if got := tbl.Len(); got != 1 {
		t.Fatalf("expected 1 tracked flow before sweep, got %d", got)
	}

	// Well within the timeout: should survive.
	evicted := tbl.Sweep(t0.Add(2 * time.Second))
	if evicted != 0 || tbl.Len() != 1 {
		t.Fatalf("expected flow to survive a sweep within the idle timeout, evicted=%d len=%d", evicted, tbl.Len())
	}

	// Past the timeout: should be evicted.
	evicted = tbl.Sweep(t0.Add(10 * time.Second))
	if evicted != 1 {
		t.Fatalf("expected 1 eviction after exceeding idle timeout, got %d", evicted)
	}
	if got := tbl.Len(); got != 0 {
		t.Fatalf("expected 0 tracked flows after eviction, got %d", got)
	}
}

func TestSweep_EvictsAtMaxLifetimeEvenIfActive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TCPEstablishedTimeout = time.Hour // idle timeout won't fire
	cfg.MaxLifetime = 5 * time.Second
	tbl := NewTable(cfg)

	ipA := net.ParseIP("10.0.0.1")
	ipB := net.ParseIP("10.0.0.2")
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	k := NewKey(ipA, ipB, 4000, 443, 6) // TCP
	state, _ := tbl.GetOrCreate(k, t0, ipA)
	state.TCPState = "established"

	// "Refresh" LastSeen to simulate ongoing activity, well past MaxLifetime
	// from FirstSeen but not past the (very long) idle timeout.
	tbl.GetOrCreate(k, t0.Add(10*time.Second), ipA)

	evicted := tbl.Sweep(t0.Add(10 * time.Second))
	if evicted != 1 {
		t.Fatalf("expected max-lifetime cap to evict an active flow, got evicted=%d len=%d", evicted, tbl.Len())
	}
}
