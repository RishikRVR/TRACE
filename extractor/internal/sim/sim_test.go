package sim

import (
	"bytes"
	"testing"
	"time"
)

func spec(kind string, seed int64) Spec {
	return Spec{ID: "t", Kind: kind, Seed: seed, Start: time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)}
}

// Training data must be reproducible: the same seed has to give byte-identical
// packets, or a reported benchmark cannot be repeated.
func TestGenerateIsDeterministic(t *testing.T) {
	a, err := Generate(spec("full", 42))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(spec("full", 42))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Packets) != len(b.Packets) {
		t.Fatalf("same seed gave %d and %d packets", len(a.Packets), len(b.Packets))
	}
	for i := range a.Packets {
		if !a.Packets[i].Timestamp.Equal(b.Packets[i].Timestamp) || !bytes.Equal(a.Packets[i].Data, b.Packets[i].Data) {
			t.Fatalf("packet %d differs between runs with the same seed", i)
		}
	}
	if len(a.Timeline) != len(b.Timeline) {
		t.Fatalf("timelines differ: %d vs %d intervals", len(a.Timeline), len(b.Timeline))
	}
}

func TestDifferentSeedsDiffer(t *testing.T) {
	a, _ := Generate(spec("full", 1))
	b, _ := Generate(spec("full", 2))
	if len(a.Packets) == len(b.Packets) && bytes.Equal(a.Packets[0].Data, b.Packets[0].Data) {
		t.Error("different seeds produced the same capture")
	}
}

// A full chain must actually contain the stages the label file claims, in
// order, or the forecasting target is meaningless.
func TestFullChainHasOrderedStages(t *testing.T) {
	ep, err := Generate(spec("full", 7))
	if err != nil {
		t.Fatal(err)
	}
	firstOf := map[int]time.Time{}
	for _, iv := range ep.Timeline {
		if cur, ok := firstOf[iv.Stage]; !ok || iv.Start.Before(cur) {
			firstOf[iv.Stage] = iv.Start
		}
	}
	for _, stage := range []int{Recon, InitialAccess, Lateral, C2, Exfil} {
		if _, ok := firstOf[stage]; !ok {
			t.Errorf("full chain is missing stage %d", stage)
		}
	}
	if firstOf[Recon].After(firstOf[InitialAccess]) {
		t.Error("reconnaissance must start before initial access")
	}
	if firstOf[InitialAccess].After(firstOf[Lateral]) {
		t.Error("initial access must start before lateral movement")
	}
	if firstOf[Lateral].After(firstOf[Exfil]) {
		t.Error("lateral movement must start before exfiltration")
	}
}

// A benign episode must carry no attack annotation at all: it is the
// false-alarm test set.
func TestBenignEpisodeHasNoAttackStages(t *testing.T) {
	ep, err := Generate(spec("benign", 3))
	if err != nil {
		t.Fatal(err)
	}
	if len(ep.Timeline) != 0 {
		t.Errorf("benign episode has %d attack intervals, want 0: %+v", len(ep.Timeline), ep.Timeline[0])
	}
	if len(ep.Packets) == 0 {
		t.Error("benign episode has no traffic")
	}
}

// A scan-only episode probes but never gets in, so it must never be labelled
// with an infiltration stage.
func TestScanOnlyNeverReachesInfiltration(t *testing.T) {
	ep, err := Generate(spec("scan_only", 11))
	if err != nil {
		t.Fatal(err)
	}
	for _, iv := range ep.Timeline {
		if iv.Stage != Recon {
			t.Errorf("scan_only produced stage %d (%s), want only reconnaissance", iv.Stage, iv.Family)
		}
	}
}

// The recon probe gap is what the slow-scan sweep varies, so it has to be
// honoured rather than randomised away.
func TestProbeGapIsHonoured(t *testing.T) {
	s := spec("scan_only", 5)
	s.Variant = Variant{ProbeGap: 10 * time.Second}
	ep, err := Generate(s)
	if err != nil {
		t.Fatal(err)
	}
	var recon *Interval
	for i := range ep.Timeline {
		if ep.Timeline[i].Stage == Recon {
			recon = &ep.Timeline[i]
			break
		}
	}
	if recon == nil {
		t.Fatal("no reconnaissance interval")
	}
	if d := recon.End.Sub(recon.Start); d < 5*time.Minute {
		t.Errorf("a 10 s probe gap produced a %s scan; it should stretch over many minutes", d)
	}
}

func TestUnknownKindIsAnError(t *testing.T) {
	if _, err := Generate(spec("nonsense", 1)); err == nil {
		t.Error("want an error for an unknown episode kind")
	}
}
