package fmp4

import (
	"bytes"
	"fmt"
	"testing"

	"fmp4audit/internal/fixture"
)

const (
	ntpEpoch = uint64(0xE8A5B3C4) << 32
	// One 3072-tick fragment at 48000 Hz lasts 64 ms; in NTP 32.32 units
	// (rounded), so the residual rounding skew is ~0.0002 µs per hop.
	ntpHop64ms = uint64(274877907)
)

func clockSeg(seq uint32, base uint64, ntp uint64) []byte {
	return fixture.MediaSegment(fixture.MediaOpts{
		Seq: seq, BaseTime: base, Samples: fixture.Samples(3, 1024, 16),
		Prft: &fixture.PrftSpec{NTP: ntp},
	})
}

func clockOn() ClockOpts { return ClockOpts{Enabled: true, MaxSkewUs: 1000} }

func goodClockSegs() [][]byte {
	return [][]byte{
		clockSeg(1, 0, ntpEpoch),
		clockSeg(2, 3072, ntpEpoch+ntpHop64ms),
		clockSeg(3, 6144, ntpEpoch+2*ntpHop64ms),
	}
}

// expectClockCode audits init+segs in clock=prft mode and requires the given
// error code and indices.
func expectClockCode(t *testing.T, segs [][]byte, code string, seg, frag int) {
	t.Helper()
	_, aerr := AuditClock(goodInit(), segs, clockOn())
	if aerr == nil {
		t.Fatalf("expected %s, got success", code)
	}
	if aerr.Code != code {
		t.Fatalf("expected %s, got %s (%s)", code, aerr.Code, aerr.Message)
	}
	if aerr.SegmentIndex != seg || aerr.FragmentIndex != frag {
		t.Fatalf("expected indices %d/%d, got %d/%d",
			seg, frag, aerr.SegmentIndex, aerr.FragmentIndex)
	}
}

func TestAuditClockValid(t *testing.T) {
	rep, aerr := AuditClock(goodInit(), goodClockSegs(), clockOn())
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.FragmentCount != 3 || rep.TotalDuration != 9216 {
		t.Fatalf("fragments=%d total=%d", rep.FragmentCount, rep.TotalDuration)
	}
	for i, f := range rep.Fragments {
		if f.MediaTime == nil || *f.MediaTime != f.Start {
			t.Fatalf("fragment %d mediaTime=%v, want start=%d", i, f.MediaTime, f.Start)
		}
		want := fmt.Sprintf("%016x", ntpEpoch+uint64(i)*ntpHop64ms)
		if f.NtpTimestamp != want {
			t.Fatalf("fragment %d ntpTimestamp=%q, want %q", i, f.NtpTimestamp, want)
		}
	}
}

func TestAuditClockMultiMoofSegment(t *testing.T) {
	seg := append(clockSeg(1, 0, ntpEpoch), clockSeg(2, 3072, ntpEpoch+ntpHop64ms)...)
	rep, aerr := AuditClock(goodInit(), [][]byte{seg}, clockOn())
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.FragmentCount != 2 {
		t.Fatalf("fragments=%d", rep.FragmentCount)
	}
	for i, f := range rep.Fragments {
		want := fmt.Sprintf("%016x", ntpEpoch+uint64(i)*ntpHop64ms)
		if f.NtpTimestamp != want || f.MediaTime == nil {
			t.Fatalf("fragment %d: %+v", i, f)
		}
	}
}

func TestAuditClockDisabledIgnoresPrft(t *testing.T) {
	segs := goodClockSegs()
	for _, enabled := range []bool{false, true} {
		rep, aerr := AuditClock(goodInit(), segs, ClockOpts{Enabled: enabled, MaxSkewUs: 1000})
		if aerr != nil {
			t.Fatalf("enabled=%v: unexpected error: %+v", enabled, aerr)
		}
		for i, f := range rep.Fragments {
			if !enabled && (f.MediaTime != nil || f.NtpTimestamp != "") {
				t.Fatalf("legacy audit must not report clock anchors, fragment %d: %+v", i, f)
			}
		}
	}
	// The plain legacy entry point accepts prft-bearing segments unchanged.
	rep, aerr := Audit(goodInit(), segs)
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.Fragments[0].MediaTime != nil || rep.Fragments[0].NtpTimestamp != "" {
		t.Fatalf("legacy Audit reported clock anchors: %+v", rep.Fragments[0])
	}
}

func TestAuditClockMissingPrft(t *testing.T) {
	expectClockCode(t, [][]byte{goodSeg(1, 0), clockSeg(2, 3072, ntpEpoch+ntpHop64ms)},
		CodeMissingPrft, 0, 0)
	expectClockCode(t, [][]byte{clockSeg(1, 0, ntpEpoch), goodSeg(2, 3072)},
		CodeMissingPrft, 1, 1)
}

func TestAuditClockPrftNotAdjacent(t *testing.T) {
	// A stray box between prft and moof breaks the "immediately preceding"
	// requirement: styp, prft, free, moof, mdat.
	full := clockSeg(1, 0, ntpEpoch)
	moofAt := bytes.Index(full, []byte("moof")) - 4 // box starts 4 bytes before its type
	seg := append(append(append([]byte{}, full[:moofAt]...), fixture.Box("free", nil)...), full[moofAt:]...)
	expectClockCode(t, [][]byte{seg}, CodeMissingPrft, 0, 0)
}

func TestAuditClockPrftVersion0(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Prft: &fixture.PrftSpec{NTP: ntpEpoch, V0: true},
	})
	expectClockCode(t, [][]byte{seg}, CodeBoxStructureInvalid, 0, 0)
}

func TestAuditClockTrackMismatch(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Prft: &fixture.PrftSpec{TrackID: 9, NTP: ntpEpoch},
	})
	expectClockCode(t, [][]byte{seg}, CodePrftTrackMismatch, 0, 0)
}

func TestAuditClockMediaTimeMismatch(t *testing.T) {
	mt := uint64(1) // fragment starts at tick 0
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Prft: &fixture.PrftSpec{NTP: ntpEpoch, MediaTime: &mt},
	})
	expectClockCode(t, [][]byte{seg}, CodePrftMediaTimeMismatch, 0, 0)
}

func TestAuditClockNtpNotIncreasing(t *testing.T) {
	// Equal timestamps are not strictly increasing.
	expectClockCode(t, [][]byte{
		clockSeg(1, 0, ntpEpoch),
		clockSeg(2, 3072, ntpEpoch),
	}, CodePrftNtpNotIncreasing, 1, 1)
	// Going backwards likewise.
	expectClockCode(t, [][]byte{
		clockSeg(1, 0, ntpEpoch),
		clockSeg(2, 3072, ntpEpoch-1),
	}, CodePrftNtpNotIncreasing, 1, 1)
}

func TestAuditClockSkewExceeded(t *testing.T) {
	// Third anchor is ~10 ms (42949673 NTP units) late against a 1 ms budget.
	drift := ntpEpoch + 2*ntpHop64ms + 42949673
	expectClockCode(t, [][]byte{
		clockSeg(1, 0, ntpEpoch),
		clockSeg(2, 3072, ntpEpoch+ntpHop64ms),
		clockSeg(3, 6144, drift),
	}, CodeClockSkewExceeded, 2, 2)
}

func TestAuditClockSkewWithinBudget(t *testing.T) {
	// ~10 µs of drift per hop is accepted with a 1 ms budget.
	segs := [][]byte{
		clockSeg(1, 0, ntpEpoch),
		clockSeg(2, 3072, ntpEpoch+ntpHop64ms+42950),
		clockSeg(3, 6144, ntpEpoch+2*ntpHop64ms+2*42950),
	}
	rep, aerr := AuditClock(goodInit(), segs, clockOn())
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.FragmentCount != 3 {
		t.Fatalf("fragments=%d", rep.FragmentCount)
	}
}

func TestAuditClockSkewBudgetTight(t *testing.T) {
	// The same ~10 µs drift is rejected with a 5 µs budget.
	segs := [][]byte{
		clockSeg(1, 0, ntpEpoch),
		clockSeg(2, 3072, ntpEpoch+ntpHop64ms+42950),
	}
	_, aerr := AuditClock(goodInit(), segs, ClockOpts{Enabled: true, MaxSkewUs: 5})
	if aerr == nil || aerr.Code != CodeClockSkewExceeded {
		t.Fatalf("expected CLOCK_SKEW_EXCEEDED, got %+v", aerr)
	}
}

func TestAuditClockLegacyErrorKeepsPriority(t *testing.T) {
	// A timeline gap is reported even though the drifting third anchor would
	// also fail the clock audit: legacy codes win.
	drift := ntpEpoch + 2*ntpHop64ms + 42949673
	expectClockCode(t, [][]byte{
		clockSeg(1, 0, ntpEpoch),
		clockSeg(2, 4096, ntpEpoch+ntpHop64ms), // 1024-tick gap
		clockSeg(3, 7168, drift),
	}, CodeTimelineGap, 1, 1)
}
