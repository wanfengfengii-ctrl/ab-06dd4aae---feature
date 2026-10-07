package fmp4

import (
	"testing"

	"fmp4audit/internal/fixture"
)

// prftSeg builds a standard 3-sample fragment (3072 ticks @48000 Hz) with a
// version 1 prft directly before its moof.
func prftSeg(seq uint32, base uint64, trackID uint32, ntp, mediaTime uint64) []byte {
	return fixture.MediaSegment(fixture.MediaOpts{
		Seq: seq, BaseTime: base, Samples: fixture.Samples(3, 1024, 16),
		Prft: &fixture.PrftOpts{TrackID: trackID, Ntp: ntp, MediaTime: mediaTime},
	})
}

// ntpStep is the NTP 32.32 duration of one 3072-tick fragment @48000 Hz
// (0.064 s). The true value is fractional (274877906.944); rounding to the
// nearest fractional unit leaves a sub-nanosecond residual, far below any
// microsecond threshold.
const ntpStep = uint64(274_877_907)

func prftOpts(maxSkewUs int64) Options {
	return Options{Clock: ClockPrft, MaxClockSkewUs: maxSkewUs}
}

func expectCodeOpts(t *testing.T, init []byte, segs [][]byte, opts Options, code string, seg, frag int) {
	t.Helper()
	_, aerr := AuditWithOptions(init, segs, opts)
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

func TestAuditPrftAccepted(t *testing.T) {
	base := uint64(1) << 32 // 1 second in NTP 32.32
	segs := [][]byte{
		prftSeg(1, 0, 1, base, 0),
		prftSeg(2, 3072, 1, base+ntpStep, 3072),
		prftSeg(3, 6144, 1, base+2*ntpStep, 6144),
	}
	rep, aerr := AuditWithOptions(goodInit(), segs, prftOpts(1000))
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.FragmentCount != 3 {
		t.Fatalf("fragments=%d", rep.FragmentCount)
	}
	wantMedia := []uint64{0, 3072, 6144}
	wantNtp := []string{
		"0000000100000000",
		"0000000110624dd3",
		"0000000120c49ba6",
	}
	for i, f := range rep.Fragments {
		if f.MediaTime == nil || *f.MediaTime != wantMedia[i] {
			t.Fatalf("fragment %d mediaTime=%v want %d", i, f.MediaTime, wantMedia[i])
		}
		if f.NtpTimestamp == nil {
			t.Fatalf("fragment %d missing ntpTimestamp", i)
		}
		// Compare case-insensitively only to guard the hand-computed literals;
		// the contract is lowercase, asserted separately below.
		if !eqFold(*f.NtpTimestamp, wantNtp[i]) {
			t.Fatalf("fragment %d ntp=%s want %s", i, *f.NtpTimestamp, wantNtp[i])
		}
		for _, c := range *f.NtpTimestamp {
			if c >= 'A' && c <= 'Z' {
				t.Fatalf("fragment %d ntp %q is not lowercase hex", i, *f.NtpTimestamp)
			}
		}
	}
}

func eqFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func TestAuditPrftHexPadding(t *testing.T) {
	// A small timestamp must render as 16 lowercase hex digits.
	seg := prftSeg(1, 0, 1, 0xAB, 0)
	rep, aerr := AuditWithOptions(goodInit(), [][]byte{seg}, prftOpts(1000))
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if got := rep.Fragments[0].NtpTimestamp; got == nil || *got != "00000000000000ab" {
		t.Fatalf("ntp=%v", got)
	}
}

func TestAuditPrftZeroNtpStillReported(t *testing.T) {
	// The very first anchor may legitimately carry ntp 0; the field must
	// still be present (and zero-padded), not dropped by serialization.
	seg := prftSeg(1, 0, 1, 0, 0)
	rep, aerr := AuditWithOptions(goodInit(), [][]byte{seg}, prftOpts(1000))
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	got := rep.Fragments[0].NtpTimestamp
	if got == nil {
		t.Fatalf("ntpTimestamp missing despite clock=prft")
	}
	if *got != "0000000000000000" {
		t.Fatalf("ntp=%q", *got)
	}
}

// Legacy audits ignore any prft boxes entirely.
func TestAuditPrftIgnoredInDecodeMode(t *testing.T) {
	seg := prftSeg(1, 0, 9, 12345, 777)
	if _, aerr := Audit(goodInit(), [][]byte{seg}); aerr != nil {
		t.Fatalf("decode-mode audit rejected a segment carrying prft: %+v", aerr)
	}
}

func TestAuditPrftMissing(t *testing.T) {
	// First fragment has no prft at all.
	expectCodeOpts(t, goodInit(), [][]byte{goodSeg(1, 0)}, prftOpts(1000),
		CodeMissingPrft, 0, 0)

	// Second fragment dropped its anchor.
	segs := [][]byte{
		prftSeg(1, 0, 1, 1<<32, 0),
		goodSeg(2, 3072),
	}
	expectCodeOpts(t, goodInit(), segs, prftOpts(1000), CodeMissingPrft, 1, 1)
}

func TestAuditPrftNotAdjacent(t *testing.T) {
	mk := func(placement fixture.PrftPlacement) []byte {
		return fixture.MediaSegment(fixture.MediaOpts{
			Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
			Prft: &fixture.PrftOpts{Ntp: 1 << 32, MediaTime: 0, Placement: placement},
		})
	}
	expectCodeOpts(t, goodInit(), [][]byte{mk(fixture.PrftBeforeMoofWithGap)},
		prftOpts(1000), CodePrftNotAdjacent, 0, 0)
	// A prft after the moof leaves the moof without a preceding anchor.
	expectCodeOpts(t, goodInit(), [][]byte{mk(fixture.PrftAfterMoof)},
		prftOpts(1000), CodeMissingPrft, 0, 0)
	// A trailing prft after mdat is not adjacent to any moof; the moof is
	// reported first as missing its anchor.
	expectCodeOpts(t, goodInit(), [][]byte{mk(fixture.PrftSegmentEnd)},
		prftOpts(1000), CodeMissingPrft, 0, 0)
}

func TestAuditPrftVersion0(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
		Prft: &fixture.PrftOpts{Ntp: 1 << 32, MediaTime: 0, V0: true},
	})
	expectCodeOpts(t, goodInit(), [][]byte{seg}, prftOpts(1000),
		CodePrftVersion, 0, 0)
}

func TestAuditPrftTrackMismatch(t *testing.T) {
	seg := prftSeg(1, 0, 2, 1<<32, 0)
	expectCodeOpts(t, goodInit(), [][]byte{seg}, prftOpts(1000),
		CodePrftTrackMismatch, 0, 0)
}

func TestAuditPrftMediaTimeMismatch(t *testing.T) {
	seg := prftSeg(1, 0, 1, 1<<32, 512)
	expectCodeOpts(t, goodInit(), [][]byte{seg}, prftOpts(1000),
		CodePrftMediaTime, 0, 0)
}

func TestAuditPrftNtpNotIncreasing(t *testing.T) {
	segs := [][]byte{
		prftSeg(1, 0, 1, 1<<32, 0),
		prftSeg(2, 3072, 1, 1<<32, 3072), // equal timestamp
	}
	expectCodeOpts(t, goodInit(), segs, prftOpts(1000),
		CodePrftNtpNotIncrease, 1, 1)

	segs[1] = prftSeg(2, 3072, 1, 1<<32-1, 3072) // backwards
	expectCodeOpts(t, goodInit(), segs, prftOpts(1000),
		CodePrftNtpNotIncrease, 1, 1)
}

func TestAuditPrftDrift(t *testing.T) {
	// Second anchor advances an extra ~1 ms beyond the decoded duration.
	segs := [][]byte{
		prftSeg(1, 0, 1, 1<<32, 0),
		prftSeg(2, 3072, 1, 1<<32+ntpStep+4295, 3072),
	}
	expectCodeOpts(t, goodInit(), segs, prftOpts(1),
		CodeClockDrift, 1, 1)
}

func TestAuditPrftDriftBoundary(t *testing.T) {
	// Use a fragment step whose media duration maps exactly onto NTP units:
	// 3000 ticks @48000 Hz = 62500 us = 2^28 NTP fractional units.
	const tickStep = uint64(3000)
	const exactNtpStep = uint64(1) << 28
	mk := func(ntp uint64) []byte {
		return fixture.MediaSegment(fixture.MediaOpts{
			Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1000, 16),
			Prft: &fixture.PrftOpts{Ntp: ntp, MediaTime: 0},
		})
	}
	mk2 := func(ntp uint64) []byte {
		return fixture.MediaSegment(fixture.MediaOpts{
			Seq: 2, BaseTime: tickStep, Samples: fixture.Samples(3, 1000, 16),
			Prft: &fixture.PrftOpts{Ntp: ntp, MediaTime: tickStep},
		})
	}

	// +4294 fractional units is 0.99977 us: inside a 1 us threshold.
	if _, aerr := AuditWithOptions(goodInit(),
		[][]byte{mk(1 << 32), mk2(1<<32 + exactNtpStep + 4294)},
		prftOpts(1)); aerr != nil {
		t.Fatalf("drift within threshold rejected: %+v", aerr)
	}
	// +4295 fractional units is 1.00001 us: beyond the 1 us threshold.
	expectCodeOpts(t, goodInit(),
		[][]byte{mk(1 << 32), mk2(1<<32 + exactNtpStep + 4295)},
		prftOpts(1), CodeClockDrift, 1, 1)
	// The same deviation is accepted with a more permissive threshold.
	if _, aerr := AuditWithOptions(goodInit(),
		[][]byte{mk(1 << 32), mk2(1<<32 + exactNtpStep + 4295)},
		prftOpts(2)); aerr != nil {
		t.Fatalf("drift within 2 us threshold rejected: %+v", aerr)
	}
}

func TestAuditPrftMultipleMoofsPerSegment(t *testing.T) {
	// One uploaded segment containing two anchored moofs.
	one := prftSeg(1, 0, 1, 1<<32, 0)
	two := prftSeg(2, 3072, 1, 1<<32+ntpStep, 3072)
	// Each fixture segment starts with an styp; concatenation leaves the
	// second prft directly before its moof anyway (styp precedes the prft).
	seg := append(one, two...)
	rep, aerr := AuditWithOptions(goodInit(), [][]byte{seg}, prftOpts(1000))
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.FragmentCount != 2 {
		t.Fatalf("fragments=%d", rep.FragmentCount)
	}
}
