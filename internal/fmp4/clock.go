package fmp4

import (
	"fmt"
	"math/big"
)

// ClockOpts configures the optional producer-reference-clock audit
// (clock=prft). When Enabled is false the audit is byte-for-byte identical
// to the legacy timeline-only behavior.
type ClockOpts struct {
	Enabled bool
	// MaxSkewUs is the tolerated absolute difference, in microseconds,
	// between the NTP elapsed time and the decode elapsed time of two
	// adjacent prft anchors.
	MaxSkewUs uint64
}

// AuditClock runs the legacy timeline audit first; only if it passes and
// clock.Enabled is set does it additionally verify that every moof is
// anchored to a top-level version 1 prft box whose reference_track_ID matches
// the init track, whose media_time equals the fragment's start tick, whose
// NTP timestamps strictly increase in submission order, and whose adjacent
// clock skew stays within clock.MaxSkewUs microseconds. Legacy error codes
// therefore keep priority over the clock codes.
func AuditClock(initBuf []byte, segs [][]byte, clock ClockOpts) (*Report, *AuditError) {
	rep, aerr := Audit(initBuf, segs)
	if aerr != nil {
		return nil, aerr
	}
	if !clock.Enabled {
		return rep, nil
	}
	if aerr := checkClockAnchors(segs, rep, clock.MaxSkewUs); aerr != nil {
		return nil, aerr
	}
	return rep, nil
}

// checkClockAnchors verifies the prft anchor of every fragment in submission
// order and stamps the validated mediaTime/ntpTimestamp onto the report.
// Fragment indexing mirrors parseMediaSegment: moofs are numbered in segment
// order, then in order of appearance within the segment.
func checkClockAnchors(segs [][]byte, rep *Report, maxSkewUs uint64) *AuditError {
	frag := 0
	var prevNTP, prevMedia uint64
	havePrev := false
	for segIdx, seg := range segs {
		tops, aerr := parseBoxes(seg, 0, segIdx, frag)
		if aerr != nil {
			return aerr // unreachable: the timeline audit already parsed these bytes
		}
		for i := range tops {
			if tops[i].typ != "moof" {
				continue
			}
			if i == 0 || tops[i-1].typ != "prft" {
				return errf(CodeMissingPrft, segIdx, frag,
					"fragment %d is not immediately preceded by a top-level prft box", frag)
			}
			ntp, mediaTime, aerr := parsePrft(&tops[i-1], segIdx, frag, rep.TrackID)
			if aerr != nil {
				return aerr
			}
			want := rep.Fragments[frag].Start
			if mediaTime != want {
				return errf(CodePrftMediaTimeMismatch, segIdx, frag,
					"prft media_time %d does not match fragment start decode tick %d", mediaTime, want)
			}
			if havePrev {
				if ntp <= prevNTP {
					return errf(CodePrftNtpNotIncreasing, segIdx, frag,
						"prft ntp_timestamp %016x does not exceed previous fragment's %016x",
						ntp, prevNTP)
				}
				if exceeded, skewUs := clockSkewExceeded(prevNTP, ntp, prevMedia, mediaTime,
					rep.Timescale, maxSkewUs); exceeded {
					return errf(CodeClockSkewExceeded, segIdx, frag,
						"clock skew of %s microseconds between fragments %d and %d exceeds the %d microsecond budget",
						skewUs, frag-1, frag, maxSkewUs)
				}
			}
			mt := mediaTime
			rep.Fragments[frag].MediaTime = &mt
			rep.Fragments[frag].NtpTimestamp = fmt.Sprintf("%016x", ntp)
			prevNTP, prevMedia, havePrev = ntp, mediaTime, true
			frag++
		}
	}
	return nil
}

// parsePrft validates a version 1 prft box (ISO/IEC 14496-12) and returns its
// 64-bit NTP timestamp and media_time.
func parsePrft(b *box, seg, frag int, trackID uint32) (ntp uint64, mediaTime uint64, aerr *AuditError) {
	version, _, body, aerr := fullBox(b, seg, frag)
	if aerr != nil {
		return 0, 0, aerr
	}
	if version != 1 {
		return 0, 0, errf(CodeBoxStructureInvalid, seg, frag,
			"prft version %d, expected 1", version)
	}
	c := &cursor{b: body}
	ref, ok1 := c.u32()
	ntpV, ok2 := c.u64()
	mt, ok3 := c.u64()
	if !ok1 || !ok2 || !ok3 {
		return 0, 0, errf(CodeBoxStructureInvalid, seg, frag, "prft truncated")
	}
	if ref != trackID {
		return 0, 0, errf(CodePrftTrackMismatch, seg, frag,
			"prft reference_track_ID %d does not match init segment track %d", ref, trackID)
	}
	return ntpV, mt, nil
}

// clockSkewExceeded compares the NTP-measured elapsed time between two
// adjacent anchors with the decode-time elapsed (media ticks at the track
// timescale). It reports whether the absolute difference exceeds maxSkewUs
// microseconds and, if so, renders the actual skew for the error message.
// The comparison is exact big-integer arithmetic:
//
//	|ntpElapsed/2^32 - mediaElapsed/timescale| * 1e6  >  maxSkewUs
//	<=>  |ntpElapsed*timescale - mediaElapsed*2^32| * 1e6  >  maxSkewUs * 2^32 * timescale
func clockSkewExceeded(ntp0, ntp1, media0, media1 uint64, timescale uint32, maxSkewUs uint64) (bool, string) {
	ts := new(big.Int).SetUint64(uint64(timescale))
	ntpScale := new(big.Int).Lsh(big.NewInt(1), 32)

	diff := new(big.Int).Mul(new(big.Int).SetUint64(ntp1-ntp0), ts)
	diff.Sub(diff, new(big.Int).Mul(new(big.Int).SetUint64(media1-media0), ntpScale))
	diff.Abs(diff)
	left := new(big.Int).Mul(diff, big.NewInt(1_000_000))

	right := new(big.Int).SetUint64(maxSkewUs)
	right.Mul(right, ntpScale)
	right.Mul(right, ts)
	if left.Cmp(right) <= 0 {
		return false, ""
	}
	skewUs := new(big.Rat).SetInt(left)
	skewUs.Quo(skewUs, new(big.Rat).SetInt(new(big.Int).Mul(ntpScale, ts)))
	f, _ := skewUs.Float64()
	return true, fmt.Sprintf("%.3f", f)
}
