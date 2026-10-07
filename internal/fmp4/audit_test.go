package fmp4

import (
	"testing"

	"fmp4audit/internal/fixture"
)

func goodInit() []byte {
	return fixture.InitSegment(fixture.InitOpts{
		Timescale: 48000, TrackID: 1, TrexDuration: 1024, TrexSize: 16,
	})
}

func goodSeg(seq uint32, t uint64) []byte {
	return fixture.MediaSegment(fixture.MediaOpts{
		Seq: seq, BaseTime: t, Samples: fixture.Samples(3, 1024, 16),
	})
}

func TestAuditContinuous(t *testing.T) {
	rep, aerr := Audit(goodInit(), [][]byte{
		goodSeg(1, 0),
		fixture.MediaSegment(fixture.MediaOpts{
			Seq: 2, BaseTime: 3072, Samples: fixture.Samples(3, 1024, 16), TfhdDefaults: true,
		}),
		fixture.MediaSegment(fixture.MediaOpts{
			Seq: 3, BaseTime: 6144, Samples: fixture.Samples(3, 1024, 16), InheritTrex: true,
		}),
	})
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.Timescale != 48000 || rep.TrackID != 1 {
		t.Fatalf("timescale=%d track=%d", rep.Timescale, rep.TrackID)
	}
	if rep.FragmentCount != 3 || rep.TotalDuration != 9216 {
		t.Fatalf("fragments=%d total=%d", rep.FragmentCount, rep.TotalDuration)
	}
	wantStart := []uint64{0, 3072, 6144}
	for i, f := range rep.Fragments {
		if f.Start != wantStart[i] || f.End != wantStart[i]+3072 ||
			f.Samples != 3 || f.SequenceNumber != uint32(i+1) || f.SegmentIndex != i {
			t.Fatalf("fragment %d: %+v", i, f)
		}
	}
}

func TestAuditMultipleMoofsPerSegment(t *testing.T) {
	seg := append(goodSeg(1, 0), goodSeg(2, 3072)...)
	rep, aerr := Audit(goodInit(), [][]byte{seg})
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.FragmentCount != 2 || rep.TotalDuration != 6144 {
		t.Fatalf("fragments=%d total=%d", rep.FragmentCount, rep.TotalDuration)
	}
}

func TestAuditTfdtV0(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 7, BaseTime: 0, TfdtV0: true, Samples: fixture.Samples(2, 1024, 16),
	})
	rep, aerr := Audit(goodInit(), [][]byte{seg})
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.Fragments[0].SequenceNumber != 7 || rep.Fragments[0].Duration != 2048 {
		t.Fatalf("fragment: %+v", rep.Fragments[0])
	}
}

func TestAuditSecondTrun(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0,
		Samples:    fixture.Samples(2, 1024, 16),
		SecondTrun: fixture.Samples(2, 1024, 16),
	})
	rep, aerr := Audit(goodInit(), [][]byte{seg})
	if aerr != nil {
		t.Fatalf("unexpected error: %+v", aerr)
	}
	if rep.Fragments[0].Samples != 4 || rep.Fragments[0].Duration != 4096 {
		t.Fatalf("fragment: %+v", rep.Fragments[0])
	}
}

// expectCode audits init+segs and requires the given error code and indices.
func expectCode(t *testing.T, init []byte, segs [][]byte, code string, seg, frag int) {
	t.Helper()
	_, aerr := Audit(init, segs)
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

func TestAuditTimelineGap(t *testing.T) {
	expectCode(t, goodInit(), [][]byte{goodSeg(1, 0), goodSeg(2, 4096)},
		CodeTimelineGap, 1, 1)
}

func TestAuditTimelineOverlap(t *testing.T) {
	expectCode(t, goodInit(), [][]byte{goodSeg(1, 0), goodSeg(2, 2048)},
		CodeTimelineOverlap, 1, 1)
}

func TestAuditSequenceNotIncreasing(t *testing.T) {
	expectCode(t, goodInit(), [][]byte{goodSeg(5, 0), goodSeg(5, 3072)},
		CodeSequenceNotIncreasing, 1, 1)
}

func TestAuditTrackMismatch(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, TrackID: 2, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
	})
	expectCode(t, goodInit(), [][]byte{seg}, CodeTrackMismatch, 0, 0)
}

func TestAuditMissingMvex(t *testing.T) {
	init := fixture.InitSegment(fixture.InitOpts{Timescale: 48000, TrackID: 1, OmitMvex: true})
	expectCode(t, init, [][]byte{goodSeg(1, 0)}, CodeMissingMvex, -1, -1)
}

func TestAuditNotAudioTrack(t *testing.T) {
	init := fixture.InitSegment(fixture.InitOpts{
		Timescale: 48000, TrackID: 1, Handler: "vide",
		TrexDuration: 1024, TrexSize: 16,
	})
	expectCode(t, init, [][]byte{goodSeg(1, 0)}, CodeNotAudioTrack, -1, -1)
}

func TestAuditTrackCountInvalid(t *testing.T) {
	init := fixture.InitSegment(fixture.InitOpts{
		Timescale: 48000, TrackID: 1, TrexDuration: 1024, TrexSize: 16, ExtraTracks: 1,
	})
	expectCode(t, init, [][]byte{goodSeg(1, 0)}, CodeTrackCountInvalid, -1, -1)
}

func TestAuditMissingMoov(t *testing.T) {
	expectCode(t, []byte("not an mp4 file at all"), [][]byte{goodSeg(1, 0)},
		CodeBoxStructureInvalid, -1, -1)
}

func TestAuditMissingTfdt(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16), OmitTfdt: true,
	})
	expectCode(t, goodInit(), [][]byte{seg}, CodeMissingTfdt, 0, 0)
}

func TestAuditMissingTrun(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16), OmitTrun: true,
	})
	expectCode(t, goodInit(), [][]byte{seg}, CodeMissingTrun, 0, 0)
}

func TestAuditMissingMoof(t *testing.T) {
	expectCode(t, goodInit(), [][]byte{fixture.Box("free", nil)},
		CodeMissingMoof, 0, 0)
}

func TestAuditMissingMdat(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16), OmitMdat: true,
	})
	expectCode(t, goodInit(), [][]byte{seg}, CodeMissingMdat, 0, 0)
}

func TestAuditPayloadOutOfRange(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16), MdatTruncate: 4,
	})
	expectCode(t, goodInit(), [][]byte{seg}, CodePayloadOutOfRange, 0, 0)
}

func TestAuditPayloadOutOfRangeFarOffset(t *testing.T) {
	far := int32(1 << 20)
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16), DataOffset: &far,
	})
	expectCode(t, goodInit(), [][]byte{seg}, CodePayloadOutOfRange, 0, 0)
}

func TestAuditPayloadOverlap(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0,
		Samples:       fixture.Samples(2, 1024, 16),
		SecondTrun:    fixture.Samples(2, 1024, 16),
		SecondOverlap: 8,
	})
	expectCode(t, goodInit(), [][]byte{seg}, CodePayloadOverlap, 0, 0)
}

func TestAuditPayloadNotConsumed(t *testing.T) {
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16), MdatPadTail: 8,
	})
	expectCode(t, goodInit(), [][]byte{seg}, CodePayloadNotConsumed, 0, 0)
}

func TestAuditSampleDurationUnresolvable(t *testing.T) {
	init := fixture.InitSegment(fixture.InitOpts{
		Timescale: 48000, TrackID: 1, TrexDuration: 0, TrexSize: 16,
	})
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16), InheritTrex: true,
	})
	expectCode(t, init, [][]byte{seg}, CodeSampleDurationUnresolvable, 0, 0)
}

func TestAuditSampleSizeUnresolvable(t *testing.T) {
	init := fixture.InitSegment(fixture.InitOpts{
		Timescale: 48000, TrackID: 1, TrexDuration: 1024, TrexSize: 0,
	})
	seg := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16), InheritTrex: true,
	})
	expectCode(t, init, [][]byte{seg}, CodeSampleSizeUnresolvable, 0, 0)
}

func TestAuditBoxStructureTruncated(t *testing.T) {
	seg := goodSeg(1, 0)
	expectCode(t, goodInit(), [][]byte{seg[:len(seg)-3]},
		CodeBoxStructureInvalid, 0, 0)
}

func TestAuditBoxStructureGarbage(t *testing.T) {
	expectCode(t, goodInit(), [][]byte{[]byte{0, 0, 0}},
		CodeBoxStructureInvalid, 0, 0)
}

func TestAuditMissingTrex(t *testing.T) {
	// Init whose trex refers to a different track than the single trak.
	init := fixture.InitSegment(fixture.InitOpts{
		Timescale: 48000, TrackID: 1, TrexDuration: 1024, TrexSize: 16,
	})
	// Corrupt the trex track_ID (last 20-byte trex body starts with track_ID).
	idx := -1
	for i := 0; i+4 <= len(init); i++ {
		if string(init[i:i+4]) == "trex" {
			idx = i + 8 // skip size/type, then version/flags
			break
		}
	}
	if idx < 0 {
		t.Fatal("trex not found in fixture")
	}
	init[idx] = 9 // track_ID 1 -> 9
	expectCode(t, init, [][]byte{goodSeg(1, 0)}, CodeMissingTrex, -1, -1)
}
