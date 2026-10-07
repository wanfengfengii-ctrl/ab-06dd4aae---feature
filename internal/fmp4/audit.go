package fmp4

// tfhd / trun flag bits (ISO/IEC 14496-12).
const (
	tfhdBaseDataOffsetPresent       = 0x000001
	tfhdSampleDescriptionIndex      = 0x000002
	tfhdDefaultSampleDuration       = 0x000008
	tfhdDefaultSampleSize           = 0x000010
	tfhdDefaultSampleFlags          = 0x000020
	trunDataOffsetPresent           = 0x000001
	trunFirstSampleFlagsPresent     = 0x000004
	trunSampleDurationPresent       = 0x000100
	trunSampleSizePresent           = 0x000200
	trunSampleFlagsPresent          = 0x000400
	trunSampleCompositionTimeOffset = 0x000800
)

// FragmentReport describes one audited movie fragment (moof) in decode order.
type FragmentReport struct {
	Index          int    `json:"index"`
	SegmentIndex   int    `json:"segmentIndex"`
	SequenceNumber uint32 `json:"sequenceNumber"`
	Start          uint64 `json:"start"`
	End            uint64 `json:"end"`
	Duration       uint64 `json:"duration"`
	Samples        uint32 `json:"samples"`
}

// Report is the result of a successful audit.
type Report struct {
	Timescale     uint32
	TrackID       uint32
	FragmentCount int
	TotalDuration uint64
	Fragments     []FragmentReport
}

// initTrack carries the per-track facts recovered from the init segment.
type initTrack struct {
	timescale uint32
	trackID   uint32
	trexDur   uint32
	trexSize  uint32
}

// fragment is one audited moof before it is folded into the report.
type fragment struct {
	segmentIndex int
	seq          uint32
	start        uint64
	duration     uint64
	samples      uint32
}

// Audit validates one initialization segment followed by one or more media
// segments and returns the reconstructed decode timeline. Any violation is
// reported as a single *AuditError with a stable code.
func Audit(initBuf []byte, segs [][]byte) (*Report, *AuditError) {
	init, aerr := parseInit(initBuf)
	if aerr != nil {
		return nil, aerr
	}

	var frags []fragment
	for i, seg := range segs {
		fs, aerr := parseMediaSegment(seg, i, init, len(frags))
		if aerr != nil {
			return nil, aerr
		}
		frags = append(frags, fs...)
	}

	// Cross-fragment ordering and exact decode-timeline continuity.
	for i := 1; i < len(frags); i++ {
		prev, cur := frags[i-1], frags[i]
		if cur.seq <= prev.seq {
			return nil, errf(CodeSequenceNotIncreasing, cur.segmentIndex, i,
				"fragment %d has sequence number %d, previous fragment has %d",
				i, cur.seq, prev.seq)
		}
		prevEnd := prev.start + prev.duration
		switch {
		case cur.start > prevEnd:
			return nil, errf(CodeTimelineGap, cur.segmentIndex, i,
				"fragment %d starts at decode tick %d but previous fragment ends at %d (gap of %d ticks)",
				i, cur.start, prevEnd, cur.start-prevEnd)
		case cur.start < prevEnd:
			return nil, errf(CodeTimelineOverlap, cur.segmentIndex, i,
				"fragment %d starts at decode tick %d but previous fragment ends at %d (overlap of %d ticks)",
				i, cur.start, prevEnd, prevEnd-cur.start)
		}
	}

	rep := &Report{
		Timescale:     init.timescale,
		TrackID:       init.trackID,
		FragmentCount: len(frags),
	}
	for i, f := range frags {
		rep.Fragments = append(rep.Fragments, FragmentReport{
			Index:          i,
			SegmentIndex:   f.segmentIndex,
			SequenceNumber: f.seq,
			Start:          f.start,
			End:            f.start + f.duration,
			Duration:       f.duration,
			Samples:        f.samples,
		})
	}
	if len(frags) > 0 {
		first, last := frags[0], frags[len(frags)-1]
		rep.TotalDuration = last.start + last.duration - first.start
	}
	return rep, nil
}

// parseInit validates the initialization segment and extracts the single
// audio track's timescale, track ID and trex default sample parameters.
func parseInit(buf []byte) (*initTrack, *AuditError) {
	tops, aerr := parseBoxes(buf, 0, -1, -1)
	if aerr != nil {
		return nil, aerr
	}
	moov := findBox(tops, "moov")
	if moov == nil {
		return nil, errf(CodeMissingMoov, -1, -1, "initialization segment has no moov box")
	}
	mc, aerr := parseBoxes(moov.data, moov.start+moov.hdr, -1, -1)
	if aerr != nil {
		return nil, aerr
	}

	traks := findBoxes(mc, "trak")
	if len(traks) != 1 {
		return nil, errf(CodeTrackCountInvalid, -1, -1,
			"expected exactly one track, found %d", len(traks))
	}
	mvex := findBox(mc, "mvex")
	if mvex == nil {
		return nil, errf(CodeMissingMvex, -1, -1, "initialization segment has no mvex box")
	}

	trak := traks[0]
	tc, aerr := parseBoxes(trak.data, trak.start+trak.hdr, -1, -1)
	if aerr != nil {
		return nil, aerr
	}
	tkhd := findBox(tc, "tkhd")
	if tkhd == nil {
		return nil, errf(CodeMissingTrackID, -1, -1, "track has no tkhd box")
	}
	trackID, aerr := parseTkhd(tkhd)
	if aerr != nil {
		return nil, aerr
	}

	mdia := findBox(tc, "mdia")
	if mdia == nil {
		return nil, errf(CodeBoxStructureInvalid, -1, -1, "track has no mdia box")
	}
	mdc, aerr := parseBoxes(mdia.data, mdia.start+mdia.hdr, -1, -1)
	if aerr != nil {
		return nil, aerr
	}
	hdlr := findBox(mdc, "hdlr")
	if hdlr == nil {
		return nil, errf(CodeBoxStructureInvalid, -1, -1, "media has no hdlr box")
	}
	handler, aerr := parseHdlr(hdlr)
	if aerr != nil {
		return nil, aerr
	}
	if handler != "soun" {
		return nil, errf(CodeNotAudioTrack, -1, -1,
			"track handler type is %q, expected \"soun\"", handler)
	}
	mdhd := findBox(mdc, "mdhd")
	if mdhd == nil {
		return nil, errf(CodeMissingTimescale, -1, -1, "media has no mdhd box")
	}
	timescale, aerr := parseMdhd(mdhd)
	if aerr != nil {
		return nil, aerr
	}
	if timescale == 0 {
		return nil, errf(CodeMissingTimescale, -1, -1, "mdhd timescale is zero")
	}

	vc, aerr := parseBoxes(mvex.data, mvex.start+mvex.hdr, -1, -1)
	if aerr != nil {
		return nil, aerr
	}
	var trexDur, trexSize uint32
	found := false
	for _, trex := range findBoxes(vc, "trex") {
		id, dur, size, aerr := parseTrex(&trex)
		if aerr != nil {
			return nil, aerr
		}
		if id == trackID {
			trexDur, trexSize, found = dur, size, true
			break
		}
	}
	if !found {
		return nil, errf(CodeMissingTrex, -1, -1,
			"mvex has no trex entry for track %d", trackID)
	}

	return &initTrack{
		timescale: timescale,
		trackID:   trackID,
		trexDur:   trexDur,
		trexSize:  trexSize,
	}, nil
}

func parseTkhd(b *box) (uint32, *AuditError) {
	version, _, body, aerr := fullBox(b, -1, -1)
	if aerr != nil {
		return 0, aerr
	}
	c := &cursor{b: body}
	switch version {
	case 0:
		if !c.skip(8) {
			return 0, errf(CodeBoxStructureInvalid, -1, -1, "tkhd v0 truncated")
		}
	case 1:
		if !c.skip(16) {
			return 0, errf(CodeBoxStructureInvalid, -1, -1, "tkhd v1 truncated")
		}
	default:
		return 0, errf(CodeBoxStructureInvalid, -1, -1, "unsupported tkhd version %d", version)
	}
	id, ok := c.u32()
	if !ok {
		return 0, errf(CodeBoxStructureInvalid, -1, -1, "tkhd missing track_ID")
	}
	return id, nil
}

func parseMdhd(b *box) (uint32, *AuditError) {
	version, _, body, aerr := fullBox(b, -1, -1)
	if aerr != nil {
		return 0, aerr
	}
	c := &cursor{b: body}
	switch version {
	case 0:
		if !c.skip(8) {
			return 0, errf(CodeBoxStructureInvalid, -1, -1, "mdhd v0 truncated")
		}
	case 1:
		if !c.skip(16) {
			return 0, errf(CodeBoxStructureInvalid, -1, -1, "mdhd v1 truncated")
		}
	default:
		return 0, errf(CodeBoxStructureInvalid, -1, -1, "unsupported mdhd version %d", version)
	}
	ts, ok := c.u32()
	if !ok {
		return 0, errf(CodeBoxStructureInvalid, -1, -1, "mdhd missing timescale")
	}
	return ts, nil
}

func parseHdlr(b *box) (string, *AuditError) {
	_, _, body, aerr := fullBox(b, -1, -1)
	if aerr != nil {
		return "", aerr
	}
	if len(body) < 8 {
		return "", errf(CodeBoxStructureInvalid, -1, -1, "hdlr truncated")
	}
	return string(body[4:8]), nil
}

func parseTrex(b *box) (trackID, defDur, defSize uint32, aerr *AuditError) {
	_, _, body, aerr := fullBox(b, -1, -1)
	if aerr != nil {
		return 0, 0, 0, aerr
	}
	c := &cursor{b: body}
	id, ok1 := c.u32()
	_, ok2 := c.u32() // default_sample_description_index
	dur, ok3 := c.u32()
	size, ok4 := c.u32()
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return 0, 0, 0, errf(CodeBoxStructureInvalid, -1, -1, "trex truncated")
	}
	return id, dur, size, nil
}

// parseMediaSegment audits one media segment: every moof must describe the
// init segment's track, resolve all sample parameters, and reference payload
// bytes that exist inside the segment's mdat box(es). fragBase is the global
// fragment index of the segment's first moof.
func parseMediaSegment(buf []byte, segIdx int, init *initTrack, fragBase int) ([]fragment, *AuditError) {
	tops, aerr := parseBoxes(buf, 0, segIdx, fragBase)
	if aerr != nil {
		return nil, aerr
	}
	moofs := findBoxes(tops, "moof")
	if len(moofs) == 0 {
		return nil, errf(CodeMissingMoof, segIdx, fragBase,
			"media segment %d contains no moof box", segIdx)
	}
	mdats := findBoxes(tops, "mdat")

	var frags []fragment
	var ranges []payloadRange
	for i := range moofs {
		f, rs, aerr := parseMoof(&moofs[i], segIdx, fragBase+i, init)
		if aerr != nil {
			return nil, aerr
		}
		frags = append(frags, *f)
		ranges = append(ranges, rs...)
	}
	// Payload boundaries are checked at segment level: every trun range of
	// every moof must land inside an mdat of this segment, ranges must not
	// overlap, and the mdat payload bytes must be fully consumed.
	if aerr := checkPayload(ranges, mdats, segIdx); aerr != nil {
		return nil, aerr
	}
	return frags, nil
}

// payloadRange is one trun's media byte extent inside a segment.
type payloadRange struct {
	start, end int64
	frag       int
	trun       int
}

// parseMoof audits a single movie fragment and returns its payload ranges.
func parseMoof(moof *box, segIdx, fragIdx int, init *initTrack) (*fragment, []payloadRange, *AuditError) {
	mc, aerr := parseBoxes(moof.data, moof.start+moof.hdr, segIdx, fragIdx)
	if aerr != nil {
		return nil, nil, aerr
	}
	mfhd := findBox(mc, "mfhd")
	if mfhd == nil {
		return nil, nil, errf(CodeMissingMfhd, segIdx, fragIdx, "moof has no mfhd box")
	}
	seq, aerr := parseMfhd(mfhd, segIdx, fragIdx)
	if aerr != nil {
		return nil, nil, aerr
	}

	trafs := findBoxes(mc, "traf")
	if len(trafs) == 0 {
		return nil, nil, errf(CodeMissingTraf, segIdx, fragIdx, "moof has no traf box")
	}
	if len(trafs) > 1 {
		return nil, nil, errf(CodeMultiTraf, segIdx, fragIdx,
			"moof has %d traf boxes; only single-track fragments are accepted", len(trafs))
	}
	tc, aerr := parseBoxes(trafs[0].data, trafs[0].start+trafs[0].hdr, segIdx, fragIdx)
	if aerr != nil {
		return nil, nil, aerr
	}
	tfhd := findBox(tc, "tfhd")
	if tfhd == nil {
		return nil, nil, errf(CodeMissingTfhd, segIdx, fragIdx, "traf has no tfhd box")
	}
	tfdt := findBox(tc, "tfdt")
	if tfdt == nil {
		return nil, nil, errf(CodeMissingTfdt, segIdx, fragIdx, "traf has no tfdt box")
	}
	truns := findBoxes(tc, "trun")
	if len(truns) == 0 {
		return nil, nil, errf(CodeMissingTrun, segIdx, fragIdx, "traf has no trun box")
	}

	th, aerr := parseTfhd(tfhd, segIdx, fragIdx)
	if aerr != nil {
		return nil, nil, aerr
	}
	if th.trackID != init.trackID {
		return nil, nil, errf(CodeTrackMismatch, segIdx, fragIdx,
			"tfhd track_ID %d does not match init segment track %d", th.trackID, init.trackID)
	}
	baseTime, aerr := parseTfdt(tfdt, segIdx, fragIdx)
	if aerr != nil {
		return nil, nil, aerr
	}

	// Parameter inheritance: trun per-sample values win, then tfhd
	// defaults, then trex defaults from the init segment.
	defDur := th.defDur
	if defDur == 0 {
		defDur = init.trexDur
	}
	defSize := th.defSize
	if defSize == 0 {
		defSize = init.trexSize
	}

	base := moof.start // default-base-is-moof semantics
	if th.hasBase {
		base = int64(th.baseOffset)
	}

	var totalDur uint64
	var totalSamples uint32
	var ranges []payloadRange
	runEnd := base // used when a trun carries no explicit data_offset
	for i := range truns {
		trunDur, count, rng, aerr := parseTrun(&truns[i], base, runEnd, defDur, defSize, segIdx, fragIdx)
		if aerr != nil {
			return nil, nil, aerr
		}
		ranges = append(ranges, payloadRange{start: rng[0], end: rng[1], frag: fragIdx, trun: i})
		runEnd = rng[1]
		totalDur += trunDur
		totalSamples += count
	}

	return &fragment{
		segmentIndex: segIdx,
		seq:          seq,
		start:        baseTime,
		duration:     totalDur,
		samples:      totalSamples,
	}, ranges, nil
}

func parseMfhd(b *box, seg, frag int) (uint32, *AuditError) {
	_, _, body, aerr := fullBox(b, seg, frag)
	if aerr != nil {
		return 0, aerr
	}
	c := &cursor{b: body}
	seq, ok := c.u32()
	if !ok {
		return 0, errf(CodeBoxStructureInvalid, seg, frag, "mfhd truncated")
	}
	return seq, nil
}

type tfhdInfo struct {
	trackID    uint32
	hasBase    bool
	baseOffset uint64
	defDur     uint32
	defSize    uint32
}

func parseTfhd(b *box, seg, frag int) (*tfhdInfo, *AuditError) {
	_, flags, body, aerr := fullBox(b, seg, frag)
	if aerr != nil {
		return nil, aerr
	}
	c := &cursor{b: body}
	info := &tfhdInfo{}
	id, ok := c.u32()
	if !ok {
		return nil, errf(CodeBoxStructureInvalid, seg, frag, "tfhd truncated")
	}
	info.trackID = id
	if flags&tfhdBaseDataOffsetPresent != 0 {
		v, ok := c.u64()
		if !ok {
			return nil, errf(CodeBoxStructureInvalid, seg, frag, "tfhd truncated at base_data_offset")
		}
		info.baseOffset, info.hasBase = v, true
	}
	if flags&tfhdSampleDescriptionIndex != 0 && !c.skip(4) {
		return nil, errf(CodeBoxStructureInvalid, seg, frag, "tfhd truncated at sample_description_index")
	}
	if flags&tfhdDefaultSampleDuration != 0 {
		v, ok := c.u32()
		if !ok {
			return nil, errf(CodeBoxStructureInvalid, seg, frag, "tfhd truncated at default_sample_duration")
		}
		info.defDur = v
	}
	if flags&tfhdDefaultSampleSize != 0 {
		v, ok := c.u32()
		if !ok {
			return nil, errf(CodeBoxStructureInvalid, seg, frag, "tfhd truncated at default_sample_size")
		}
		info.defSize = v
	}
	if flags&tfhdDefaultSampleFlags != 0 && !c.skip(4) {
		return nil, errf(CodeBoxStructureInvalid, seg, frag, "tfhd truncated at default_sample_flags")
	}
	return info, nil
}

func parseTfdt(b *box, seg, frag int) (uint64, *AuditError) {
	version, _, body, aerr := fullBox(b, seg, frag)
	if aerr != nil {
		return 0, aerr
	}
	c := &cursor{b: body}
	switch version {
	case 0:
		v, ok := c.u32()
		if !ok {
			return 0, errf(CodeBoxStructureInvalid, seg, frag, "tfdt v0 truncated")
		}
		return uint64(v), nil
	case 1:
		v, ok := c.u64()
		if !ok {
			return 0, errf(CodeBoxStructureInvalid, seg, frag, "tfdt v1 truncated")
		}
		return v, nil
	default:
		return 0, errf(CodeBoxStructureInvalid, seg, frag, "unsupported tfdt version %d", version)
	}
}

// parseTrun resolves every sample's duration and size and returns the
// fragment-relative payload byte range [start, end) the trun consumes.
func parseTrun(b *box, base, runEnd int64, defDur, defSize uint32, seg, frag int) (dur uint64, count uint32, rng [2]int64, aerr *AuditError) {
	_, flags, body, aerr := fullBox(b, seg, frag)
	if aerr != nil {
		return 0, 0, rng, aerr
	}
	c := &cursor{b: body}
	sampleCount, ok := c.u32()
	if !ok {
		return 0, 0, rng, errf(CodeBoxStructureInvalid, seg, frag, "trun truncated at sample_count")
	}
	var dataOffset int64
	hasDataOffset := false
	if flags&trunDataOffsetPresent != 0 {
		v, ok := c.u32()
		if !ok {
			return 0, 0, rng, errf(CodeBoxStructureInvalid, seg, frag, "trun truncated at data_offset")
		}
		dataOffset = int64(int32(v))
		hasDataOffset = true
	}
	if flags&trunFirstSampleFlagsPresent != 0 && !c.skip(4) {
		return 0, 0, rng, errf(CodeBoxStructureInvalid, seg, frag, "trun truncated at first_sample_flags")
	}
	durPresent := flags&trunSampleDurationPresent != 0
	sizePresent := flags&trunSampleSizePresent != 0
	flagsPresent := flags&trunSampleFlagsPresent != 0
	ctoPresent := flags&trunSampleCompositionTimeOffset != 0

	var size uint64
	for i := uint32(0); i < sampleCount; i++ {
		d := defDur
		if durPresent {
			v, ok := c.u32()
			if !ok {
				return 0, 0, rng, errf(CodeBoxStructureInvalid, seg, frag,
					"trun truncated at sample %d duration", i)
			}
			d = v
		}
		if d == 0 {
			return 0, 0, rng, errf(CodeSampleDurationUnresolvable, seg, frag,
				"sample %d has no duration in trun, tfhd or trex", i)
		}
		s := defSize
		if sizePresent {
			v, ok := c.u32()
			if !ok {
				return 0, 0, rng, errf(CodeBoxStructureInvalid, seg, frag,
					"trun truncated at sample %d size", i)
			}
			s = v
		}
		if s == 0 {
			return 0, 0, rng, errf(CodeSampleSizeUnresolvable, seg, frag,
				"sample %d has no size in trun, tfhd or trex", i)
		}
		if flagsPresent && !c.skip(4) {
			return 0, 0, rng, errf(CodeBoxStructureInvalid, seg, frag,
				"trun truncated at sample %d flags", i)
		}
		if ctoPresent && !c.skip(4) {
			return 0, 0, rng, errf(CodeBoxStructureInvalid, seg, frag,
				"trun truncated at sample %d composition time offset", i)
		}
		dur += uint64(d)
		size += uint64(s)
	}

	start := runEnd
	if hasDataOffset {
		start = base + dataOffset
	}
	rng = [2]int64{start, start + int64(size)}
	return dur, sampleCount, rng, nil
}

// checkPayload verifies that every trun payload range lies inside exactly one
// mdat of the segment, that ranges do not overlap, and that the mdat payload
// bytes are fully consumed by the referenced ranges.
func checkPayload(ranges []payloadRange, mdats []box, seg int) *AuditError {
	total := int64(0)
	for _, r := range ranges {
		total += r.end - r.start
	}
	if len(mdats) == 0 {
		if total > 0 {
			return errf(CodeMissingMdat, seg, ranges[0].frag,
				"fragment references %d media byte(s) but the segment has no mdat box", total)
		}
		return nil
	}

	type span struct{ start, end int64 }
	spans := make([]span, len(mdats))
	for i, m := range mdats {
		spans[i] = span{m.start + m.hdr, m.start + m.size}
	}

	covered := make([]int64, len(mdats))
	for _, r := range ranges {
		if r.end < r.start {
			return errf(CodePayloadOutOfRange, seg, r.frag,
				"trun %d has negative payload extent [%d, %d)", r.trun, r.start, r.end)
		}
		owner := -1
		for j, s := range spans {
			if r.start >= s.start && r.end <= s.end {
				owner = j
				break
			}
		}
		if owner < 0 {
			return errf(CodePayloadOutOfRange, seg, r.frag,
				"trun %d payload range [%d, %d) is not contained in any mdat of the segment",
				r.trun, r.start, r.end)
		}
		covered[owner] += r.end - r.start
	}

	// Pairwise overlap check (ranges are few; O(n^2) is fine).
	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			if ranges[i].start < ranges[j].end && ranges[j].start < ranges[i].end {
				return errf(CodePayloadOverlap, seg, ranges[j].frag,
					"trun %d payload range [%d, %d) overlaps trun %d range [%d, %d)",
					ranges[i].trun, ranges[i].start, ranges[i].end,
					ranges[j].trun, ranges[j].start, ranges[j].end)
			}
		}
	}

	fragOf := -1
	if len(ranges) > 0 {
		fragOf = ranges[len(ranges)-1].frag
	}
	for j, s := range spans {
		if covered[j] != s.end-s.start {
			return errf(CodePayloadNotConsumed, seg, fragOf,
				"mdat %d payload is %d byte(s) but truns reference %d byte(s)",
				j, s.end-s.start, covered[j])
		}
	}
	return nil
}
