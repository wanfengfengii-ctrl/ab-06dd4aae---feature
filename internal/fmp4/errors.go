package fmp4

import "fmt"

// Stable error codes returned by the audit API. Clients (archivists and
// automation) may rely on these values to decide whether a submission must
// be rejected.
const (
	// Request shape.
	CodeBadMultipart     = "BAD_MULTIPART"
	CodePayloadTooLarge  = "PAYLOAD_TOO_LARGE"
	CodeNoMediaSegments  = "NO_MEDIA_SEGMENTS"
	CodeTooManySegments  = "TOO_MANY_SEGMENTS"
	CodeMethodNotAllowed = "METHOD_NOT_ALLOWED"

	// Box structure (init or media segment).
	CodeBoxStructureInvalid = "BOX_STRUCTURE_INVALID"
	CodeMissingMoov         = "MISSING_MOOV"
	CodeTrackCountInvalid   = "TRACK_COUNT_INVALID"
	CodeNotAudioTrack       = "NOT_AUDIO_TRACK"
	CodeMissingMvex         = "MISSING_MVEX"
	CodeMissingTrex         = "MISSING_TREX"
	CodeMissingTimescale    = "MISSING_TIMESCALE"
	CodeMissingTrackID      = "MISSING_TRACK_ID"
	CodeMissingMoof         = "MISSING_MOOF"
	CodeMissingTraf         = "MISSING_TRAF"
	CodeMultiTraf           = "MULTI_TRAF_UNSUPPORTED"
	CodeMissingMfhd         = "MISSING_MFHD"
	CodeMissingTfhd         = "MISSING_TFHD"
	CodeMissingTfdt         = "MISSING_TFDT"
	CodeMissingTrun         = "MISSING_TRUN"
	CodeMissingMdat         = "MISSING_MDAT"

	// Track / fragment ordering.
	CodeTrackMismatch         = "TRACK_MISMATCH"
	CodeSequenceNotIncreasing = "SEQUENCE_NOT_INCREASING"

	// Parameter inheritance (trun -> tfhd -> trex).
	CodeSampleDurationUnresolvable = "SAMPLE_DURATION_UNRESOLVABLE"
	CodeSampleSizeUnresolvable     = "SAMPLE_SIZE_UNRESOLVABLE"

	// Payload boundaries.
	CodePayloadOutOfRange  = "PAYLOAD_OUT_OF_RANGE"
	CodePayloadOverlap     = "PAYLOAD_OVERLAP"
	CodePayloadNotConsumed = "PAYLOAD_NOT_CONSUMED"

	// Decode timeline continuity.
	CodeTimelineGap     = "TIMELINE_GAP"
	CodeTimelineOverlap = "TIMELINE_OVERLAP"
)

// AuditError describes a single rejected submission. SegmentIndex is the
// 0-based index among the uploaded media segments (-1 when the failure is in
// the initialization segment or the request itself). FragmentIndex is the
// 0-based index of the offending movie fragment in submission order (-1 when
// not applicable).
type AuditError struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	SegmentIndex  int    `json:"segmentIndex"`
	FragmentIndex int    `json:"fragmentIndex"`
}

func (e *AuditError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func errf(code string, seg, frag int, format string, args ...any) *AuditError {
	return &AuditError{
		Code:          code,
		Message:       fmt.Sprintf(format, args...),
		SegmentIndex:  seg,
		FragmentIndex: frag,
	}
}
