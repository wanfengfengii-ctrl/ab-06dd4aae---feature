// Command smoke runs HTTP smoke tests against a live audit API: it submits
// a continuous timeline (expecting success) and several broken timelines
// (expecting the matching stable error codes).
//
// Usage: smoke -url http://127.0.0.1:8080
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"time"

	"fmp4audit/internal/fixture"
)

type errorBody struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	SegmentIndex  int    `json:"segmentIndex"`
	FragmentIndex int    `json:"fragmentIndex"`
}

type auditResponse struct {
	OK            bool   `json:"ok"`
	Timescale     uint32 `json:"timescale"`
	TrackID       uint32 `json:"trackId"`
	FragmentCount int    `json:"fragmentCount"`
	TotalDuration uint64 `json:"totalDuration"`
	Fragments     []struct {
		Index          int    `json:"index"`
		SegmentIndex   int    `json:"segmentIndex"`
		SequenceNumber uint32 `json:"sequenceNumber"`
		Start          uint64 `json:"start"`
		End            uint64 `json:"end"`
		Duration       uint64 `json:"duration"`
		Samples        uint32 `json:"samples"`
	} `json:"fragments"`
	Error *errorBody `json:"error"`
}

var failures int

func main() {
	url := flag.String("url", "http://127.0.0.1:8080", "base URL of the audit API")
	flag.Parse()

	client := &http.Client{Timeout: 15 * time.Second}

	checkHealth(client, *url)
	checkContinuous(client, *url)
	checkBrokenTimelines(client, *url)
	checkBrokenPayloads(client, *url)

	if failures > 0 {
		fmt.Printf("SMOKE FAILED: %d check(s) failed\n", failures)
		os.Exit(1)
	}
	fmt.Println("SMOKE OK: all checks passed")
}

func pass(format string, args ...any) {
	fmt.Printf("  PASS "+format+"\n", args...)
}

func fail(format string, args ...any) {
	failures++
	fmt.Printf("  FAIL "+format+"\n", args...)
}

func checkHealth(client *http.Client, base string) {
	fmt.Println("[health] GET /healthz")
	resp, err := client.Get(base + "/healthz")
	if err != nil {
		fail("healthz: %v", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fail("healthz: status %d, want 200", resp.StatusCode)
		return
	}
	pass("healthz: 200")
}

// checkContinuous submits init + 3 media segments whose decode intervals
// connect exactly, exercising all three parameter-inheritance levels
// (per-sample trun values, tfhd defaults, trex defaults).
func checkContinuous(client *http.Client, base string) {
	fmt.Println("[continuous] exact decode timeline across 3 segments")
	init := fixture.InitSegment(fixture.InitOpts{
		Timescale: 48000, TrackID: 1, TrexDuration: 1024, TrexSize: 16,
	})
	seg1 := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
	})
	seg2 := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 2, BaseTime: 3072, Samples: fixture.Samples(3, 1024, 16), TfhdDefaults: true,
	})
	seg3 := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 3, BaseTime: 6144, Samples: fixture.Samples(3, 1024, 16), InheritTrex: true,
	})

	status, body, err := postAudit(client, base, init, seg1, seg2, seg3)
	if err != nil {
		fail("post: %v", err)
		return
	}
	if status != http.StatusOK || !body.OK {
		fail("status %d ok=%v, want 200 ok=true (error=%+v)", status, body.OK, body.Error)
		return
	}
	if body.Timescale != 48000 || body.TrackID != 1 {
		fail("timescale=%d trackId=%d, want 48000/1", body.Timescale, body.TrackID)
		return
	}
	if body.FragmentCount != 3 || len(body.Fragments) != 3 {
		fail("fragmentCount=%d len=%d, want 3", body.FragmentCount, len(body.Fragments))
		return
	}
	if body.TotalDuration != 9216 {
		fail("totalDuration=%d, want 9216", body.TotalDuration)
		return
	}
	wantStart := []uint64{0, 3072, 6144}
	for i, f := range body.Fragments {
		if f.SequenceNumber != uint32(i+1) || f.Start != wantStart[i] ||
			f.End != wantStart[i]+3072 || f.Duration != 3072 ||
			f.Samples != 3 || f.SegmentIndex != i || f.Index != i {
			fail("fragment %d = %+v, unexpected", i, f)
			return
		}
	}
	pass("continuous timeline accepted, totalDuration=9216 ticks @48000Hz")
}

// checkBrokenTimelines submits gap, overlap and out-of-order sequences.
func checkBrokenTimelines(client *http.Client, base string) {
	init := fixture.InitSegment(fixture.InitOpts{
		Timescale: 48000, TrackID: 1, TrexDuration: 1024, TrexSize: 16,
	})
	mk := func(seq uint32, t uint64) []byte {
		return fixture.MediaSegment(fixture.MediaOpts{
			Seq: seq, BaseTime: t, Samples: fixture.Samples(3, 1024, 16),
		})
	}

	expectError(client, base, "gap of 512 ticks before fragment 2",
		422, "TIMELINE_GAP", 2, 2,
		init, mk(1, 0), mk(2, 3072), mk(3, 6656))

	expectError(client, base, "overlap of 512 ticks at fragment 2",
		422, "TIMELINE_OVERLAP", 2, 2,
		init, mk(1, 0), mk(2, 3072), mk(3, 5632))

	expectError(client, base, "sequence numbers not increasing",
		422, "SEQUENCE_NOT_INCREASING", 2, 2,
		init, mk(1, 0), mk(3, 3072), mk(3, 6144))
}

// checkBrokenPayloads submits segments with payload and inheritance defects.
func checkBrokenPayloads(client *http.Client, base string) {
	init := fixture.InitSegment(fixture.InitOpts{
		Timescale: 48000, TrackID: 1, TrexDuration: 1024, TrexSize: 16,
	})
	good := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16),
	})

	truncated := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 2, BaseTime: 3072, Samples: fixture.Samples(3, 1024, 16), MdatTruncate: 4,
	})
	expectError(client, base, "mdat shorter than trun payload",
		422, "PAYLOAD_OUT_OF_RANGE", 1, 1, init, good, truncated)

	padded := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 2, BaseTime: 3072, Samples: fixture.Samples(3, 1024, 16), MdatPadTail: 8,
	})
	expectError(client, base, "unreferenced mdat bytes",
		422, "PAYLOAD_NOT_CONSUMED", 1, 1, init, good, padded)

	bareInit := fixture.InitSegment(fixture.InitOpts{
		Timescale: 48000, TrackID: 1, TrexDuration: 0, TrexSize: 16,
	})
	noDur := fixture.MediaSegment(fixture.MediaOpts{
		Seq: 1, BaseTime: 0, Samples: fixture.Samples(3, 1024, 16), InheritTrex: true,
	})
	expectError(client, base, "duration not resolvable from trun/tfhd/trex",
		422, "SAMPLE_DURATION_UNRESOLVABLE", 0, 0, bareInit, noDur)
}

// expectError posts init+segs and requires the given status, error code and
// error indices.
func expectError(client *http.Client, base, name string, wantStatus int, wantCode string, wantSeg, wantFrag int, init []byte, segs ...[]byte) {
	fmt.Printf("[reject] %s\n", name)
	status, body, err := postAudit(client, base, init, segs...)
	if err != nil {
		fail("post: %v", err)
		return
	}
	if status != wantStatus || body.OK || body.Error == nil {
		fail("status %d ok=%v error=%+v, want %d %s", status, body.OK, body.Error, wantStatus, wantCode)
		return
	}
	e := body.Error
	if e.Code != wantCode {
		fail("code %q, want %q (message: %s)", e.Code, wantCode, e.Message)
		return
	}
	if e.SegmentIndex != wantSeg || e.FragmentIndex != wantFrag {
		fail("indices segment=%d fragment=%d, want %d/%d", e.SegmentIndex, e.FragmentIndex, wantSeg, wantFrag)
		return
	}
	pass("rejected with %s at segment %d fragment %d", e.Code, e.SegmentIndex, e.FragmentIndex)
}

// postAudit uploads one init segment and the given media segments as ordered
// multipart parts and decodes the JSON response.
func postAudit(client *http.Client, base string, init []byte, segs ...[]byte) (int, *auditResponse, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	writePart := func(name, filename string, data []byte) error {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, name, filename))
		h.Set("Content-Type", "application/octet-stream")
		pw, err := mw.CreatePart(h)
		if err != nil {
			return err
		}
		_, err = pw.Write(data)
		return err
	}
	if err := writePart("init", "init.mp4", init); err != nil {
		return 0, nil, err
	}
	for i, s := range segs {
		if err := writePart("segment", fmt.Sprintf("segment-%d.m4s", i+1), s); err != nil {
			return 0, nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return 0, nil, err
	}

	req, err := http.NewRequest(http.MethodPost, base+"/api/fmp4/audit", &buf)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	body := &auditResponse{}
	if err := json.Unmarshal(raw, body); err != nil {
		return resp.StatusCode, nil, fmt.Errorf("invalid JSON response: %w (%s)", err, raw)
	}
	return resp.StatusCode, body, nil
}
