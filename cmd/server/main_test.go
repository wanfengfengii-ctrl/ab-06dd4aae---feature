package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"regexp"
	"strings"
	"testing"

	"fmp4audit/internal/fixture"
)

func buildMultipart(t *testing.T, init []byte, segs ...[]byte) (body *bytes.Buffer, contentType string) {
	t.Helper()
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	write := func(name, filename string, data []byte) {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, name, filename))
		h.Set("Content-Type", "application/octet-stream")
		pw, err := mw.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	write("init", "init.mp4", init)
	for i, s := range segs {
		write("segment", fmt.Sprintf("segment-%d.m4s", i+1), s)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf, mw.FormDataContentType()
}

func post(t *testing.T, body *bytes.Buffer, contentType string) (int, map[string]any) {
	t.Helper()
	return postQuery(t, "", body, contentType)
}

func postQuery(t *testing.T, query string, body *bytes.Buffer, contentType string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/fmp4/audit"+query, body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	routes().ServeHTTP(rec, req)
	var parsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, parsed
}

func goodInit() []byte {
	return fixture.InitSegment(fixture.InitOpts{
		Timescale: 48000, TrackID: 1, TrexDuration: 1024, TrexSize: 16,
	})
}

func goodSeg(seq uint32, tm uint64) []byte {
	return fixture.MediaSegment(fixture.MediaOpts{
		Seq: seq, BaseTime: tm, Samples: fixture.Samples(3, 1024, 16),
	})
}

func errorCode(t *testing.T, resp map[string]any) string {
	t.Helper()
	e, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("no error object in %v", resp)
	}
	code, _ := e["code"].(string)
	return code
}

func TestHandlerOK(t *testing.T) {
	body, ct := buildMultipart(t, goodInit(), goodSeg(1, 0), goodSeg(2, 3072))
	status, resp := post(t, body, ct)
	if status != http.StatusOK {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	if resp["ok"] != true {
		t.Fatalf("ok=%v", resp["ok"])
	}
	if resp["totalDuration"] != 6144.0 {
		t.Fatalf("totalDuration=%v", resp["totalDuration"])
	}
	frags, ok := resp["fragments"].([]any)
	if !ok || len(frags) != 2 {
		t.Fatalf("fragments=%v", resp["fragments"])
	}
	// Legacy contract: no reference-clock fields without clock=prft.
	for i, f := range frags {
		fm := f.(map[string]any)
		if _, ok := fm["mediaTime"]; ok {
			t.Fatalf("fragment %d unexpectedly has mediaTime: %v", i, fm)
		}
		if _, ok := fm["ntpTimestamp"]; ok {
			t.Fatalf("fragment %d unexpectedly has ntpTimestamp: %v", i, fm)
		}
	}
}

func TestHandlerGap(t *testing.T) {
	body, ct := buildMultipart(t, goodInit(), goodSeg(1, 0), goodSeg(2, 4096))
	status, resp := post(t, body, ct)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	if code := errorCode(t, resp); code != "TIMELINE_GAP" {
		t.Fatalf("code %q", code)
	}
	e := resp["error"].(map[string]any)
	if e["fragmentIndex"] != 1.0 || e["segmentIndex"] != 1.0 {
		t.Fatalf("indices %v/%v", e["segmentIndex"], e["fragmentIndex"])
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/fmp4/audit", nil)
	rec := httptest.NewRecorder()
	routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestHandlerBadContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/fmp4/audit", strings.NewReader("x"))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestHandlerNoMediaSegments(t *testing.T) {
	body, ct := buildMultipart(t, goodInit())
	status, resp := post(t, body, ct)
	if status != http.StatusBadRequest {
		t.Fatalf("status %d", status)
	}
	if code := errorCode(t, resp); code != "NO_MEDIA_SEGMENTS" {
		t.Fatalf("code %q", code)
	}
}

func TestHandlerTooManySegments(t *testing.T) {
	segs := make([][]byte, 33)
	for i := range segs {
		segs[i] = goodSeg(uint32(i+1), uint64(i*3072))
	}
	body, ct := buildMultipart(t, goodInit(), segs...)
	status, resp := post(t, body, ct)
	if status != http.StatusBadRequest {
		t.Fatalf("status %d", status)
	}
	if code := errorCode(t, resp); code != "TOO_MANY_SEGMENTS" {
		t.Fatalf("code %q", code)
	}
}

func TestHandlerPayloadTooLarge(t *testing.T) {
	big := make([]byte, maxTotalBytes) // init alone hits the 16 MiB limit
	body, ct := buildMultipart(t, big, goodSeg(1, 0))
	status, resp := post(t, body, ct)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", status)
	}
	if code := errorCode(t, resp); code != "PAYLOAD_TOO_LARGE" {
		t.Fatalf("code %q", code)
	}
}

func TestHandlerHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

const (
	ntpEpoch = uint64(0xE8A5B3C4) << 32
	// 3072 ticks @ 48000 Hz = 64 ms, in NTP 32.32 units (rounded).
	ntpHop64ms = uint64(274877907)
)

func clockSeg(seq uint32, tm uint64, ntp uint64) []byte {
	return fixture.MediaSegment(fixture.MediaOpts{
		Seq: seq, BaseTime: tm, Samples: fixture.Samples(3, 1024, 16),
		Prft: &fixture.PrftSpec{NTP: ntp},
	})
}

func TestHandlerClockOK(t *testing.T) {
	body, ct := buildMultipart(t, goodInit(),
		clockSeg(1, 0, ntpEpoch),
		clockSeg(2, 3072, ntpEpoch+ntpHop64ms),
		clockSeg(3, 6144, ntpEpoch+2*ntpHop64ms))
	status, resp := postQuery(t, "?clock=prft&maxClockSkewUs=1000", body, ct)
	if status != http.StatusOK {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	frags, ok := resp["fragments"].([]any)
	if !ok || len(frags) != 3 {
		t.Fatalf("fragments=%v", resp["fragments"])
	}
	wantStart := []uint64{0, 3072, 6144}
	hexRe := regexp.MustCompile(`^[0-9a-f]{16}$`)
	for i, f := range frags {
		fm := f.(map[string]any)
		if fm["mediaTime"] != float64(wantStart[i]) {
			t.Fatalf("fragment %d mediaTime=%v, want %d", i, fm["mediaTime"], wantStart[i])
		}
		ntp, _ := fm["ntpTimestamp"].(string)
		want := fmt.Sprintf("%016x", ntpEpoch+uint64(i)*ntpHop64ms)
		if ntp != want || !hexRe.MatchString(ntp) {
			t.Fatalf("fragment %d ntpTimestamp=%q, want %q (16 lowercase hex)", i, ntp, want)
		}
	}
}

func TestHandlerClockBadParams(t *testing.T) {
	queries := []string{
		"?clock=prft",                        // missing maxClockSkewUs
		"?maxClockSkewUs=1000",               // skew without clock mode
		"?clock=ntp&maxClockSkewUs=1000",     // unsupported mode
		"?clock=prft&maxClockSkewUs=0",       // below range
		"?clock=prft&maxClockSkewUs=1000001", // above range
		"?clock=prft&maxClockSkewUs=abc",     // not an integer
		"?clock=prft&maxClockSkewUs=",        // empty value
		"?clock=prft&maxClockSkewUs=1000.5",  // not an integer
	}
	for _, q := range queries {
		body, ct := buildMultipart(t, goodInit(), clockSeg(1, 0, ntpEpoch))
		status, resp := postQuery(t, q, body, ct)
		if status != http.StatusBadRequest {
			t.Fatalf("%s: status %d, resp %v", q, status, resp)
		}
		if code := errorCode(t, resp); code != "BAD_CLOCK_PARAMS" {
			t.Fatalf("%s: code %q", q, code)
		}
	}
	// Boundary values are accepted.
	for _, us := range []string{"1", "1000000"} {
		body, ct := buildMultipart(t, goodInit(), clockSeg(1, 0, ntpEpoch))
		status, resp := postQuery(t, "?clock=prft&maxClockSkewUs="+us, body, ct)
		if status != http.StatusOK {
			t.Fatalf("maxClockSkewUs=%s: status %d, resp %v", us, status, resp)
		}
	}
}

func TestHandlerClockDrift(t *testing.T) {
	// Second anchor is ~10 ms late against the 1 ms budget.
	body, ct := buildMultipart(t, goodInit(),
		clockSeg(1, 0, ntpEpoch),
		clockSeg(2, 3072, ntpEpoch+ntpHop64ms+42949673))
	status, resp := postQuery(t, "?clock=prft&maxClockSkewUs=1000", body, ct)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	if code := errorCode(t, resp); code != "CLOCK_SKEW_EXCEEDED" {
		t.Fatalf("code %q", code)
	}
	e := resp["error"].(map[string]any)
	if e["fragmentIndex"] != 1.0 || e["segmentIndex"] != 1.0 {
		t.Fatalf("indices %v/%v", e["segmentIndex"], e["fragmentIndex"])
	}
}

func TestHandlerClockMissingPrft(t *testing.T) {
	body, ct := buildMultipart(t, goodInit(), goodSeg(1, 0), clockSeg(2, 3072, ntpEpoch+ntpHop64ms))
	status, resp := postQuery(t, "?clock=prft&maxClockSkewUs=1000", body, ct)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	if code := errorCode(t, resp); code != "MISSING_PRFT" {
		t.Fatalf("code %q", code)
	}
	e := resp["error"].(map[string]any)
	if e["fragmentIndex"] != 0.0 || e["segmentIndex"] != 0.0 {
		t.Fatalf("indices %v/%v", e["segmentIndex"], e["fragmentIndex"])
	}
}
