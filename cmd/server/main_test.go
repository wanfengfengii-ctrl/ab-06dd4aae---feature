package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
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
	req := httptest.NewRequest(http.MethodPost, "/api/fmp4/audit", body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	routes().ServeHTTP(rec, req)
	var parsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, parsed
}

func postURL(t *testing.T, target string, body *bytes.Buffer, contentType string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, body)
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

// ---- clock=prft ----

// anchoredSeg builds a fragment with a version 1 prft directly before moof.
func anchoredSeg(seq uint32, base, ntp uint64) []byte {
	return fixture.MediaSegment(fixture.MediaOpts{
		Seq: seq, BaseTime: base, Samples: fixture.Samples(3, 1024, 16),
		Prft: &fixture.PrftOpts{Ntp: ntp, MediaTime: base},
	})
}

const ntpStep = uint64(274_877_907) // 3072 ticks @48kHz in NTP 32.32

func TestHandlerPrftOK(t *testing.T) {
	base := uint64(1) << 32
	body, ct := buildMultipart(t, goodInit(),
		anchoredSeg(1, 0, base),
		anchoredSeg(2, 3072, base+ntpStep))
	status, resp := postURL(t, "/api/fmp4/audit?clock=prft&maxClockSkewUs=1000", body, ct)
	if status != http.StatusOK {
		t.Fatalf("status %d, resp %v", status, resp)
	}
	frags, ok := resp["fragments"].([]any)
	if !ok || len(frags) != 2 {
		t.Fatalf("fragments=%v", resp["fragments"])
	}
	f0 := frags[0].(map[string]any)
	if f0["mediaTime"] != 0.0 || f0["ntpTimestamp"] != "0000000100000000" {
		t.Fatalf("fragment 0 anchors: %v", f0)
	}
	f1 := frags[1].(map[string]any)
	if f1["mediaTime"] != 3072.0 || f1["ntpTimestamp"] != "0000000110624dd3" {
		t.Fatalf("fragment 1 anchors: %v", f1)
	}
}

func TestHandlerPrftMissingParam(t *testing.T) {
	body, ct := buildMultipart(t, goodInit(), anchoredSeg(1, 0, 1<<32))
	status, resp := postURL(t, "/api/fmp4/audit?clock=prft", body, ct)
	if status != http.StatusBadRequest || errorCode(t, resp) != "MISSING_MAX_CLOCK_SKEW" {
		t.Fatalf("status %d resp %v", status, resp)
	}

	status, resp = postURL(t, "/api/fmp4/audit?clock=prft&maxClockSkewUs=", body, ct)
	if status != http.StatusBadRequest || errorCode(t, resp) != "MISSING_MAX_CLOCK_SKEW" {
		t.Fatalf("status %d resp %v", status, resp)
	}
}

func TestHandlerPrftInvalidParam(t *testing.T) {
	body, ct := buildMultipart(t, goodInit(), anchoredSeg(1, 0, 1<<32))
	for _, q := range []string{
		"clock=prft&maxClockSkewUs=0",
		"clock=prft&maxClockSkewUs=-5",
		"clock=prft&maxClockSkewUs=1000001",
		"clock=prft&maxClockSkewUs=abc",
		"maxClockSkewUs=1000",
	} {
		status, resp := postURL(t, "/api/fmp4/audit?"+q, body, ct)
		if status != http.StatusBadRequest || errorCode(t, resp) != "INVALID_MAX_CLOCK_SKEW" {
			t.Fatalf("query %q: status %d resp %v", q, status, resp)
		}
	}
}

func TestHandlerUnknownClockMode(t *testing.T) {
	body, ct := buildMultipart(t, goodInit(), anchoredSeg(1, 0, 1<<32))
	status, resp := postURL(t, "/api/fmp4/audit?clock=wall&maxClockSkewUs=1000", body, ct)
	if status != http.StatusBadRequest || errorCode(t, resp) != "UNKNOWN_CLOCK_MODE" {
		t.Fatalf("status %d resp %v", status, resp)
	}
}

func TestHandlerPrftMissingAnchor(t *testing.T) {
	// Legacy segments without prft are rejected under clock=prft.
	body, ct := buildMultipart(t, goodInit(), goodSeg(1, 0), goodSeg(2, 3072))
	status, resp := postURL(t, "/api/fmp4/audit?clock=prft&maxClockSkewUs=1000", body, ct)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d resp %v", status, resp)
	}
	if code := errorCode(t, resp); code != "MISSING_PRFT" {
		t.Fatalf("code %q", code)
	}
	e := resp["error"].(map[string]any)
	if e["fragmentIndex"] != 0.0 || e["segmentIndex"] != 0.0 {
		t.Fatalf("indices %v/%v", e["segmentIndex"], e["fragmentIndex"])
	}
}

func TestHandlerPrftClockDrift(t *testing.T) {
	// ~1 ms of extra producer time between the two anchors, 1 us threshold.
	body, ct := buildMultipart(t, goodInit(),
		anchoredSeg(1, 0, 1<<32),
		anchoredSeg(2, 3072, 1<<32+ntpStep+4295))
	status, resp := postURL(t, "/api/fmp4/audit?clock=prft&maxClockSkewUs=1", body, ct)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d resp %v", status, resp)
	}
	if code := errorCode(t, resp); code != "CLOCK_DRIFT" {
		t.Fatalf("code %q", code)
	}
	e := resp["error"].(map[string]any)
	if e["fragmentIndex"] != 1.0 || e["segmentIndex"] != 1.0 {
		t.Fatalf("indices %v/%v", e["segmentIndex"], e["fragmentIndex"])
	}
}

func TestHandlerLegacyMaterialAcceptedWithoutClock(t *testing.T) {
	// No clock parameter: anchored or unanchored segments follow the original
	// contract, and no prft fields appear in the response.
	body, ct := buildMultipart(t, goodInit(), goodSeg(1, 0), goodSeg(2, 3072))
	status, resp := post(t, body, ct)
	if status != http.StatusOK {
		t.Fatalf("status %d resp %v", status, resp)
	}
	f0 := resp["fragments"].([]any)[0].(map[string]any)
	if _, present := f0["mediaTime"]; present {
		t.Fatalf("mediaTime must be omitted in legacy mode: %v", f0)
	}
	if _, present := f0["ntpTimestamp"]; present {
		t.Fatalf("ntpTimestamp must be omitted in legacy mode: %v", f0)
	}
}
