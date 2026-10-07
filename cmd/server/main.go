// Command server exposes the fMP4 audit HTTP API.
//
// Usage:
//
//	server              start the API (PORT env, default 8080)
//	server healthcheck  exit 0 iff http://127.0.0.1:$PORT/healthz answers 200
package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"fmp4audit/internal/fmp4"
)

const (
	maxTotalBytes    = 16 << 20 // 16 MiB of segment payload per request
	maxBodyBytes     = maxTotalBytes + 1<<20
	maxMediaSegments = 32
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck())
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("fmp4 audit API listening on :%s", port)
	log.Fatal(srv.ListenAndServe())
}

func routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/api/fmp4/audit", handleAudit)
	return mux
}

func runHealthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		log.Printf("healthcheck: %v", err)
		return 1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("healthcheck: status %d", resp.StatusCode)
		return 1
	}
	return 0
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, &fmp4.AuditError{
			Code: fmp4.CodeMethodNotAllowed, Message: "use GET",
			SegmentIndex: -1, FragmentIndex: -1,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type okResponse struct {
	OK            bool                  `json:"ok"`
	Timescale     uint32                `json:"timescale"`
	TrackID       uint32                `json:"trackId"`
	FragmentCount int                   `json:"fragmentCount"`
	TotalDuration uint64                `json:"totalDuration"`
	Fragments     []fmp4.FragmentReport `json:"fragments"`
}

type errResponse struct {
	OK    bool             `json:"ok"`
	Error *fmp4.AuditError `json:"error"`
}

func handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, &fmp4.AuditError{
			Code: fmp4.CodeMethodNotAllowed, Message: "use POST",
			SegmentIndex: -1, FragmentIndex: -1,
		})
		return
	}

	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		writeError(w, http.StatusBadRequest, &fmp4.AuditError{
			Code: fmp4.CodeBadMultipart, Message: "expected multipart/form-data with a boundary",
			SegmentIndex: -1, FragmentIndex: -1,
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	mr := multipart.NewReader(r.Body, params["boundary"])

	var init []byte
	var segs [][]byte
	total := 0
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeError(w, multipartErrStatus(err), &fmp4.AuditError{
				Code: multipartErrCode(err), Message: "malformed multipart body: " + err.Error(),
				SegmentIndex: -1, FragmentIndex: -1,
			})
			return
		}
		if init != nil && len(segs) >= maxMediaSegments {
			writeError(w, http.StatusBadRequest, &fmp4.AuditError{
				Code:         fmp4.CodeTooManySegments,
				Message:      "too many media segments: more than 32",
				SegmentIndex: -1, FragmentIndex: -1,
			})
			return
		}
		data, err := io.ReadAll(io.LimitReader(part, maxTotalBytes+1))
		if err != nil {
			writeError(w, multipartErrStatus(err), &fmp4.AuditError{
				Code: multipartErrCode(err), Message: "failed reading part: " + err.Error(),
				SegmentIndex: -1, FragmentIndex: -1,
			})
			return
		}
		total += len(data)
		if total > maxTotalBytes {
			writeError(w, http.StatusRequestEntityTooLarge, &fmp4.AuditError{
				Code:         fmp4.CodePayloadTooLarge,
				Message:      "segments exceed the 16 MiB total limit",
				SegmentIndex: -1, FragmentIndex: -1,
			})
			return
		}
		if init == nil {
			init = data
		} else {
			segs = append(segs, data)
		}
		part.Close()
	}

	if init == nil {
		writeError(w, http.StatusBadRequest, &fmp4.AuditError{
			Code: fmp4.CodeBadMultipart, Message: "multipart body has no parts",
			SegmentIndex: -1, FragmentIndex: -1,
		})
		return
	}
	if len(segs) == 0 {
		writeError(w, http.StatusBadRequest, &fmp4.AuditError{
			Code:         fmp4.CodeNoMediaSegments,
			Message:      "expected one init segment followed by 1..32 media segments",
			SegmentIndex: -1, FragmentIndex: -1,
		})
		return
	}

	rep, aerr := fmp4.Audit(init, segs)
	if aerr != nil {
		writeError(w, http.StatusUnprocessableEntity, aerr)
		return
	}
	writeJSON(w, http.StatusOK, okResponse{
		OK:            true,
		Timescale:     rep.Timescale,
		TrackID:       rep.TrackID,
		FragmentCount: rep.FragmentCount,
		TotalDuration: rep.TotalDuration,
		Fragments:     rep.Fragments,
	})
}

func multipartErrCode(err error) string {
	if isTooLarge(err) {
		return fmp4.CodePayloadTooLarge
	}
	return fmp4.CodeBadMultipart
}

func multipartErrStatus(err error) int {
	if isTooLarge(err) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func isTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return true
	}
	return strings.Contains(err.Error(), "http: request body too large")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, aerr *fmp4.AuditError) {
	writeJSON(w, status, errResponse{OK: false, Error: aerr})
}
