package main

// Log sanitization: logSafe neutralizes newlines/control chars and clamps
// length without splitting runes; respondInternal keeps one log line per error.

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLogSafe(t *testing.T) {
	if got := logSafe("x\nCRITICAL forged"); got != "x CRITICAL forged" {
		t.Errorf("newline not neutralized: %q", got)
	}
	if got := logSafe("a\r\nb\x00c\x1b[31m"); strings.ContainsAny(got, "\r\n\x00\x1b") {
		t.Errorf("control chars survived: %q", got)
	}
	long := strings.Repeat("é", 200) // multi-byte: clamp must not split runes
	got := logSafe(long)
	if !utf8.ValidString(got) {
		t.Errorf("clamp produced invalid UTF-8 (rune split): %x", got[len(got)-3:])
	}
	if !strings.HasSuffix(got, "…") || len([]rune(got)) != 121 {
		t.Errorf("clamp wrong: runes=%d suffix=%q", len([]rune(got)), got[len(got)-1:])
	}
}

func TestRespondInternalLogSingleLine(t *testing.T) {
	d := newTestDB(t)
	if _, err := d.Exec(`DROP TABLE sensor_tags`); err != nil {
		t.Fatal(err)
	}
	mux := NewServer(d, NewProbeWorker(d)).Mux() // auth off

	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prev) })

	rr := httptest.NewRecorder()
	// Tag carries a CR+LF + "CRITICAL" payload: it must not forge a line.
	mux.ServeHTTP(rr, httptest.NewRequest("DELETE", "/api/tags?tag=evil%0aCRITICAL%20forged%0d%0aFAKE", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500", rr.Code)
	}
	out := strings.TrimRight(logBuf.String(), "\n")
	if lines := strings.Split(out, "\n"); len(lines) != 1 {
		t.Fatalf("log forged: %d lines:\n%s", len(lines), out)
	}
	lower := strings.ToLower(out)
	if i := strings.Index(lower, "critical"); i == 0 {
		t.Fatalf("payload starts its own line: %q", out)
	}
}
