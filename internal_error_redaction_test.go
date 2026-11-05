package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// g3 guard: no handler may answer a 500 with the raw error text (driver SQL,
// filesystem paths). respondInternal logs the detail and returns a generic body.
func TestFix_g3_NoRawErrorTextInInternalErrors(t *testing.T) {
	// 502/503 joined the 500 class (review 2026-10-24): upstream-failure
	// bodies leak resolver/proxy/URL detail exactly like SQL text does.
	// A deliberate, reviewed exception carries a `redaction-ok:` marker
	// on the same line.
	re := regexp.MustCompile(`Status(InternalServerError|BadGateway|ServiceUnavailable),\s*("[^"]*"\s*\+\s*)?err\.Error\(\)`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "redaction-ok:") {
				continue
			}
			if re.MatchString(line) {
				t.Errorf("%s:%d returns err.Error() in a 5xx: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// A DB query failing must give the generic 500 body, not sqlite text. The
// graph is memory-backed (finding #8 — it no longer queries the probes table),
// so this exercises the sensors listing, which still reads the DB directly.
func TestFix_g3_QueryErrorIsGeneric(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()
	if _, err := d.Exec(`DROP TABLE sensors`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/sensors", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 (%s)", rr.Code, rr.Body.String())
	}
	// The 500 body must be generic — no sqlite driver text ("no such table")
	// may leak to the client. (The message itself is handler-specific; the
	// g3 guard is about redaction, not the exact wording.)
	if strings.Contains(strings.ToLower(rr.Body.String()), "no such table") {
		t.Fatalf("body leaks driver text: %s", rr.Body.String())
	}
}
