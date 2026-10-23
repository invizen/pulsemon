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
	re := regexp.MustCompile(`StatusInternalServerError,\s*("[^"]*"\s*\+\s*)?err\.Error\(\)`)
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
			if re.MatchString(line) {
				t.Errorf("%s:%d returns err.Error() in a 500: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// The graph query failing must give the generic body, not sqlite text.
func TestFix_g3_GraphQueryErrorIsGeneric(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()
	if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('g', 'g', '10.0.0.1', 60, 1000, 25, 3, 3, 'paused', 'up', 'x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DROP TABLE probes`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/sensors/g/graph?range=1h", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 (%s)", rr.Code, rr.Body.String())
	}
	if strings.Contains(strings.ToLower(rr.Body.String()), "no such table") || !strings.Contains(rr.Body.String(), "internal error") {
		t.Fatalf("body leaks driver text or is not generic: %s", rr.Body.String())
	}
}
