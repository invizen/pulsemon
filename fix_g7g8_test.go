package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestFix_g7_StaticCharsetETag304(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/index.html", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /index.html = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	etag := rr.Header().Get("ETag")
	if len(etag) < 10 || !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) || strings.HasPrefix(etag, "W/") {
		t.Fatalf("ETag = %q, want a quoted strong tag", etag)
	}
	if !strings.Contains(rr.Header().Get("Cache-Control"), "no-cache") {
		t.Errorf("Cache-Control = %q, want no-cache", rr.Header().Get("Cache-Control"))
	}
	if rr.Body.Len() == 0 {
		t.Fatal("200 response had no body")
	}

	// Revalidation with the returned tag: 304, no body, tag still sent.
	req := httptest.NewRequest("GET", "/index.html", nil)
	req.Header.Set("If-None-Match", etag)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusNotModified || rr2.Body.Len() != 0 {
		t.Fatalf("If-None-Match => %d with %d body bytes, want 304 and empty", rr2.Code, rr2.Body.Len())
	}
	if rr2.Header().Get("ETag") != etag {
		t.Errorf("304 lost the ETag: %q", rr2.Header().Get("ETag"))
	}

	// A stale tag must NOT 304 (an update is never served stale).
	req = httptest.NewRequest("GET", "/index.html", nil)
	req.Header.Set("If-None-Match", `"stale"`)
	rr3 := httptest.NewRecorder()
	mux.ServeHTTP(rr3, req)
	if rr3.Code != http.StatusOK {
		t.Errorf("stale If-None-Match => %d, want 200", rr3.Code)
	}

	// Other assets get an ETag too; unknown paths are still 404.
	rr4 := httptest.NewRecorder()
	mux.ServeHTTP(rr4, httptest.NewRequest("GET", "/favicon.svg", nil))
	if rr4.Code != http.StatusOK || rr4.Header().Get("ETag") == "" {
		t.Errorf("favicon.svg => %d etag %q", rr4.Code, rr4.Header().Get("ETag"))
	}
	rr5 := httptest.NewRecorder()
	mux.ServeHTTP(rr5, httptest.NewRequest("GET", "/nope-does-not-exist.js", nil))
	if rr5.Code != http.StatusNotFound {
		t.Errorf("unknown asset => %d, want 404", rr5.Code)
	}
}

func TestFix_g8_CloneNamePicksFreeSuffix(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()
	for _, n := range []string{"src", "src-copy", "src-copy2"} {
		if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES (?, ?, '10.0.0.1', 60, 1000, 25, 3, 3, 'paused', 'up', 'x')`, "id-"+n, n); err != nil {
			t.Fatal(err)
		}
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("POST", "/api/sensors/id-src/clone", nil))
	var got Sensor
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if rr.Code != http.StatusCreated || got.Name != "src-copy3" {
		t.Fatalf("clone => %d name %q, want 201 src-copy3 (%s)", rr.Code, got.Name, rr.Body.String())
	}
}

// A concurrent clone can take the chosen name between the SELECT and the
// INSERT. The trigger simulates that deterministically: just before the
// clone's own INSERT of "src-copy" it inserts "src-copy" itself, so the real
// INSERT fails with a UNIQUE error and the handler must move to "src-copy2"
// rather than return 500.
func TestFix_g8_CloneRetriesOnUniqueRace(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()
	if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('id-src', 'src', '10.0.0.1', 60, 1000, 25, 3, 3, 'paused', 'up', 'x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`CREATE TRIGGER race BEFORE INSERT ON sensors WHEN NEW.name = 'src-copy'
		BEGIN
			INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES ('racer', 'src-copy', '10.0.0.9', 60, 1000, 25, 3, 3, 'paused', 'up', 'x');
		END`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("POST", "/api/sensors/id-src/clone", nil))
	var got Sensor
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if rr.Code != http.StatusCreated || got.Name != "src-copy2" {
		t.Fatalf("raced clone => %d name %q, want 201 src-copy2 (%s)", rr.Code, got.Name, rr.Body.String())
	}
}

// When every attempt loses the race, the answer is 409 - not a 500 and not a
// leak of the driver's error text.
func TestFix_g8_CloneGivesUpWith409(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()
	if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('id-src', 'src', '10.0.0.1', 60, 1000, 25, 3, 3, 'paused', 'up', 'x')`); err != nil {
		t.Fatal(err)
	}
	// Every "src-copy*" name is taken by the trigger just before the INSERT.
	if _, err := d.Exec(`CREATE TRIGGER race BEFORE INSERT ON sensors WHEN NEW.name LIKE 'src-copy%'
		BEGIN
			INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES ('racer-' || NEW.name, NEW.name, '10.0.0.9', 60, 1000, 25, 3, 3, 'paused', 'up', 'x');
		END`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("POST", "/api/sensors/id-src/clone", nil))
	if rr.Code != http.StatusConflict || strings.Contains(rr.Body.String(), "UNIQUE") {
		t.Fatalf("exhausted clone => %d %s, want 409 without driver text", rr.Code, rr.Body.String())
	}
}

// TestFix_g8_CloneNameTruncatesByRunes pins the 2026-10-20 external review
// fix: the clone base is truncated to the RUNE cap (60 minus the longest
// suffix), not the byte cap. A 60-rune CJK name (180 bytes) keeps 52 runes
// before "-copy" — the old byte cut left only ~17. The same old byte cut
// was also the invalid-UTF-8 hazard: its continuation-byte rollback strip
// removed the split rune's trailing bytes but kept its FIRST byte
// (20×"网" cut at 52 B = 17 runes + dangling 0xE7), which the dashboard
// rendered as U+FFFD and validSensorName's utf8.ValidString gate later
// rejected on any PATCH renaming the clone. Rune slicing (9a5ba74) makes
// both failure modes unreachable; this assertion pins the exact valid
// result, which implies utf8.ValidString.
func TestFix_g8_CloneNameTruncatesByRunes(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()
	src := strings.Repeat("网", 60) // 60 runes, 180 bytes
	if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('id-src', ?, '10.0.0.1', 60, 1000, 25, 3, 3, 'paused', 'up', 'x')`, src); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("POST", "/api/sensors/id-src/clone", nil))
	var got Sensor
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	want := strings.Repeat("网", 52) + "-copy"
	if rr.Code != http.StatusCreated || got.Name != want {
		t.Fatalf("clone => %d name %q (%d runes), want 201 %d runes (%s)",
			rr.Code, got.Name, utf8.RuneCountInString(got.Name), utf8.RuneCountInString(want), rr.Body.String())
	}
}
