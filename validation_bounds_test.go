package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"pulsemon/internal/store"
	"strings"
	"testing"
)

// newM10bServer builds a real server over a temp DB and returns it plus a
// do() helper that drives the Mux directly (auth gate bypassed — these
// tests exercise the sensor-write validation, not auth).
func newM10bServer(t *testing.T) (*Server, func(string, string, string) (int, map[string]any)) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.NewStore(filepath.Join(dir, "m10b.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(db, NewProbeWorker(db))
	do := func(method, path, body string) (int, map[string]any) {
		req, _ := http.NewRequest(method, path, bytes.NewBufferString(body))
		rr := httptest.NewRecorder()
		srv.Mux().ServeHTTP(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	return srv, do
}

// TestFix_M10b_PostIntervalFloor pins the 5s floor on the POST path:
// interval_s below 5 is a 400 (with the exact message), 5 and 3600 are the
// accepted bounds, 3601 is a 400, and an omitted value still defaults to 60.
func TestFix_M10b_PostIntervalFloor(t *testing.T) {
	_, do := newM10bServer(t)

	code, out := do(http.MethodPost, "/api/sensors", `{"name":"a","target":"192.0.2.1","interval_s":4}`)
	if code != http.StatusBadRequest {
		t.Fatalf("POST interval_s=4 = %d, want 400: %v", code, out)
	}
	if msg := out["error"].(string); msg != "interval_s must be 5-3600" {
		t.Fatalf("POST interval_s=4 error = %q, want the exact floor message", msg)
	}

	for _, ok := range []int{5, 3600} {
		code, out = do(http.MethodPost, "/api/sensors", fmt.Sprintf(`{"name":"ok%d","target":"192.0.2.1","interval_s":%d}`, ok, ok))
		if code != http.StatusCreated {
			t.Fatalf("POST interval_s=%d = %d, want 201: %v", ok, code, out)
		}
	}

	code, out = do(http.MethodPost, "/api/sensors", `{"name":"big","target":"192.0.2.1","interval_s":3601}`)
	if code != http.StatusBadRequest {
		t.Fatalf("POST interval_s=3601 = %d, want 400: %v", code, out)
	}
}

// TestFix_M10b_PostIntervalDefault pins that an OMITTED interval_s still
// defaults to 60 (the floor must not change the default).
func TestFix_M10b_PostIntervalDefault(t *testing.T) {
	srv, do := newM10bServer(t)
	code, out := do(http.MethodPost, "/api/sensors", `{"name":"dflt","target":"192.0.2.1"}`)
	if code != http.StatusCreated {
		t.Fatalf("POST omitted interval_s = %d, want 201: %v", code, out)
	}
	id := out["id"].(string)
	var stored int
	if err := srv.db.QueryRow(`SELECT interval_s FROM sensors WHERE id = ?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 60 {
		t.Fatalf("default interval_s = %d, want 60", stored)
	}
}

// TestFix_M10b_DownAfterBounded pins down_after 1-100 on BOTH POST and
// PATCH. POST: omitted defaults to 2, 1 and 100 are accepted, 101 is a 400
// with the exact message. PATCH: 101 is a 400, 1 is accepted.
func TestFix_M10b_DownAfterBounded(t *testing.T) {
	srv, do := newM10bServer(t)

	code, out := do(http.MethodPost, "/api/sensors", `{"name":"da","target":"192.0.2.1","down_after":101}`)
	if code != http.StatusBadRequest {
		t.Fatalf("POST down_after=101 = %d, want 400: %v", code, out)
	}
	if msg := out["error"].(string); msg != "down_after must be 1-100" {
		t.Fatalf("POST down_after=101 error = %q, want the exact message", msg)
	}
	for _, ok := range []int{1, 100} {
		code, out = do(http.MethodPost, "/api/sensors", fmt.Sprintf(`{"name":"da%d","target":"192.0.2.1","down_after":%d}`, ok, ok))
		if code != http.StatusCreated {
			t.Fatalf("POST down_after=%d = %d, want 201: %v", ok, code, out)
		}
	}
	// Omitted down_after still defaults to 2.
	code, out = do(http.MethodPost, "/api/sensors", `{"name":"dada","target":"192.0.2.1"}`)
	if code != http.StatusCreated {
		t.Fatalf("POST omitted down_after = %d, want 201: %v", code, out)
	}
	id := out["id"].(string)
	var stored int
	if err := srv.db.QueryRow(`SELECT down_after FROM sensors WHERE id = ?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 2 {
		t.Fatalf("default down_after = %d, want 2", stored)
	}

	// PATCH side.
	code, out = do(http.MethodPatch, "/api/sensors/"+id, `{"down_after":101}`)
	if code != http.StatusBadRequest {
		t.Fatalf("PATCH down_after=101 = %d, want 400: %v", code, out)
	}
	code, out = do(http.MethodPatch, "/api/sensors/"+id, `{"down_after":1}`)
	if code != http.StatusOK {
		t.Fatalf("PATCH down_after=1 = %d, want 200: %v", code, out)
	}
}

// TestFix_M10b_TimeoutVsInterval pins the timeout_ms <= interval_s*1000
// cross-check on both paths. POST: 5s interval + 6000ms timeout is a 400,
// the equal boundary (5s + 5000ms) is accepted. PATCH uses the STORED value
// for whichever of the two is not supplied.
func TestFix_M10b_TimeoutVsInterval(t *testing.T) {
	srv, do := newM10bServer(t)

	// POST: timeout longer than the interval is rejected.
	code, out := do(http.MethodPost, "/api/sensors", `{"name":"t1","target":"192.0.2.1","interval_s":5,"timeout_ms":6000}`)
	if code != http.StatusBadRequest {
		t.Fatalf("POST 5s+6000ms = %d, want 400: %v", code, out)
	}
	if msg := out["error"].(string); msg != "timeout_ms must not exceed interval_s*1000" {
		t.Fatalf("POST cross-check error = %q, want the exact message", msg)
	}
	// Equal boundary is allowed.
	code, out = do(http.MethodPost, "/api/sensors", `{"name":"t2","target":"192.0.2.1","interval_s":5,"timeout_ms":5000}`)
	if code != http.StatusCreated {
		t.Fatalf("POST 5s+5000ms = %d, want 201: %v", code, out)
	}

	// PATCH: seed a 10s/10000ms row via SQL (a fast row the API would now
	// refuse to create), then exercise the stored-value fallback.
	id := store.NewID()
	if _, err := srv.db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, created_at, status)
		VALUES (?, 'p1', '192.0.2.9', 'icmp', 10, 10000, 25, 2, 5, 'paused', ?, 'up')`, id, store.Now()); err != nil {
		t.Fatal(err)
	}
	// Shrink the interval below the stored timeout: 10000ms > 5s*1000.
	code, out = do(http.MethodPatch, "/api/sensors/"+id, `{"interval_s":5}`)
	if code != http.StatusBadRequest {
		t.Fatalf("PATCH interval_s=5 (stored 10000ms) = %d, want 400: %v", code, out)
	}
	// Grow the timeout past the stored interval: 11000ms > 10s*1000.
	code, out = do(http.MethodPatch, "/api/sensors/"+id, `{"timeout_ms":11000}`)
	if code != http.StatusBadRequest {
		t.Fatalf("PATCH timeout_ms=11000 (stored 10s) = %d, want 400: %v", code, out)
	}
	// Equal boundary on the PATCH cross-check is accepted.
	code, out = do(http.MethodPatch, "/api/sensors/"+id, `{"timeout_ms":10000}`)
	if code != http.StatusOK {
		t.Fatalf("PATCH timeout_ms=10000 (stored 10s) = %d, want 200: %v", code, out)
	}
	if !strings.Contains(strings.Join([]string{fmt.Sprint(out["status"])}, " "), "updated") {
		t.Fatalf("PATCH timeout_ms=10000 body = %v, want updated", out)
	}
}

// TestPatchCrossFieldSentinelsNotSubstrings (review 2026-11-11 #7) pins
// that PATCH routes every validateCrossField rejection onto its sentinel
// through the error VALUE (crossFieldError.Unwrap → errors.Is), not
// through substrings of the message ("URL" / "timeout" / "down_after").
// Pre-refactor the closure re-derived the mapping from err.Error() text,
// so any wording tweak in sensor_spec.go silently mis-routed the 400 —
// and with the refactor's plain-returns as the sabotage (sentinel codes
// stripped from the returned errors), every case here lands on the
// closure's outer default (respondInternal) and answers 500.
// All field values stay inside sensorBounds so each request reaches the
// cross-field gate, not the per-field bound check.
func TestPatchCrossFieldSentinelsNotSubstrings(t *testing.T) {
	_, do := newM10bServer(t)
	code, out := do("POST", "/api/sensors", `{"name":"cf-1","target":"10.0.0.1","type":"icmp","interval_s":60,"timeout_ms":1000,"loss_warn":25,"down_after":2,"spike_mult":3}`)
	if code != http.StatusCreated {
		t.Fatalf("seed sensor: %d %v", code, out)
	}
	id, _ := out["id"].(string)
	cases := []struct{ label, body, want string }{
		{"http target not a URL", `{"type":"http","target":"notaurl"}`, "target must be an http://"},
		// #29 (2026-11-20): the errPatchTargetInvalid 400 now renders the
		// probe-type-specific message (patchErr.Error()), so a TCP target
		// without a port gets the TCP text, not the ICMP "IPv4 address or
		// hostname". The sentinel routing this test pins is unchanged.
		{"tcp target without port", `{"type":"tcp","target":"noport"}`, "target must be host:port with an explicit port"},
		{"icmp target invalid", `{"target":"!!!"}`, "target must be an IPv4 address or hostname"},
		{"timeout over interval", `{"interval_s":5,"timeout_ms":30000}`, "timeout_ms must not exceed interval_s*1000"},
		{"down_after over retention", `{"interval_s":3600,"down_after":100}`, "down_after × interval_s must not exceed 24h"},
	}
	for _, c := range cases {
		code, out = do("PATCH", "/api/sensors/"+id, c.body)
		msg, _ := out["error"].(string)
		if code != http.StatusBadRequest {
			t.Errorf("%s: PATCH got %d %v, want 400 routed to its sentinel (500 = sentinel lost, fell through to respondInternal)", c.label, code, out)
			continue
		}
		if !strings.Contains(msg, c.want) {
			t.Errorf("%s: 400 body %q, want it to carry %q (silent cross-field misroute)", c.label, msg, c.want)
		}
	}

	// The detailed POST text is the SAME Error() string: validate() must
	// keep rendering the full example message (client-visible contract).
	code, out = do("POST", "/api/sensors", `{"name":"cf-2","target":"notaurl","type":"http"}`)
	msg, _ := out["error"].(string)
	if code != http.StatusBadRequest || !strings.Contains(msg, "target must be an http:// or https:// URL (e.g. https://example.com/health)") {
		t.Errorf("POST http invalid target: %d %v, want 400 with the detailed example text", code, out)
	}
}

// TestPatchSensorRejectsUnknownField pins the strict-decode fix: a misspelled
// field alongside a valid one is now a 400 (before the fix the misspelled
// field was silently ignored and the valid one applied). Well-formed payloads
// are unaffected.
func TestPatchSensorRejectsUnknownField(t *testing.T) {
	_, do := newM10bServer(t)
	code, out := do(http.MethodPost, "/api/sensors", `{"name":"uf","target":"192.0.2.1"}`)
	if code != http.StatusCreated {
		t.Fatalf("seed sensor: %d %v", code, out)
	}
	id, _ := out["id"].(string)

	// "timout_ms" is a typo for "timeout_ms" — with a valid "name" present.
	code, out = do(http.MethodPatch, "/api/sensors/"+id, `{"name":"renamed","timout_ms":5000}`)
	if code != http.StatusBadRequest {
		t.Fatalf("PATCH with a misspelled field = %d, want 400: %v", code, out)
	}
	// The valid-only request still works (strict decode must not reject
	// well-formed payloads).
	code, out = do(http.MethodPatch, "/api/sensors/"+id, `{"name":"renamed"}`)
	if code != http.StatusOK {
		t.Fatalf("PATCH with a valid field = %d, want 200: %v", code, out)
	}
}

// TestPatchTCPInvalidTargetGetsTCPMessage pins the PATCH error-message fix:
// a TCP sensor with an invalid target must get the TCP "host:port" message,
// not the ICMP "IPv4 address or hostname" text (the old hardcoded case returned
// the ICMP text for BOTH types). The ICMP path is the positive control — it
// still gets its own message.
func TestPatchTCPInvalidTargetGetsTCPMessage(t *testing.T) {
	_, do := newM10bServer(t)

	code, out := do(http.MethodPost, "/api/sensors", `{"name":"tcp1","target":"192.0.2.1:80","type":"tcp"}`)
	if code != http.StatusCreated {
		t.Fatalf("seed TCP sensor: %d %v", code, out)
	}
	id, _ := out["id"].(string)

	// PATCH the TCP target to a bare IP (no port) — invalid for TCP.
	code, out = do(http.MethodPatch, "/api/sensors/"+id, `{"target":"192.0.2.1"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("PATCH TCP target without port = %d, want 400: %v", code, out)
	}
	msg, _ := out["error"].(string)
	if !strings.Contains(msg, "host:port") {
		t.Fatalf("TCP target error = %q, want the TCP 'host:port' message", msg)
	}
	if strings.Contains(msg, "IPv4 address or hostname") {
		t.Fatalf("TCP target error = %q leaked the ICMP 'IPv4 address or hostname' text", msg)
	}

	// Positive control: an ICMP sensor with an IPv6 literal (neither an IPv4
	// address nor a hostname) still gets the ICMP message.
	code, out = do(http.MethodPost, "/api/sensors", `{"name":"icmp1","target":"2001:db8::1"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("POST ICMP sensor with an IPv6 target = %d, want 400: %v", code, out)
	}
	if msg, _ := out["error"].(string); msg != "target must be an IPv4 address or hostname" {
		t.Fatalf("ICMP target error = %q, want the ICMP 'IPv4 address or hostname' message", msg)
	}
}

// TestValidateRangeBeforeCrossField (review 2026-11-24 nits) pins the
// CHECK ORDER in sensorSpec.validate(): per-field range checks must run
// BEFORE validateCrossField. When both a range violation and a cross-field
// violation are present, the RANGE error wins — a cross-field message about
// an out-of-range field is misleading (interval_s=4 + timeout_ms=4500 must
// say "interval_s must be 5-3600", not "timeout_ms must not exceed
// interval_s*1000"), and an out-of-range interval_s makes the
// IntervalS*1000 / DownAfter*IntervalS products in validateCrossField
// meaningless (they can overflow int).
// History: docs/DECISIONS.md → validation-range-before-cross-field.
func TestValidateRangeBeforeCrossField(t *testing.T) {
	_, do := newM10bServer(t)

	// interval_s=4 is below the 5-3600 bound AND timeout_ms=4500 exceeds
	// 4*1000 — the range error must be reported, not the timeout rule.
	code, out := do(http.MethodPost, "/api/sensors", `{"name":"ord1","target":"192.0.2.1","interval_s":4,"timeout_ms":4500}`)
	if code != http.StatusBadRequest {
		t.Fatalf("POST 4s+4500ms = %d, want 400: %v", code, out)
	}
	if msg := out["error"].(string); msg != "interval_s must be 5-3600" {
		t.Fatalf("POST 4s+4500ms error = %q, want the interval_s range error (cross-field fired first = order regression)", msg)
	}

	// Huge interval_s (1e18): DownAfter*IntervalS overflows the 24h
	// cross-field comparison — the range check must fire before any
	// cross-field product is computed.
	code, out = do(http.MethodPost, "/api/sensors", `{"name":"ord2","target":"192.0.2.1","interval_s":1000000000000000000,"timeout_ms":100}`)
	if code != http.StatusBadRequest {
		t.Fatalf("POST 1e18s interval = %d, want 400: %v", code, out)
	}
	if msg := out["error"].(string); msg != "interval_s must be 5-3600" {
		t.Fatalf("POST 1e18s interval error = %q, want the interval_s range error (a cross-field product overflowed)", msg)
	}

	// Positive control: both fields IN range, timeout over interval — the
	// cross-field rule must still fire with its own message.
	code, out = do(http.MethodPost, "/api/sensors", `{"name":"ord3","target":"192.0.2.1","interval_s":5,"timeout_ms":6000}`)
	if code != http.StatusBadRequest {
		t.Fatalf("POST 5s+6000ms = %d, want 400: %v", code, out)
	}
	if msg := out["error"].(string); msg != "timeout_ms must not exceed interval_s*1000" {
		t.Fatalf("POST 5s+6000ms error = %q, want the cross-field message (range-first broke the in-range path)", msg)
	}
}
