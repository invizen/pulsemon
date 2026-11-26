package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNewHTTPServerBaseContextCancellable pins the MINOR-18 shutdown
// contract: the server's BaseContext returns a cancellable context, and
// the cancel func newHTTPServer returns stops it — runServer calls it
// after the 5s HTTP drain, so a handler that outlived the drain (a 30s
// sensor ping mid-probe) aborts its request context before the deferred
// db.Close() instead of running into a closed DB.
// History: docs/DECISIONS.md → slow-handler-write-deadlines.
func TestNewHTTPServerBaseContextCancellable(t *testing.T) {
	srv, cancel := newHTTPServer(http.NewServeMux())
	ctx := srv.BaseContext(nil)
	if ctx == nil {
		t.Fatal("BaseContext returned nil")
	}
	select {
	case <-ctx.Done():
		t.Fatal("BaseContext done before cancel")
	default:
	}
	cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("BaseContext not cancelled by the returned cancel func")
	}
}

// TestSensorPingExtendsWriteDeadline pins the MINOR-18 fix: a pulse runs
// the sensor's own timeout (up to the 30000ms API cap) plus the history
// write, so a loss on a max-timeout sensor takes just over the 30s server
// WriteTimeout before the {"lost":true} response — the handler must
// extend THIS connection's write deadline (40s), and the client gets the
// diagnostic toast instead of a broken pipe.
// History: docs/DECISIONS.md → slow-handler-write-deadlines.
func TestSensorPingExtendsWriteDeadline(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('pingwd','pingwd','192.0.2.1',60,30000,25,1,5,'active','up','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)
	orig := probeTarget
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		return probeOutcome{lost: true, ip: "192.0.2.1"}
	}
	t.Cleanup(func() { probeTarget = orig })

	req := httptest.NewRequest(http.MethodPost, "/api/sensors/pingwd/ping", nil)
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ping handler: %d, want 200, body %s", w.Code, w.Body.String())
	}
	if w.deadline.IsZero() {
		t.Fatal("ping handler set no write deadline — a max-timeout (30s) loss would trip the 30s server WriteTimeout before the response")
	}
	if rem := time.Until(w.deadline); rem < 35*time.Second || rem > 45*time.Second {
		t.Errorf("ping write deadline = %v from now, want ~40s (past the 30s timeout cap + history write)", rem)
	}
}

// TestSettingsTestExtendsWriteDeadline pins the same contract for the
// settings-test button: a test against a hanging SMTP relay runs up to
// the SMTP transport budget (~15s), which plus the pre-flight reads can
// graze the 30s server WriteTimeout — the handler extends the connection
// deadline to 45s.
// History: docs/DECISIONS.md → slow-handler-write-deadlines.
func TestSettingsTestExtendsWriteDeadline(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))

	req := httptest.NewRequest(http.MethodPost, "/api/settings/test", strings.NewReader(`{"kind":"google_chat"}`))
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	srv.Mux().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("settings-test handler: %d, want 200, body %s", w.Code, w.Body.String())
	}
	if w.deadline.IsZero() {
		t.Fatal("settings-test handler set no write deadline — a test on a hanging SMTP relay would trip the 30s server WriteTimeout")
	}
	if rem := time.Until(w.deadline); rem < 40*time.Second || rem > 50*time.Second {
		t.Errorf("settings-test write deadline = %v from now, want ~45s", rem)
	}
}
