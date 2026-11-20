package main

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// TestPatchSensorScanErrorIs500Not404 pins the external-review 2026-11-19
// F17 fix: the in-tx sensor read in PATCH /api/sensors/{id} must classify
// ONLY sql.ErrNoRows as a 404. A transient SQLITE_BUSY, a canceled
// context, or an I/O failure must surface as a logged 500 — before the fix
// every scan error returned errPatchSensorGone, so the client was told
// "sensor not found" and the real error vanished from the service log.
//
// The failure is injected through the patchScanHook test seam (api.go):
// the real query still runs inside the real IMMEDIATE tx, the hook only
// replaces the scan error the handler must classify.
func TestPatchSensorScanErrorIs500Not404(t *testing.T) {
	_, do := newM10bServer(t)

	// Seed a real sensor so the injected failures happen on a row that
	// EXISTS — a 404 there would only be the missing-row behavior.
	code, out := do(http.MethodPost, "/api/sensors", `{"name":"scanerr","target":"192.0.2.1"}`)
	if code != http.StatusCreated {
		t.Fatalf("seed sensor: %d %v", code, out)
	}
	id, _ := out["id"].(string)

	t.Run("missing row is still 404 (positive control)", func(t *testing.T) {
		code, out := do(http.MethodPatch, "/api/sensors/does-not-exist", `{"name":"x"}`)
		if code != http.StatusNotFound {
			t.Fatalf("PATCH of a missing sensor = %d, want 404: %v", code, out)
		}
	})

	t.Run("clean patch is still 200 (positive control)", func(t *testing.T) {
		code, out := do(http.MethodPatch, "/api/sensors/"+id, `{"name":"scanerr2"}`)
		if code != http.StatusOK {
			t.Fatalf("clean PATCH = %d, want 200: %v", code, out)
		}
	})

	t.Run("injected non-NoRows scan failure is 500, not 404", func(t *testing.T) {
		patchScanHook = func(err error) error {
			return errors.New("SQLITE_BUSY: database is locked (injected)")
		}
		t.Cleanup(func() { patchScanHook = nil })

		code, out := do(http.MethodPatch, "/api/sensors/"+id, `{"name":"scanerr3"}`)
		if code == http.StatusNotFound {
			t.Fatalf("injected SQLITE_BUSY reported 404 'sensor not found' — it must be a 500: %v", out)
		}
		if code != http.StatusInternalServerError {
			t.Fatalf("injected SQLITE_BUSY = %d, want 500: %v", code, out)
		}
		if msg, _ := out["error"].(string); !strings.Contains(msg, "internal error") {
			t.Fatalf("500 body = %q, want the generic internal-error text (raw DB text must not leak to the client)", msg)
		}
	})

	t.Run("injected ErrNoRows stays 404", func(t *testing.T) {
		patchScanHook = func(err error) error { return sql.ErrNoRows }
		t.Cleanup(func() { patchScanHook = nil })

		code, out := do(http.MethodPatch, "/api/sensors/"+id, `{"name":"scanerr4"}`)
		if code != http.StatusNotFound {
			t.Fatalf("injected ErrNoRows = %d, want 404: %v", code, out)
		}
	})
}
