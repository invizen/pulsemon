package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// patchSensorRespawned drives a real PATCH through the API against a live
// ProbeWorker and reports whether the PATCH triggered a probe-loop respawn.
//
// M2 regression: syncSensors captures each sensor's config by value at
// spawn and the loop never refreshes it — deriveStatus reads down_after and
// loss_warn from that spawn-time copy. A PATCH that wrote the new
// thresholds to the DB without respawning the loop would leave the running
// probe operating on stale values until a full process restart (API says
// "updated", probe disagrees).
//
// Mechanics: Restart(id) cancels the old loop and REMOVES the map entry; the
// respawn happens on the next syncSensors pass (the 5s tick in production),
// which re-queries the DB and re-spawns any missing loop with fresh config.
// So "triggered" = the map entry is GONE after the PATCH, and a follow-up
// syncSensors re-spawns it. A non-triggering PATCH leaves the entry in
// place and a follow-up sync is a no-op for that sensor. (Go funcs aren't
// comparable, so the observation is the map lifecycle, not cancel identity.)
func patchSensorRespawned(t *testing.T, body string, wantRespawn bool) {
	t.Helper()
	dir := t.TempDir()
	db, err := NewDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	// The probe loops spawned by syncSensors are children of this context.
	// Cancelling it stops them. Declared AFTER defer db.Close() so it runs
	// FIRST (LIFO) — the loop must not tick a probe into an already-closed
	// DB (its first tick is phase-staggered 0..interval and can land right
	// after the test ends).
	lctx, lcancel := context.WithCancel(context.Background())
	defer db.Close()
	defer lcancel()
	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('s1', 's1', '192.0.2.1', 15, 1000, 10, 10, 5, 'active', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)
	pw.syncSensors(lctx)

	pw.mu.Lock()
	_, ok := pw.loops["s1"]
	pw.mu.Unlock()
	if !ok {
		t.Fatalf("syncSensors did not spawn a loop for s1")
	}

	req, _ := http.NewRequest(http.MethodPatch, "/api/sensors/s1", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	srv.Mux().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH %s = %d, want 200: %s", body, rr.Code, rr.Body.String())
	}

	pw.mu.Lock()
	_, afterPatch := pw.loops["s1"]
	pw.mu.Unlock()

	if wantRespawn {
		if afterPatch {
			t.Fatalf("PATCH %s: loop still registered after PATCH — Restart was not called", body)
		}
		// The next syncSensors pass (what Run's 5s tick does) must respawn
		// the loop with the fresh DB config.
		pw.syncSensors(lctx)
		pw.mu.Lock()
		_, respawned := pw.loops["s1"]
		pw.mu.Unlock()
		if !respawned {
			t.Fatalf("PATCH %s: syncSensors did not respawn the loop after restart", body)
		}
		return
	}

	// Non-triggering: the original loop must survive the PATCH AND the next
	// sync pass (no churn on cosmetic/metadata-only edits).
	if !afterPatch {
		t.Fatalf("PATCH %s: loop was respawned — want no restart for this field", body)
	}
	pw.syncSensors(lctx)
	pw.mu.Lock()
	_, stillThere := pw.loops["s1"]
	pw.mu.Unlock()
	if !stillThere {
		t.Fatalf("PATCH %s: loop disappeared on the next sync pass", body)
	}
}

// TestPatchLossWarnRespawns pins the M2 fix: PATCH loss_warn must trigger a
// loop respawn so deriveStatus uses the new threshold, not the spawn-time
// value.
func TestPatchLossWarnRespawns(t *testing.T) {
	patchSensorRespawned(t, `{"loss_warn": 20}`, true)
}

// TestPatchDownAfterRespawns pins the same for down_after — the reported
// regression: down_after 4 → 10 kept erroring after 4 losses until restart.
func TestPatchDownAfterRespawns(t *testing.T) {
	patchSensorRespawned(t, `{"down_after": 10}`, true)
}

// TestPatchNameNoRespawn pins the boundary: a pure metadata PATCH must NOT
// respawn the loop (no config the running probe reads changed) — avoids
// needless probe-loop churn on cosmetic edits.
func TestPatchNameNoRespawn(t *testing.T) {
	patchSensorRespawned(t, `{"name": "renamed"}`, false)
}

// TestPatchSpikeMultDeprecated pins the deprecated spike_mult field's
// backward-compat behavior: the field is no longer accepted by PATCH, so a
// spike_mult-only request is an empty patch — 400 "no fields to update",
// nothing written, and the probe loop must not churn.
func TestPatchSpikeMultDeprecated(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	lctx, lcancel := context.WithCancel(context.Background())
	defer db.Close()
	defer lcancel()
	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('s1', 's1', '192.0.2.1', 15, 1000, 10, 10, 5, 'active', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)
	pw.syncSensors(lctx)

	req, _ := http.NewRequest(http.MethodPatch, "/api/sensors/s1", bytes.NewBufferString(`{"spike_mult": 8}`))
	rr := httptest.NewRecorder()
	srv.Mux().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PATCH {\"spike_mult\": 8} = %d, want 400 (deprecated field is not accepted): %s", rr.Code, rr.Body.String())
	}

	// The stored value is untouched and the loop did not churn.
	var stored int
	if err := db.QueryRow(`SELECT spike_mult FROM sensors WHERE id = 's1'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 5 {
		t.Fatalf("spike_mult changed to %d, want 5 (deprecated field must not write)", stored)
	}
	pw.mu.Lock()
	_, alive := pw.loops["s1"]
	pw.mu.Unlock()
	if !alive {
		t.Fatal("probe loop churned on a deprecated-field PATCH")
	}
}

// TestPatchTargetStillRespawns pins that the pre-existing triggers still work
// (regression guard for the one-line change that added the new fields).
func TestPatchTargetStillRespawns(t *testing.T) {
	patchSensorRespawned(t, `{"target": "192.0.2.2"}`, true)
}
