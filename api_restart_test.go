package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// TestPatchSpikeMultNoRespawn pins the display-only contract: spike_mult
// only tints dashboard sparkline bars — the probe engine never reads it —
// so a spike_mult PATCH must succeed AND must not churn the probe loop
// (unlike loss_warn/down_after, which the running loop reads from its
// spawn-time config copy).
func TestPatchSpikeMultNoRespawn(t *testing.T) {
	patchSensorRespawned(t, `{"spike_mult": 8}`, false)
}

// TestSpikeMultLifecycle pins the field's full API surface: POST defaults
// to 5, GET returns it, PATCH validates the 2-10 range and persists, and
// clone carries the value over.
func TestSpikeMultLifecycle(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)
	do := func(method, path, body string) (int, map[string]interface{}) {
		req, _ := http.NewRequest(method, path, bytes.NewBufferString(body))
		rr := httptest.NewRecorder()
		srv.Mux().ServeHTTP(rr, req)
		var out map[string]interface{}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	// POST without spike_mult → default 5.
	code, created := do(http.MethodPost, "/api/sensors", `{"name":"sm1","target":"192.0.2.1"}`)
	if code != http.StatusCreated {
		t.Fatalf("POST = %d, want 201: %v", code, created)
	}
	if got := created["spike_mult"]; got != float64(5) {
		t.Fatalf("POST default spike_mult = %v, want 5", got)
	}
	id := created["id"].(string)

	// GET (list) returns it too.
	code, _ = do(http.MethodGet, "/api/sensors", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/sensors = %d", code)
	}
	// PATCH to 8 → persisted.
	code, _ = do(http.MethodPatch, "/api/sensors/"+id, `{"spike_mult": 8}`)
	if code != http.StatusOK {
		t.Fatalf("PATCH spike_mult=8 = %d, want 200", code)
	}
	var stored int
	if err := db.QueryRow(`SELECT spike_mult FROM sensors WHERE id = ?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 8 {
		t.Fatalf("stored spike_mult = %d, want 8", stored)
	}
	// Validation: below and above the range are rejected, stored value intact.
	for _, bad := range []int{1, 11} {
		code, _ = do(http.MethodPatch, "/api/sensors/"+id, fmt.Sprintf(`{"spike_mult": %d}`, bad))
		if code != http.StatusBadRequest {
			t.Fatalf("PATCH spike_mult=%d = %d, want 400", bad, code)
		}
	}
	if err := db.QueryRow(`SELECT spike_mult FROM sensors WHERE id = ?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 8 {
		t.Fatalf("stored spike_mult = %d after rejected patches, want 8", stored)
	}
	// POST validation.
	code, _ = do(http.MethodPost, "/api/sensors", `{"name":"sm2","target":"192.0.2.2","spike_mult": 11}`)
	if code != http.StatusBadRequest {
		t.Fatalf("POST spike_mult=11 = %d, want 400", code)
	}
	// Clone carries the value over.
	code, cloned := do(http.MethodPost, "/api/sensors/"+id+"/clone", "")
	if code != http.StatusCreated {
		t.Fatalf("clone = %d, want 201", code)
	}
	if got := cloned["spike_mult"]; got != float64(8) {
		t.Fatalf("clone spike_mult = %v, want 8", got)
	}
}

// TestPatchTargetStillRespawns pins that the pre-existing triggers still work
// (regression guard for the one-line change that added the new fields).
func TestPatchTargetStillRespawns(t *testing.T) {
	patchSensorRespawned(t, `{"target": "192.0.2.2"}`, true)
}
