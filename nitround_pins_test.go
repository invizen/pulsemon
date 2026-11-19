package main

// Batch pins for the 2026-11-16 nit round: alert-state in-memory cache in
// front of the re-alert SELECT, and the hot-reload cert stat memo.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"pulsemon/internal/store"
	"testing"
	"time"
)

// TestRealertUsesAlertMemCache pins the re-alert hot path reading the
// in-memory alert-state copy instead of SELECTing alert_state every tick:
// after setAlertState seeds the cache, a steady-state error tick performs
// ZERO DB lookups; invalidation (ResetStatsFor, the clear-history path)
// forces exactly one durable re-read.
func TestRealertUsesAlertMemCache(t *testing.T) {
	db := newTestDB(t)
	pw := NewProbeWorker(db)

	// Seed a sensor row (alert_state has an FK to sensors).
	var id string
	if err := db.QueryRow(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, state, status)
		VALUES ('s1','s1','10.0.0.1','icmp',60,5000,50,3,'active','up') RETURNING id`).Scan(&id); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}

	lookups := 0
	orig := alertStateSelect
	t.Cleanup(func() { alertStateSelect = orig })
	alertStateSelect = func(db *store.Store, id string) (string, string, error) {
		lookups++
		return orig(db, id)
	}

	// Cold cache: one lookup seeds via the miss path (row absent ->
	// setAlertState writes DB + memory).
	c := sensorConfig{id: id, name: "s1"}
	pw.maybeRealert(context.Background(), c, "error", 0)
	if lookups != 1 {
		t.Fatalf("cold tick did %d lookups, want 1", lookups)
	}

	// Steady state (same status, inside the re-alert interval): zero DB.
	before := lookups
	pw.maybeRealert(context.Background(), c, "error", 0)
	pw.maybeRealert(context.Background(), c, "error", 0)
	if lookups != before {
		t.Fatalf("steady-state error ticks did %d alert_state lookups, want 0", lookups-before)
	}

	// Invalidation (single-sensor clear-history) forces one durable re-read.
	pw.ResetStatsFor(id)
	pw.maybeRealert(context.Background(), c, "error", 0)
	if lookups != before+1 {
		t.Fatalf("after invalidation: %d lookups, want exactly 1 more", lookups-before)
	}
}

// TestHotReloadCertStatMemo pins the certStatMemo window: while it is
// open, GetCertificate serves the cached pair without re-stating the
// files (a replacement on disk is NOT seen); once it elapses, the next
// call stats, sees the new fingerprint, and reloads.
func TestHotReloadCertStatMemo(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeTestCertPEM(t, certPath, keyPath)

	old := certStatMemo
	t.Cleanup(func() { certStatMemo = old })

	certStatMemo = 50 * time.Second // memo effectively frozen
	get := hotReloadCert(certPath, keyPath)
	c1, err := get(nil)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	// Replace the pair on disk; inside the memo window the stat is not
	// re-taken, so the cached pair is served (the memo must be what
	// suppresses the reload — not the loader).
	writeTestCertPEM(t, certPath, keyPath)
	c2, err := get(nil)
	if err != nil {
		t.Fatalf("memo-window call: %v", err)
	}
	if !sameCert(c1, c2) {
		t.Fatal("pair changed inside the memo window — the stat memo is not applied")
	}

	// Window closed: the next call re-stats and serves the new pair.
	certStatMemo = 0
	c3, err := get(nil)
	if err != nil {
		t.Fatalf("post-window call: %v", err)
	}
	if sameCert(c1, c3) {
		t.Fatal("replaced pair never picked up after the memo window closed")
	}
}

// TestUpdateCheckDisabledOptOut pins PULSEMON_DISABLE_UPDATE_CHECK=1: the
// endpoint answers a canned no-update result (disabled:true) and makes zero
// upstream calls — the routine call-home is fully silenced.
func TestUpdateCheckDisabledOptOut(t *testing.T) {
	var hits int
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://github.com/invizen/pulsemon/releases/tag/v9.9.9"}`))
	}))
	defer gh.Close()
	oldBase := releaseBase
	releaseBase = gh.URL + "/releases"
	t.Cleanup(func() { releaseBase = oldBase })
	oldCache, oldFailed := updateCheckCached, updateCheckFailed
	t.Cleanup(func() { updateCheckCached, updateCheckFailed = oldCache, oldFailed })
	updateCheckCached, updateCheckFailed = nil, false

	t.Setenv("PULSEMON_DISABLE_UPDATE_CHECK", "1")
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	req := httptest.NewRequest("GET", "/api/update-check?refresh=1", nil)
	rec := httptest.NewRecorder()
	srv.handleUpdateCheck(rec, req)
	if rec.Code != 200 {
		t.Fatalf("disabled check = %d, want 200", rec.Code)
	}
	var res updateCheckResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Disabled || res.Available {
		t.Fatalf("disabled check = %+v, want disabled:true available:false", res)
	}
	if hits != 0 {
		t.Fatalf("disabled check made %d upstream calls, want 0", hits)
	}
}
