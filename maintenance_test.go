package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"pulsemon/internal/store"
	"sync"
	"testing"
)

// sensorState reads one sensor's state column straight from the DB.
func sensorState(t *testing.T, db *store.Store, id string) string {
	t.Helper()
	var state string
	if err := db.QueryRow("SELECT state FROM sensors WHERE id = ?", id).Scan(&state); err != nil {
		t.Fatalf("read state for %s: %v", id, err)
	}
	return state
}

// putMaint drives a real PUT /api/settings through the API.
func putMaint(t *testing.T, srv *Server, on bool) {
	t.Helper()
	putMaintStatus(t, srv, on, http.StatusOK)
}

// putMaintStatus drives a real PUT /api/settings and asserts a specific code.
func putMaintStatus(t *testing.T, srv *Server, on bool, want int) {
	t.Helper()
	val := "false"
	if on {
		val = "true"
	}
	req, _ := http.NewRequest(http.MethodPut, "/api/settings", bytes.NewBufferString(`{"maintenance_mode":`+val+`}`))
	rr := httptest.NewRecorder()
	srv.Mux().ServeHTTP(rr, req)
	if rr.Code != want {
		t.Fatalf("PUT maintenance=%v = %d, want %d: %s", on, rr.Code, want, rr.Body.String())
	}
}

func newMaintTestDB(t *testing.T, rows []string) *store.Store {
	t.Helper()
	db, err := store.NewStore(filepath.Join(t.TempDir(), "maint.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for _, r := range rows {
		if _, err := db.Exec(r); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return db
}

const maintSeedActive = `INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at) VALUES ('a1', 'alpha', '192.0.2.1', 60, 1000, 25, 2, 3, 'active', 'up', '2026-01-01T00:00:00Z')`
const maintSeedPaused = `INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at) VALUES ('u1', 'gamma', '192.0.2.3', 60, 1000, 25, 2, 3, 'paused', 'up', '2026-01-01T00:00:00Z')`

// TestMaintenancePauseResume pins the rework: enable pauses every ACTIVE
// sensor and snapshots that set; disable reactivates exactly the snapshot.
// A user-paused sensor never leaves the paused state.
func TestMaintenancePauseResume(t *testing.T) {
	db := newMaintTestDB(t, []string{maintSeedActive, `INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at) VALUES ('a2', 'beta', '192.0.2.2', 60, 1000, 25, 2, 3, 'active', 'up', '2026-01-01T00:00:00Z')`, maintSeedPaused})
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	// Baseline: a1 + a2 active, u1 user-paused.
	if got := sensorState(t, db, "a1"); got != "active" {
		t.Fatalf("baseline a1 = %s", got)
	}

	// ENABLE: both active sensors pause, user-paused stays paused.
	putMaint(t, srv, true)
	if db.GetSetting("maintenance_mode") != "1" {
		t.Fatal("maintenance_mode != 1 after enable")
	}
	if db.GetSetting("maintenance_active_ids") == "" {
		t.Fatal("snapshot empty after enable")
	}
	for id, want := range map[string]string{"a1": "paused", "a2": "paused", "u1": "paused"} {
		if got := sensorState(t, db, id); got != want {
			t.Fatalf("after enable %s = %s, want %s", id, got, want)
		}
	}

	// DISABLE: snapshot reactivates a1 + a2; u1 stays paused; snapshot cleared.
	putMaint(t, srv, false)
	if db.GetSetting("maintenance_mode") != "0" {
		t.Fatal("maintenance_mode != 0 after disable")
	}
	if db.GetSetting("maintenance_active_ids") != "" {
		t.Fatal("snapshot not cleared after disable")
	}
	for id, want := range map[string]string{"a1": "active", "a2": "active", "u1": "paused"} {
		if got := sensorState(t, db, id); got != want {
			t.Fatalf("after disable %s = %s, want %s", id, got, want)
		}
	}
}

// TestMaintenanceIgnoresSensorsAddedDuringMaint pins that a sensor NOT in the
// snapshot (added while maintenance is on, starting paused like all new
// sensors) is left alone by resume — it stays paused even after the cycle.
func TestMaintenanceIgnoresSensorsAddedDuringMaint(t *testing.T) {
	db := newMaintTestDB(t, []string{maintSeedActive, maintSeedPaused})
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	putMaint(t, srv, true)

	// A sensor created while maintenance is on. New sensors start paused, and
	// it was not in the snapshot (taken at enable), so resume must not revive
	// it.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at) VALUES ('n1', 'newbie', '192.0.2.4', 60, 1000, 25, 2, 3, 'paused', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("add during maintenance: %v", err)
	}

	putMaint(t, srv, false)

	if got := sensorState(t, db, "a1"); got != "active" {
		t.Fatalf("a1 = %s after disable, want active (in snapshot)", got)
	}
	if got := sensorState(t, db, "n1"); got != "paused" {
		t.Fatalf("n1 = %s after disable, want paused (not in snapshot)", got)
	}
}

// TestMaintenanceIdempotentDisable pins that disabling with an empty/missing
// snapshot (e.g. a stale DB from before the rework) doesn't error and leaves
// states alone.
func TestMaintenanceIdempotentDisable(t *testing.T) {
	db := newMaintTestDB(t, []string{maintSeedActive})
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	// No snapshot was ever written; just flip the flag off.
	if err := db.SetSetting("maintenance_mode", "1"); err != nil {
		t.Fatal(err)
	}
	putMaint(t, srv, false)
	if got := sensorState(t, db, "a1"); got != "active" {
		t.Fatalf("a1 = %s, want active (untouched)", got)
	}
	if db.GetSetting("maintenance_mode") != "0" {
		t.Fatal("flag not off")
	}
}

// TestMaintenanceEnableNoActiveSensors pins the guard: enabling maintenance
// when NOTHING is active must be rejected (400) — an empty snapshot means
// resume would have nothing to restore, a state that can't be cleanly undone.
func TestMaintenanceEnableNoActiveSensors(t *testing.T) {
	db := newMaintTestDB(t, []string{maintSeedPaused})
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	putMaintStatus(t, srv, true, http.StatusBadRequest)
	if db.GetSetting("maintenance_mode") == "1" {
		t.Fatal("maintenance flag set despite zero active sensors")
	}
	if got := sensorState(t, db, "u1"); got != "paused" {
		t.Fatalf("u1 = %s, want paused (untouched)", got)
	}
}

// TestConcurrentEnterMaintenancePreservesSnapshot pins the double-click
// race end to end, with the interleaving FORCED through the
// enterMaintenance seam (the same pattern settings_patch_test.go uses to
// force post-commit failures): both PUTs are held at the seam so BOTH
// pre-reads of maintenance_mode observe "0" — the exact double-click
// shape the pre-tx read is racy on. The first PUT commits its enter
// (pause + snapshot), then the second runs: without the in-tx mode
// re-check it sees 0 active sensors (the first paused them all) and
// overwrites the snapshot with "null" — leaving maintenance then resumes
// NOTHING and strands the whole fleet paused.
func TestConcurrentEnterMaintenancePreservesSnapshot(t *testing.T) {
	db := newMaintTestDB(t, []string{maintSeedActive, `INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at) VALUES ('a2', 'beta', '192.0.2.2', 60, 1000, 25, 2, 3, 'active', 'up', '2026-01-01T00:00:00Z')`})
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	firstReached := make(chan struct{})
	secondReached := make(chan struct{})
	releaseA := make(chan struct{})
	releaseB := make(chan struct{})
	var mu sync.Mutex
	enterN := 0
	origEnter := enterMaintenance
	enterMaintenance = func(db *store.Store, ctx context.Context) ([]string, error) {
		mu.Lock()
		enterN++
		n := enterN
		mu.Unlock()
		if n == 1 {
			close(firstReached)
			<-releaseA
		} else {
			close(secondReached)
			<-releaseB
		}
		return db.EnterMaintenanceWithFreshSnapshot(ctx)
	}
	defer func() { enterMaintenance = origEnter }()

	put := func(done chan<- int) {
		req, _ := http.NewRequest(http.MethodPut, "/api/settings", bytes.NewBufferString(`{"maintenance_mode":true}`))
		rr := httptest.NewRecorder()
		srv.Mux().ServeHTTP(rr, req)
		done <- rr.Code
	}
	codeA := make(chan int, 1)
	go put(codeA)
	<-firstReached // PUT A is parked AT the enter — its commit has not happened
	codeB := make(chan int, 1)
	go put(codeB)   // PUT B's pre-read now observes "0" (A hasn't committed)
	<-secondReached // both pre-reads saw "0" — the double-click shape
	close(releaseA) // A's enter commits: 2 paused, snapshot [a1 a2], mode ON
	if code := <-codeA; code != http.StatusOK {
		t.Fatalf("PUT A = %d (want 200)", code)
	}
	close(releaseB) // B's enter runs AGAINST the committed mode — the race
	if code := <-codeB; code != http.StatusOK {
		t.Fatalf("PUT B = %d (want 200)", code)
	}
	// The snapshot must be the 2 active sensors, not "null".
	raw := db.GetSetting("maintenance_active_ids")
	var snap []string
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		t.Fatalf("snapshot is not valid JSON after the double-click enter: %v (%q)", err, raw)
	}
	if len(snap) != 2 {
		t.Fatalf("snapshot after the double-click enter = %v, want the 2 active sensors (pre-fix the second enter overwrote it with null)", snap)
	}
	// Leave resumes the full set — the fleet is not stranded.
	putMaint(t, srv, false)
	for _, id := range []string{"a1", "a2"} {
		if got := sensorState(t, db, id); got != "active" {
			t.Fatalf("%s = %s after leave, want active (fleet stranded paused)", id, got)
		}
	}
}

// TestMaintenanceTransitionOrdering pins the maintenance transition ORDER
// through the worker's observation hooks (nil in production): the
// alert-snapshot swap must land AFTER the transition's DB commit and
// BEFORE the in-memory pause flips, on BOTH sides —
//
//	enter: DB → reloadAlertSettings() → SetPaused(true)
//	leave: DB → ResetAlertStates() → reloadAlertSettings() → SetPaused(false)
//
// Pre-fix the reload ran only in the handler-exit defer: on enter,
// in-flight probes finishing after the commit fired alerts under a stale
// maintenance:false (an alert during a maintenance the operator just
// asked for); on leave, a fast sensor recovering between the resume and
// the handler exit read a stale maintenance:true and dropped its recovery
// alert permanently.
func TestMaintenanceTransitionOrdering(t *testing.T) {
	db := newMaintTestDB(t, []string{maintSeedActive})
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)

	var mu sync.Mutex
	var events []string
	pw.reloadObs = func() {
		mu.Lock()
		events = append(events, "reload")
		mu.Unlock()
	}
	pw.pausedObs = func(id string, paused bool) {
		mu.Lock()
		events = append(events, fmt.Sprintf("pause:%s:%v", id, paused))
		mu.Unlock()
	}
	takeEvents := func() []string {
		mu.Lock()
		defer mu.Unlock()
		e := make([]string, len(events))
		copy(e, events)
		events = nil
		return e
	}
	firstIndex := func(ev []string, s string) int {
		for i, x := range ev {
			if x == s {
				return i
			}
		}
		return -1
	}

	// ENTER: the explicit reload (post-commit) must precede the pause
	// flip. The handler-exit deferred reload is a later, idempotent event
	// and is irrelevant to the ordering — only the FIRST reload counts.
	putMaint(t, srv, true)
	ev := takeEvents()
	if i := firstIndex(ev, "pause:a1:true"); i == -1 {
		t.Fatalf("enter: no SetPaused(a1,true) observed (events %v)", ev)
	}
	if r := firstIndex(ev, "reload"); r == -1 {
		t.Fatalf("enter: no reloadAlertSettings observed (events %v)", ev)
	} else if r > firstIndex(ev, "pause:a1:true") {
		t.Fatalf("enter: reload (%d) after the pause flip (%d) — in-flight probes fire under a stale maintenance:false (events %v)",
			r, firstIndex(ev, "pause:a1:true"), ev)
	}

	// LEAVE: the reload (gate open) must precede the resume kick —
	// nothing can recover before the gate opens.
	putMaint(t, srv, false)
	ev = takeEvents()
	if i := firstIndex(ev, "pause:a1:false"); i == -1 {
		t.Fatalf("leave: no SetPaused(a1,false) observed (events %v)", ev)
	}
	if r := firstIndex(ev, "reload"); r == -1 {
		t.Fatalf("leave: no reloadAlertSettings observed (events %v)", ev)
	} else if r > firstIndex(ev, "pause:a1:false") {
		t.Fatalf("leave: reload (%d) after the resume kick (%d) — a fast recovery reads a stale maintenance:true and drops its alert (events %v)",
			r, firstIndex(ev, "pause:a1:false"), ev)
	}
}
