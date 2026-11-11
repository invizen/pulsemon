package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"pulsemon/internal/store"
	"strings"
	"testing"
)

// fixServerWithDB builds a Server on a fresh schema-initialized DB.
func fixServerWithDB(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	db := newTestDB(t)
	return NewServer(db, NewProbeWorker(db)), db
}

// TestFix_M7_PutSettingsKeepsRouting pins the M7(a) fix: a partial
// PUT /api/settings used to reset alert_scope to "all" and alert_filter to
// [] on EVERY save (repro: tags/["prod"] -> all/[] after saving
// {"realert_min":10}). AlertScope/AlertFilter are now pointers: nil = keep.
// Validation of scope/realert/filter also happens BEFORE any write, so a
// 400 leaves the store untouched.
func TestFix_M7_PutSettingsKeepsRouting(t *testing.T) {
	srv, db := fixServerWithDB(t)
	_ = db.SetSetting("alert_scope", "tags")
	_ = db.SetSetting("alert_filter", `["prod"]`)
	_ = db.SetSetting("realert_min", "30")

	// A partial save must keep scope + filter and change only realert_min.
	req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"realert_min": 10}`))
	rr := httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT {realert_min:10}: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := db.GetSetting("alert_scope"); got != "tags" {
		t.Errorf("alert_scope = %q after partial PUT, want \"tags\" (must be kept, not reset to all)", got)
	}
	if got := db.GetSetting("alert_filter"); got != `["prod"]` {
		t.Errorf("alert_filter = %q after partial PUT, want [\"prod\"] (must be kept, not reset to [])", got)
	}
	if got := db.GetSetting("realert_min"); got != "10" {
		t.Errorf("realert_min = %q after PUT, want \"10\"", got)
	}

	// Explicit values are still written (the dashboard saves full objects).
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"alert_scope":"all","alert_filter":[],"realert_min":15}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT full object: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := db.GetSetting("alert_scope"); got != "all" {
		t.Errorf("alert_scope = %q after explicit PUT, want \"all\"", got)
	}
	if got := db.GetSetting("alert_filter"); got != "[]" {
		t.Errorf("alert_filter = %q after explicit PUT, want []", got)
	}

	// An INVALID scope in the same request is a 400 and must not write the
	// valid fields that travel with it (validate everything first).
	_ = db.SetSetting("realert_min", "15")
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"realert_min": 99, "alert_scope": "bogus"}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT bogus scope: %d, want 400", rr.Code)
	}
	if got := db.GetSetting("realert_min"); got != "15" {
		t.Errorf("realert_min = %q after a 400 PUT, want \"15\" (a rejected save must not partially write)", got)
	}
}

// TestSettingsPutSwapsAlertSnapshot pins the finding-#5 snapshot swap:
// PUT /api/settings must reload the probe worker's alert settings snapshot
// after the commit, so the gate (maintenance, routing) reads the NEW values
// lock-free — not a stale pre-PUT snapshot. Pre-snapshot the gate re-read
// the DB on every decision, so a PUT took effect with no explicit swap; the
// snapshot makes that swap a step, and this test proves it happens (a
// missing reloadAlertSettings call in handleSettingsPut fails the
// maintenance assertion below).
func TestSettingsPutSwapsAlertSnapshot(t *testing.T) {
	srv, db := fixServerWithDB(t)
	pw := srv.probeWorker

	// An active sensor: entering maintenance pauses it (a fresh DB with no
	// active sensors 400s the maintenance PUT with "no active sensors to
	// pause").
	id := store.NewID()
	if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, 'active1','10.0.0.1','icmp',60,1000,25,2,5,'active','up',?)`, id, store.Now()); err != nil {
		t.Fatal(err)
	}

	// Baseline: maintenance off, scope all.
	if !pw.alertsEnabled() {
		t.Fatal("baseline: alertsEnabled=false, want true (maintenance off)")
	}
	if !pw.shouldAlert("any-sensor", nil) {
		t.Fatal("baseline: shouldAlert=false, want true (scope all)")
	}

	// Enter maintenance via the settings PUT: the gate must go silent on the
	// next decision (snapshot swapped) with no DB re-read on the hot path.
	req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"maintenance_mode": true}`))
	rr := httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT maintenance_mode:true: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if pw.alertsEnabled() {
		t.Error("alertsEnabled=true after a maintenance PUT, want false (the snapshot must reflect the committed change)")
	}

	// Leave maintenance: alerts return.
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"maintenance_mode": false}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT maintenance_mode:false: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if !pw.alertsEnabled() {
		t.Error("alertsEnabled=false after leaving maintenance, want true")
	}

	// Routing: scope=tags with a filter — only filtered sensors alert.
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"alert_scope":"tags","alert_filter":["prod"]}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT scope=tags: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if !pw.shouldAlert("s1", []string{"prod"}) {
		t.Error("shouldAlert(s1, [prod])=false, want true (tag in filter)")
	}
	if pw.shouldAlert("s2", []string{"dev"}) {
		t.Error("shouldAlert(s2, [dev])=true, want false (tag not in filter)")
	}
}

// TestSettingsPutReloadsSnapshotWhenMaintenanceTxFails (2026-11-10 review
// #6): the settings tx commits FIRST; if the maintenance-mode tx (its own
// transaction) then fails with a 500, the old handler returned BEFORE
// reloadAlertSettings — the provider/routing/realert_min changes in the
// same PUT stayed stale in pw.alertCfg until the next successful PUT or a
// restart. The reload is now deferred at commit, so every committed save
// converges memory to the store. Both 500 paths are pinned: entering
// maintenance (enterMaintenance seam) and leaving (setMaintenanceMode
// seam).
func TestSettingsPutReloadsSnapshotWhenMaintenanceTxFails(t *testing.T) {
	srv, db := fixServerWithDB(t)
	pw := srv.probeWorker

	// An active sensor so the entering-maintenance pre-check passes.
	id := store.NewID()
	if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, 'active1','10.0.0.1','icmp',60,1000,25,2,5,'active','up',?)`, id, store.Now()); err != nil {
		t.Fatal(err)
	}
	// Baseline: realert_min 30 in the store AND in the snapshot.
	if err := db.SetSetting("realert_min", "30"); err != nil {
		t.Fatal(err)
	}
	pw.reloadAlertSettings()
	if got := pw.realertMin(); got != 30 {
		t.Fatalf("baseline snapshot realertMin = %d, want 30", got)
	}

	t.Run("enter-maintenance-500", func(t *testing.T) {
		origEnter := enterMaintenance
		enterMaintenance = func(db *store.Store, ctx context.Context) ([]string, error) {
			return nil, errors.New("simulated maintenance tx failure")
		}
		defer func() { enterMaintenance = origEnter }()

		// The settings tx commits (realert_min=10); the maintenance tx 500s.
		req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"realert_min": 10, "maintenance_mode": true}`))
		rr := httptest.NewRecorder()
		srv.handleSettingsPut(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("PUT with failing maintenance tx: %d, want 500: %s", rr.Code, rr.Body.String())
		}
		if got := db.GetSetting("realert_min"); got != "10" {
			t.Errorf("store realert_min = %q, want \"10\" (the settings tx committed)", got)
		}
		// The snapshot must follow the committed store even though the
		// maintenance tx 500'd.
		if got := pw.realertMin(); got != 10 {
			t.Errorf("snapshot realertMin = %d after a 500 entering-maintenance PUT, want 10 (the reload must run on the committed-settings path)", got)
		}
	})

	t.Run("leave-maintenance-500", func(t *testing.T) {
		// Seed: maintenance ON, so the leave path reaches SetMaintenanceMode.
		if err := db.SetSetting("maintenance_mode", "1"); err != nil {
			t.Fatal(err)
		}
		pw.reloadAlertSettings()
		origSet := setMaintenanceMode
		setMaintenanceMode = func(db *store.Store, ctx context.Context, on bool, ids []string, snap string) error {
			return errors.New("simulated maintenance tx failure")
		}
		defer func() { setMaintenanceMode = origSet }()

		req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"realert_min": 20, "maintenance_mode": false}`))
		rr := httptest.NewRecorder()
		srv.handleSettingsPut(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("PUT with failing leave-maintenance tx: %d, want 500: %s", rr.Code, rr.Body.String())
		}
		if got := db.GetSetting("realert_min"); got != "20" {
			t.Errorf("store realert_min = %q, want \"20\" (the settings tx committed)", got)
		}
		if got := pw.realertMin(); got != 20 {
			t.Errorf("snapshot realertMin = %d after a 500 leave-maintenance PUT, want 20", got)
		}
	})
}

// TestFix_M7_PatchInvalidFieldDoesNotPersistTags pins the M7(b) fix: a PATCH
// used to write the tags BEFORE validating the remaining fields, so a 400
// left the tag set changed (repro: {"tags":["sneaky"],"interval_s":0} ->
// 400 with tags persisted). The tag write now happens only after ALL
// validation, in the same transaction as the UPDATE.
func TestFix_M7_PatchInvalidFieldDoesNotPersistTags(t *testing.T) {
	srv, db := fixServerWithDB(t)
	id := store.NewID()
	if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, 'a','10.0.0.1','icmp',60,1000,25,2,5,'paused','up',?)`, id, store.Now()); err != nil {
		t.Fatal(err)
	}

	// Valid tags + an invalid interval: 400, and the tags must NOT persist.
	req := httptest.NewRequest("PATCH", "/api/sensors/"+id, strings.NewReader(`{"tags":["sneaky"],"interval_s":0}`))
	req.SetPathValue("id", id)
	rr := httptest.NewRecorder()
	srv.handleSensorByID(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PATCH {tags, interval_s:0}: %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if tags, _ := db.SensorTags(context.Background(), id); len(tags) != 0 {
		t.Errorf("tags persisted after a 400 PATCH: %v — the tag write must not happen before validation", tags)
	}

	// A valid PATCH with tags still works and persists them.
	req = httptest.NewRequest("PATCH", "/api/sensors/"+id, strings.NewReader(`{"tags":["sneaky","ok"]}`))
	req.SetPathValue("id", id)
	rr = httptest.NewRecorder()
	srv.handleSensorByID(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH valid tags: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	tags, _ := db.SensorTags(context.Background(), id)
	if len(tags) != 2 || tags[0] != "ok" || tags[1] != "sneaky" {
		t.Errorf("tags after valid PATCH = %v, want [ok sneaky]", tags)
	}
}

// TestFix_M7_PatchDuplicateName409 pins the M7(c) fix: a PATCH rename (and a
// clone) hitting the UNIQUE name constraint used to return 500 with raw SQL
// text. It must return 409 {"error":"sensor name already exists"}, exactly
// like POST does.
func TestFix_M7_PatchDuplicateName409(t *testing.T) {
	srv, db := fixServerWithDB(t)
	mk := func(name string) string {
		id := store.NewID()
		if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, ?,'10.0.0.1','icmp',60,1000,25,2,5,'paused','up',?)`, id, name, store.Now()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	_ = mk("one")
	id2 := mk("two")

	req := httptest.NewRequest("PATCH", "/api/sensors/"+id2, strings.NewReader(`{"name":"one"}`))
	req.SetPathValue("id", id2)
	rr := httptest.NewRecorder()
	srv.handleSensorByID(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("PATCH rename to an existing name: %d, want 409: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode 409 body: %v", err)
	}
	if body.Error != "sensor name already exists" {
		t.Errorf("409 body = %q, want \"sensor name already exists\" (no raw SQL text)", body.Error)
	}
	// The original name is untouched.
	var name string
	if err := db.QueryRow("SELECT name FROM sensors WHERE id = ?", id2).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "two" {
		t.Errorf("name = %q after a rejected rename, want \"two\"", name)
	}

	// Clone: a normal clone finds a free "-copy" name and succeeds.
	srcID := mk("cloneme")
	req = httptest.NewRequest("POST", "/api/sensors/"+srcID+"/clone", nil)
	req.SetPathValue("id", srcID)
	rr = httptest.NewRecorder()
	srv.handleSensorClone(rr, req)
	if rr.Code != http.StatusCreated {
		t.Errorf("clone: %d, want 201: %s", rr.Code, rr.Body.String())
	}

	// Clone cap: with every "-copy".."-copy100" name taken, the clone is a
	// 409 (never a 500).
	capID := mk("capped")
	for i := 1; i <= 100; i++ {
		nm := "capped-copy"
		if i > 1 {
			nm = fmt.Sprintf("capped-copy%d", i)
		}
		if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, ?,'10.0.0.1','icmp',60,1000,25,2,5,'paused','up',?)`, store.NewID(), nm, store.Now()); err != nil {
			t.Fatal(err)
		}
	}
	req = httptest.NewRequest("POST", "/api/sensors/"+capID+"/clone", nil)
	req.SetPathValue("id", capID)
	rr = httptest.NewRecorder()
	srv.handleSensorClone(rr, req)
	if rr.Code != http.StatusConflict {
		t.Errorf("clone with all candidate names taken: %d, want 409: %s", rr.Code, rr.Body.String())
	}
}
