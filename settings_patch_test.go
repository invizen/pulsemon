package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"pulsemon/internal/store"
)

// fixServerWithDB builds a Server on a fresh schema-initialized DB.
func fixServerWithDB(t *testing.T) (*Server, *DB) {
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
	if tags := db.SensorTags(id); len(tags) != 0 {
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
	tags := db.SensorTags(id)
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
