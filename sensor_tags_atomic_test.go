package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFix_PostAndCloneTagsAtomic pins the atomic create+tag fix: POST
// /api/sensors and POST /api/sensors/{id}/clone used to INSERT the sensor
// row (autocommit) and ONLY THEN replace the tags in a separate
// SetSensorTags transaction, logging and swallowing that error while still
// returning 201 with the requested tags in the body. A failed tag write
// left a sensor the API claimed was tagged but the DB had none — with
// alert_scope='tags' that silently changes which sensors alert once the
// user resumes the (paused) sensor. Both writes now commit in one
// ImmediateTx: a tag-write failure rolls back the row and the request
// fails, never a 201 with phantom tags. Fails on the pre-fix code (201 +
// a tagless row left behind).
func TestFix_PostAndCloneTagsAtomic(t *testing.T) {
	srv, db := fixServerWithDB(t)

	// Seed a source sensor carrying the poison tag BEFORE the trigger
	// exists (the trigger would block the seed insert too).
	srcID := newID()
	if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, 'src','127.0.0.1','icmp',60,1000,25,2,5,'paused','up',?)`, srcID, tsNow()); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSensorTags(srcID, []string{"bad"}); err != nil {
		t.Fatalf("seed source tags: %v", err)
	}

	// Force a tag-write failure: any insert of tag "bad" aborts (same
	// seam as TestSetSensorTagsAtomic).
	if _, err := db.Exec(`CREATE TRIGGER tagblock BEFORE INSERT ON sensor_tags
		FOR EACH ROW WHEN NEW.tag = 'bad'
		BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	defer db.Exec(`DROP TRIGGER IF EXISTS tagblock`)

	// POST with a failing tag write: not a 201 claiming the tags were
	// saved, and no sensor row may be left behind.
	req := httptest.NewRequest("POST", "/api/sensors", strings.NewReader(`{"name":"tagged","target":"127.0.0.1","type":"icmp","tags":["bad"]}`))
	rr := httptest.NewRecorder()
	srv.handleSensors(rr, req)
	if rr.Code == http.StatusCreated {
		t.Errorf("POST with failing tag write: %d — the API claimed the tags were saved; want a non-201 (the write must roll back)", rr.Code)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors WHERE name = 'tagged'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("sensor row persisted after a failed tag write: %d rows, want 0 (INSERT and tags must commit together)", n)
	}

	// Clone with a failing tag write: the same contract.
	req = httptest.NewRequest("POST", "/api/sensors/"+srcID+"/clone", nil)
	req.SetPathValue("id", srcID)
	rr = httptest.NewRecorder()
	srv.handleSensorClone(rr, req)
	if rr.Code == http.StatusCreated {
		t.Errorf("clone with failing tag write: %d — the API claimed the tags were saved; want a non-201", rr.Code)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors WHERE name = 'src-copy'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("clone row persisted after a failed tag write: %d rows, want 0 (INSERT and tags must commit together)", n)
	}

	// The trigger must not leak: a valid create with tags still works and
	// persists them (guards against an over-zealous rollback).
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS tagblock`); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("POST", "/api/sensors", strings.NewReader(`{"name":"oktag","target":"127.0.0.1","type":"icmp","tags":["good"]}`))
	rr = httptest.NewRecorder()
	srv.handleSensors(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST with valid tag: %d, want 201: %s", rr.Code, rr.Body.String())
	}
	var okID string
	if err := db.QueryRow("SELECT id FROM sensors WHERE name = 'oktag'").Scan(&okID); err != nil {
		t.Fatal(err)
	}
	if tags := db.SensorTags(okID); len(tags) != 1 || tags[0] != "good" {
		t.Errorf("tags after valid POST = %v, want [good]", tags)
	}
}
