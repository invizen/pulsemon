package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
	"pulsemon/internal/store"
)

// TestFix_CloneNamePickedInOneQuery pins the clone name-pick optimization:
// the existing clone names are fetched in ONE GLOB query and the first free
// suffix is picked in memory (the old loop ran up to 100 sequential SELECT
// COUNT(*) round-trips before the first INSERT — 2026-10-22 external
// review). The observable behavior must be unchanged — -copy, then
// -copy2..-copy100, 409 past the cap — and the test adds the edge the old
// exact-match loop never had: a base name containing GLOB metacharacters
// (validSensorName is a blacklist, so * ? [ are legal names). A "[" in the
// base turns the pattern's "[b]" into a character class, so the taken name
// "a[b]-copy" does NOT match "a[b]-copy*" — the in-memory scan picks it,
// the INSERT must hit the sensors.name UNIQUE index, and the retry must
// land on a[b]-copy2 (no 500, no duplicate). The UNIQUE index remains the
// arbiter in every case.
func TestFix_CloneNamePickedInOneQuery(t *testing.T) {
	srv, db := fixServerWithDB(t)
	mk := func(name string) string {
		id := store.NewID()
		if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, ?,'10.0.0.1','icmp',60,1000,25,2,5,'paused','up',?)`, id, name, store.Now()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	clone := func(srcID string) (int, string) {
		req := httptest.NewRequest("POST", "/api/sensors/"+srcID+"/clone", nil)
		req.SetPathValue("id", srcID)
		rr := httptest.NewRecorder()
		srv.handleSensorClone(rr, req)
		if rr.Code != http.StatusCreated {
			return rr.Code, ""
		}
		var body Sensor
		if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return rr.Code, body.Name
	}

	// 0 existing clones -> base-copy.
	id0 := mk("fresh")
	if code, name := clone(id0); code != http.StatusCreated || name != "fresh-copy" {
		t.Errorf("clone with no existing clones: %d %q, want 201 fresh-copy", code, name)
	}

	// 99 existing clones (fresh-copy..fresh-copy99) -> fresh-copy100: the
	// deep-scan case that used to be 100 sequential COUNT(*) queries.
	for i := 2; i <= 99; i++ { // fresh-copy (i==1) exists from the clone above
		mk(fmt.Sprintf("fresh-copy%d", i))
	}
	if code, name := clone(id0); code != http.StatusCreated || name != "fresh-copy100" {
		t.Errorf("clone with 99 existing clones: %d %q, want 201 fresh-copy100", code, name)
	}

	// Cap: fresh-copy..fresh-copy100 are all taken now -> 409 (never 500).
	if code, _ := clone(id0); code != http.StatusConflict {
		t.Errorf("clone with all 100 candidate names taken: %d, want 409", code)
	}

	// GLOB metacharacter edge (see the test comment): the under-matched
	// taken name is rejected by the UNIQUE index and the retry moves on.
	idMeta := mk("a[b]")
	mk("a[b]-copy")
	if code, name := clone(idMeta); code != http.StatusCreated || name != "a[b]-copy2" {
		t.Errorf("clone of a GLOB-metacharacter base: %d %q, want 201 a[b]-copy2 (UNIQUE index is the arbiter)", code, name)
	}
}

func TestFix_g8_CloneNamePicksFreeSuffix(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()
	for _, n := range []string{"src", "src-copy", "src-copy2"} {
		if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES (?, ?, '10.0.0.1', 60, 1000, 25, 3, 3, 'paused', 'up', 'x')`, "id-"+n, n); err != nil {
			t.Fatal(err)
		}
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("POST", "/api/sensors/id-src/clone", nil))
	var got Sensor
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if rr.Code != http.StatusCreated || got.Name != "src-copy3" {
		t.Fatalf("clone => %d name %q, want 201 src-copy3 (%s)", rr.Code, got.Name, rr.Body.String())
	}
}

// A concurrent clone can take the chosen name between the SELECT and the
// INSERT. The trigger simulates that deterministically: just before the
// clone's own INSERT of "src-copy" it inserts "src-copy" itself, so the real
// INSERT fails with a UNIQUE error and the handler must move to "src-copy2"
// rather than return 500.
func TestFix_g8_CloneRetriesOnUniqueRace(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()
	if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('id-src', 'src', '10.0.0.1', 60, 1000, 25, 3, 3, 'paused', 'up', 'x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`CREATE TRIGGER race BEFORE INSERT ON sensors WHEN NEW.name = 'src-copy'
		BEGIN
			INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES ('racer', 'src-copy', '10.0.0.9', 60, 1000, 25, 3, 3, 'paused', 'up', 'x');
		END`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("POST", "/api/sensors/id-src/clone", nil))
	var got Sensor
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if rr.Code != http.StatusCreated || got.Name != "src-copy2" {
		t.Fatalf("raced clone => %d name %q, want 201 src-copy2 (%s)", rr.Code, got.Name, rr.Body.String())
	}
}

// When every attempt loses the race, the answer is 409 - not a 500 and not a
// leak of the driver's error text.
func TestFix_g8_CloneGivesUpWith409(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()
	if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('id-src', 'src', '10.0.0.1', 60, 1000, 25, 3, 3, 'paused', 'up', 'x')`); err != nil {
		t.Fatal(err)
	}
	// Every "src-copy*" name is taken by the trigger just before the INSERT.
	if _, err := d.Exec(`CREATE TRIGGER race BEFORE INSERT ON sensors WHEN NEW.name LIKE 'src-copy%'
		BEGIN
			INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES ('racer-' || NEW.name, NEW.name, '10.0.0.9', 60, 1000, 25, 3, 3, 'paused', 'up', 'x');
		END`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("POST", "/api/sensors/id-src/clone", nil))
	if rr.Code != http.StatusConflict || strings.Contains(rr.Body.String(), "UNIQUE") {
		t.Fatalf("exhausted clone => %d %s, want 409 without driver text", rr.Code, rr.Body.String())
	}
}

// TestFix_g8_CloneNameTruncatesByRunes pins the 2026-10-20 external review
// fix: the clone base is truncated to the RUNE cap (60 minus the longest
// suffix), not the byte cap. A 60-rune CJK name (180 bytes) keeps 52 runes
// before "-copy" — the old byte cut left only ~17. The same old byte cut
// was also the invalid-UTF-8 hazard: its continuation-byte rollback strip
// removed the split rune's trailing bytes but kept its FIRST byte
// (20×"网" cut at 52 B = 17 runes + dangling 0xE7), which the dashboard
// rendered as U+FFFD and validSensorName's utf8.ValidString gate later
// rejected on any PATCH renaming the clone. Rune slicing (9a5ba74) makes
// both failure modes unreachable; this assertion pins the exact valid
// result, which implies utf8.ValidString.
func TestFix_g8_CloneNameTruncatesByRunes(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()
	src := strings.Repeat("网", 60) // 60 runes, 180 bytes
	if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('id-src', ?, '10.0.0.1', 60, 1000, 25, 3, 3, 'paused', 'up', 'x')`, src); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("POST", "/api/sensors/id-src/clone", nil))
	var got Sensor
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	want := strings.Repeat("网", 52) + "-copy"
	if rr.Code != http.StatusCreated || got.Name != want {
		t.Fatalf("clone => %d name %q (%d runes), want 201 %d runes (%s)",
			rr.Code, got.Name, utf8.RuneCountInString(got.Name), utf8.RuneCountInString(want), rr.Body.String())
	}
}

// TestCloneClampsLegacyParams pins the 2026-10-28 review n5 fix: a clone is
// a NEW write, so it must honor the CURRENT new-write floors/caps
// (minIntervalS, the timeout/loss/down/spike ranges, and the timeout <=
// interval*1000 cross-field rule) rather than copy the source verbatim. A
// legacy row can hold out-of-range values (those floors were added after the
// row existed and are deliberately not migrated — see minIntervalS), so a
// verbatim copy let an operator multiply a legacy 1s sensor indefinitely via
// clone. The seeds go in via a direct INSERT (the API would reject them); the
// clone must come back clamped into range.
func TestCloneClampsLegacyParams(t *testing.T) {
	d := newTestDB(t)
	mux := NewServer(d, NewProbeWorker(d)).Mux()
	seed := func(id string, intervalS, timeoutMS, lossWarn, downAfter, spikeMult int) {
		if _, err := d.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES (?, ?, '10.0.0.1', 'icmp', ?, ?, ?, ?, ?, 'paused', 'up', 'x')`,
			id, id, intervalS, timeoutMS, lossWarn, downAfter, spikeMult); err != nil {
			t.Fatal(err)
		}
	}
	clone := func(id string) Sensor {
		var got Sensor
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("POST", "/api/sensors/"+id+"/clone", nil))
		if rr.Code != http.StatusCreated {
			t.Fatalf("clone %s => %d, want 201 (%s)", id, rr.Code, rr.Body.String())
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	// All five params out of range: interval below the 5s floor, zeroed
	// loss_warn/down_after, spike_mult 15 above its cap -> clamped to the
	// nearest valid value. timeout 1000 stays (1000 <= 5*1000).
	seed("legacy-low", 1, 1000, 0, 0, 15)
	got := clone("legacy-low")
	if got.IntervalS != 5 || got.TimeoutMS != 1000 || got.LossWarn != 1 || got.DownAfter != 1 || got.SpikeMult != 10 {
		t.Errorf("legacy-low clone = interval %d / timeout %d / loss %d / down %d / spike %d, want 5 / 1000 / 1 / 1 / 10",
			got.IntervalS, got.TimeoutMS, got.LossWarn, got.DownAfter, got.SpikeMult)
	}

	// Cross-field: timeout 60000 clamps to the 30000 cap, then the
	// timeout <= interval*1000 rule (5*1000 = 5000) clamps it to 5000.
	seed("legacy-cross", 5, 60000, 50, 5, 5)
	got = clone("legacy-cross")
	if got.IntervalS != 5 || got.TimeoutMS != 5000 || got.LossWarn != 50 || got.DownAfter != 5 || got.SpikeMult != 5 {
		t.Errorf("legacy-cross clone = interval %d / timeout %d / loss %d / down %d / spike %d, want 5 / 5000 / 50 / 5 / 5 (cross-field)",
			got.IntervalS, got.TimeoutMS, got.LossWarn, got.DownAfter, got.SpikeMult)
	}

	// Control: an in-range source is copied unchanged (the clamp must not
	// perturb valid values).
	seed("normal", 60, 1000, 25, 2, 5)
	got = clone("normal")
	if got.IntervalS != 60 || got.TimeoutMS != 1000 || got.LossWarn != 25 || got.DownAfter != 2 || got.SpikeMult != 5 {
		t.Errorf("normal clone = interval %d / timeout %d / loss %d / down %d / spike %d, want 60 / 1000 / 25 / 2 / 5 (unchanged)",
			got.IntervalS, got.TimeoutMS, got.LossWarn, got.DownAfter, got.SpikeMult)
	}
}
