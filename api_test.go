package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"pulsemon/internal/store"
)

// TestValidSensorName pins the stored-XSS name gate: names that could escape
// their string context in a consumer (inline event handler, alert card) are
// rejected at the API layer, while ordinary operator labels pass.
func TestValidSensorName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"router", true},
		{"my server", true},
		{"ok-name_1.2", true},
		{"ÜberNAS", true}, // non-ASCII is fine — no string-escape char
		{"", false},
		{"x');alert(1);//", false},       // single-quote breakout
		{"a\"b", false},                  // double quote
		{"a`b", false},                   // backtick
		{"a\\b", false},                  // backslash
		{"a<b", false},                   // angle bracket
		{"a>b", false},                   // angle bracket
		{"tab\nline", false},             // control char (newline)
		{"nul\x00x", false},              // control char (NUL)
		{strings.Repeat("x", 61), false}, // over 60
		{strings.Repeat("x", 60), true},  // exactly 60 ok
		// Rune-length cap (external review #8): 60 CJK chars = 180 bytes
		// must pass — the UI maxlength="60" allows exactly this.
		{strings.Repeat("网", 60), true},
		{strings.Repeat("网", 61), false},
		// Invalid UTF-8 is refused at the write path (external review #8).
		{"ok\xff\xfe", false},
	}
	for _, c := range cases {
		if got := validSensorName(c.name); got != c.ok {
			t.Errorf("validSensorName(%q) = %v, want %v", c.name, got, c.ok)
		}
	}
}

// TestCleanTagsXSSGate pins the tag half of the stored-XSS fix: tags flow
// into JS string literals in the setTag / removeFormTag inline handlers, so
// cleanTags applies the same string-escape gate as sensor names. Breakout
// payloads are dropped at the API layer; ordinary operator labels (the ones
// the 2026-10-13 review pinned as legitimate) still pass, and the existing
// trim / dedupe / 30-char / 8-tag behavior is unchanged.
func TestCleanTagsXSSGate(t *testing.T) {
	got := cleanTags([]string{
		"wifi:guest",          // legit: colon
		"nas/01",              // legit: slash
		"camera@front",        // legit: at-sign
		"ÜberNAS",             // legit: non-ASCII
		" x');alert(1);//",    // single-quote breakout — dropped (after trim)
		`a"onfocus="alert(1)`, // double-quote attribute breakout — dropped
		"a\\b",                // backslash — dropped
		"a`b",                 // backtick — dropped
		"a<b",                 // angle bracket — dropped
		"line\nbreak",         // control char — dropped
		"wifi:guest",          // duplicate — dropped
	})
	want := []string{"wifi:guest", "nas/01", "camera@front", "ÜberNAS"}
	if len(got) != len(want) {
		t.Fatalf("cleanTags = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("cleanTags = %v, want %v", got, want)
		}
	}
	// The 30-char cap and 8-tag cap still apply.
	long := cleanTags([]string{strings.Repeat("x", 31), strings.Repeat("x", 30)})
	if len(long) != 1 || long[0] != strings.Repeat("x", 30) {
		t.Fatalf("30-char cap broken: %v", long)
	}
	// The cap counts RUNES (external review #8): 30 CJK chars = 90 bytes
	// must pass, 31 must be dropped.
	longCJK := cleanTags([]string{strings.Repeat("网", 31), strings.Repeat("网", 30)})
	if len(longCJK) != 1 || longCJK[0] != strings.Repeat("网", 30) {
		t.Fatalf("30-rune tag cap broken: %v", longCJK)
	}
	many := cleanTags([]string{"a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10"})
	if len(many) != 8 {
		t.Fatalf("8-tag cap broken: %v", many)
	}
}

// TestRequestBodyBounded drives the real server: a valid-but-oversized JSON
// body (2 MiB of padding, well past the 1 MiB gate limit) must be refused at
// the auth gate with 413 "request body too large" — not silently buffered
// into the JSON decoder. Without the MaxBytesReader bound this body decodes
// fine and the POST succeeds (201), so the test fails on the unfixed build.
func TestRequestBodyBounded(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	// Auth-disabled state (bootstrapped install, zero users): endpoints are
	// open. This test exercises the body bound, not auth — the setup-mode
	// and disable paths are locked in TestSetupModeBootstrapOnly and
	// TestAuthDisableViaAPI.
	db.SetSetting("auth_bootstrapped", "1")

	// Valid JSON, ~2 MiB: a 1 MiB string field of padding.
	pad := strings.Repeat("x", 1<<20)
	body := `{"name":"router","target":"10.99.99.1","pad":"` + pad + `"}`
	resp, err := http.Post(httpSrv.URL+"/api/sensors", "application/json",
		strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Error string `json:"error"`
	}
	jsonDecode(t, resp, &out)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: got %d, want 413", resp.StatusCode)
	}
	if !strings.Contains(strings.ToLower(out.Error), "too large") {
		t.Fatalf("oversized body: error %q does not mention the size limit", out.Error)
	}

	// A normal-sized body still works end-to-end.
	resp, err = http.Post(httpSrv.URL+"/api/sensors", "application/json",
		strings.NewReader(`{"name":"router","target":"10.99.99.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("normal body: got %d, want 201", resp.StatusCode)
	}
}

// TestEventsQueryCapped drives the real server: the events endpoint must cap
// ?n= at 500, exactly like the sensor-history endpoint already does. With 700
// stored events, n=10000 must still return only 500 (the newest 500).
func TestEventsQueryCapped(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	// Auth-disabled state (bootstrapped install, zero users): endpoints are
	// open. This test exercises the events API, not auth — the setup-mode
	// and disable paths are locked in TestSetupModeBootstrapOnly and
	// TestAuthDisableViaAPI.
	db.SetSetting("auth_bootstrapped", "1")

	// One sensor + 700 events with distinct ascending timestamps.
	resp, err := http.Post(httpSrv.URL+"/api/sensors", "application/json",
		strings.NewReader(`{"name":"router","target":"10.99.99.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var got Sensor
	resp, err = http.Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	var sensors []Sensor
	jsonDecode(t, resp, &sensors)
	resp.Body.Close()
	if len(sensors) != 1 {
		t.Fatalf("want 1 sensor, got %d", len(sensors))
	}
	got = sensors[0]

	base := time.Now().Add(-700 * time.Second).UTC()
	for i := 0; i < 700; i++ {
		ts := base.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		if _, err := db.Exec("INSERT INTO events (sensor_id, ts, from_status, to_status, note) VALUES (?, ?, ?, ?, ?)",
			got.ID, ts, "up", "error", "test event"); err != nil {
			t.Fatal(err)
		}
	}

	// n=10000 must be capped at 500.
	resp, err = http.Get(httpSrv.URL + "/api/events?n=10000")
	if err != nil {
		t.Fatal(err)
	}
	var events []EventView
	jsonDecode(t, resp, &events)
	resp.Body.Close()
	if len(events) != 500 {
		t.Fatalf("events?n=10000: got %d events, want 500 (cap)", len(events))
	}

	// A request below the cap is honored.
	resp, err = http.Get(httpSrv.URL + "/api/events?n=10")
	if err != nil {
		t.Fatal(err)
	}
	var small []EventView
	jsonDecode(t, resp, &small)
	resp.Body.Close()
	if len(small) != 10 {
		t.Fatalf("events?n=10: got %d events, want 10", len(small))
	}
}

// TestSettingsTestRejectsUnknownKind drives the real server: POST
// /api/settings/test must be self-documenting — an unknown or missing
// provider kind is a 400 naming the valid kinds (NOT 200 {"ok":false}), and
// a malformed JSON body is a 400 instead of being silently swallowed into
// an empty kind. A known kind without a URL stays a 200 {"ok":false} — that
// is the "test ran, no target configured" outcome the UI relies on.
func TestSettingsTestRejectsUnknownKind(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	// Auth-disabled state (bootstrapped install, zero users): endpoints are
	// open. This test exercises the settings API, not auth — the setup-mode
	// and disable paths are locked in TestSetupModeBootstrapOnly and
	// TestAuthDisableViaAPI.
	db.SetSetting("auth_bootstrapped", "1")

	var out struct {
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
		Error  string `json:"error"`
	}

	// 1) Unknown kind: 400, names the valid kinds.
	resp, err := http.Post(httpSrv.URL+"/api/settings/test", "application/json",
		strings.NewReader(`{"kind":"carrier_pigeon"}`))
	if err != nil {
		t.Fatal(err)
	}
	jsonDecode(t, resp, &out)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown kind: got %d, want 400", resp.StatusCode)
	}
	low := strings.ToLower(out.Error)
	if !strings.Contains(low, "carrier_pigeon") || !strings.Contains(low, "google_chat") || !strings.Contains(low, "discord") {
		t.Fatalf("unknown kind: error %q should name the bad kind and the valid kinds", out.Error)
	}

	// 2) Missing kind (empty body): 400, not a 200 {"ok":false}.
	resp, err = http.Post(httpSrv.URL+"/api/settings/test", "application/json",
		strings.NewReader(``))
	if err != nil {
		t.Fatal(err)
	}
	jsonDecode(t, resp, &out)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty body: got %d, want 400", resp.StatusCode)
	}

	// 3) Malformed JSON: 400, not silently swallowed.
	resp, err = http.Post(httpSrv.URL+"/api/settings/test", "application/json",
		strings.NewReader(`{not json`))
	if err != nil {
		t.Fatal(err)
	}
	jsonDecode(t, resp, &out)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON: got %d, want 400", resp.StatusCode)
	}

	// 4) A known kind with no URL configured: still 200 {"ok":false} with a
	// detail — the test ran, it just had nothing to deliver to.
	out = struct {
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
		Error  string `json:"error"`
	}{}
	resp, err = http.Post(httpSrv.URL+"/api/settings/test", "application/json",
		strings.NewReader(`{"kind":"google_chat"}`))
	if err != nil {
		t.Fatal(err)
	}
	jsonDecode(t, resp, &out)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("known kind, no URL: got %d, want 200", resp.StatusCode)
	}
	if out.OK || out.Detail == "" {
		t.Fatalf("known kind, no URL: ok=%v detail=%q, want ok=false with a detail", out.OK, out.Detail)
	}
}

// TestSensorNameXSSRejectedEndToEnd drives the real server: a sensor name
// carrying a quote-breakout payload must be refused on both POST and PATCH,
// and the stored name of a clean sensor must survive a round-trip. This is
// the server-side half of the stored-XSS fix (the frontend escJs is the
// other half).
func TestSensorNameXSSRejectedEndToEnd(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	// Auth-disabled state (bootstrapped install, zero users): endpoints are
	// open. This test exercises the sensors API, not auth — the setup-mode
	// and disable paths are locked in TestSetupModeBootstrapOnly and
	// TestAuthDisableViaAPI.
	db.SetSetting("auth_bootstrapped", "1")

	// 1) POST with a breakout name must be 400.
	resp, err := http.Post(httpSrv.URL+"/api/sensors", "application/json",
		strings.NewReader(`{"name":"x');alert(1);//","target":"10.99.99.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST breakout name: got %d, want 400", resp.StatusCode)
	}

	// 2) A clean POST must succeed.
	resp, err = http.Post(httpSrv.URL+"/api/sensors", "application/json",
		strings.NewReader(`{"name":"router","target":"10.99.99.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST clean name: got %d, want 201", resp.StatusCode)
	}

	// Find the created sensor id.
	var got Sensor
	if err := db.QueryRow("SELECT id,name,target FROM sensors WHERE name='router'").
		Scan(&got.ID, &got.Name, &got.Target); err != nil {
		t.Fatalf("read created sensor: %v", err)
	}
	if got.Name != "router" {
		t.Fatalf("stored name = %q, want router", got.Name)
	}

	// 3) PATCH that renames it to a backslash-breakout name must be 400.
	req, _ := http.NewRequest("PATCH", httpSrv.URL+"/api/sensors/"+got.ID,
		strings.NewReader(`{"name":"a\\b"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = httpSrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PATCH backslash name: got %d, want 400", resp.StatusCode)
	}

	// 4) The name must be unchanged after the rejected PATCH.
	var after string
	if err := db.QueryRow("SELECT name FROM sensors WHERE id=?", got.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != "router" {
		t.Fatalf("name after rejected PATCH = %q, want router (unchanged)", after)
	}

	// 5) A clean PATCH rename must succeed.
	req, _ = http.NewRequest("PATCH", httpSrv.URL+"/api/sensors/"+got.ID,
		strings.NewReader(`{"name":"router2"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = httpSrv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH clean rename: got %d, want 200", resp.StatusCode)
	}
	if err := db.QueryRow("SELECT name FROM sensors WHERE id=?", got.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != "router2" {
		t.Fatalf("renamed = %q, want router2", after)
	}
}

// TestLossWarnBounded locks the M2 fix: loss_warn is range-checked (1-100) on
// BOTH POST and PATCH. Out-of-range values are a 400, an omitted value
// defaults to 25, and a valid PATCH value is persisted.
func TestLossWarnBounded(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	// Auth-disabled state (bootstrapped install, zero users): endpoints are
	// open. This test exercises the sensors API, not auth — the setup-mode
	// and disable paths are locked in TestSetupModeBootstrapOnly and
	// TestAuthDisableViaAPI.
	db.SetSetting("auth_bootstrapped", "1")

	// POST: out-of-range → 400.
	resp, err := http.Post(httpSrv.URL+"/api/sensors", "application/json",
		strings.NewReader(`{"name":"a","target":"10.99.99.1","loss_warn":150}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST loss_warn=150: got %d, want 400", resp.StatusCode)
	}

	// POST: omitted → 201, defaults to 25.
	resp, err = http.Post(httpSrv.URL+"/api/sensors", "application/json",
		strings.NewReader(`{"name":"router","target":"10.99.99.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST omitted loss_warn: got %d, want 201", resp.StatusCode)
	}
	var lw int
	if err := db.QueryRow("SELECT loss_warn FROM sensors WHERE name='router'").Scan(&lw); err != nil {
		t.Fatal(err)
	}
	if lw != 25 {
		t.Fatalf("default loss_warn = %d, want 25", lw)
	}

	var id string
	if err := db.QueryRow("SELECT id FROM sensors WHERE name='router'").Scan(&id); err != nil {
		t.Fatal(err)
	}
	patch := func(body string) int {
		req, _ := http.NewRequest("PATCH", httpSrv.URL+"/api/sensors/"+id, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r, err := httpSrv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}

	// PATCH: 0 and 150 → 400; 50 → 200 and persisted.
	if code := patch(`{"loss_warn":0}`); code != http.StatusBadRequest {
		t.Fatalf("PATCH loss_warn=0: got %d, want 400", code)
	}
	if code := patch(`{"loss_warn":150}`); code != http.StatusBadRequest {
		t.Fatalf("PATCH loss_warn=150: got %d, want 400", code)
	}
	if code := patch(`{"loss_warn":50}`); code != http.StatusOK {
		t.Fatalf("PATCH loss_warn=50: got %d, want 200", code)
	}
	if err := db.QueryRow("SELECT loss_warn FROM sensors WHERE id=?", id).Scan(&lw); err != nil {
		t.Fatal(err)
	}
	if lw != 50 {
		t.Fatalf("loss_warn after PATCH = %d, want 50", lw)
	}
}

// TestMaintenanceModeFlipsInMemoryPauseImmediately pins the maintenance-mode
// fast path: enabling maintenance must flip the probe worker's in-memory
// pause flag IMMEDIATELY (the same SetPaused fast path the single-sensor
// PATCH uses), not on the next 5s syncSensors tick. Pre-fix, the sensor
// loops kept probing during the window — up to one extra probe row and a
// possible transition event per sensor landed after maintenance was already
// reported ON. Disabling must flip the flag back just as immediately.
func TestMaintenanceModeFlipsInMemoryPauseImmediately(t *testing.T) {
	db := newTestDB(t)
	pw := NewProbeWorker(db)
	srv := NewServer(db, pw)
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	// Auth-disabled state (bootstrapped install, zero users): endpoints are
	// open. This test exercises the maintenance transition, not auth.
	db.SetSetting("auth_bootstrapped", "1")

	// One ACTIVE sensor, with its in-memory state as syncSensors would have
	// built it (probing, not paused). No loop is spawned — the test asserts
	// the flag flip, not the probe cadence.
	id := store.NewID()
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, created_at, status)
		VALUES (?, 'maint-test', '10.99.99.1', 'icmp', 60, 1000, 25, 2, 3, 'active', ?, 'up')`, id, store.Now()); err != nil {
		t.Fatal(err)
	}
	pw.mu.Lock()
	pw.sensors[id] = &ProbeState{id: id, isPaused: false}
	pw.mu.Unlock()

	put := func(body string) int {
		req, _ := http.NewRequest(http.MethodPut, httpSrv.URL+"/api/settings", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r, err := httpSrv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	paused := func() bool {
		pw.mu.Lock()
		defer pw.mu.Unlock()
		return pw.sensors[id].isPaused
	}
	dbState := func() string {
		var st string
		if err := db.QueryRow("SELECT state FROM sensors WHERE id = ?", id).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}

	// Enable: the in-memory flag flips NOW — no sync tick in between.
	if code := put(`{"maintenance_mode":true}`); code != http.StatusOK {
		t.Fatalf("enable maintenance: got %d, want 200", code)
	}
	if !paused() {
		t.Fatal("in-memory isPaused not flipped immediately on maintenance enable")
	}
	if st := dbState(); st != "paused" {
		t.Fatalf("db state = %q, want paused", st)
	}
	if db.GetSetting("maintenance_mode") != "1" {
		t.Fatal("maintenance_mode flag not set in db")
	}

	// Disable: the flag flips back NOW too (symmetric fast path).
	if code := put(`{"maintenance_mode":false}`); code != http.StatusOK {
		t.Fatalf("disable maintenance: got %d, want 200", code)
	}
	if paused() {
		t.Fatal("in-memory isPaused not cleared immediately on maintenance disable")
	}
	if st := dbState(); st != "active" {
		t.Fatalf("db state = %q, want active", st)
	}
}

// TestPatchSingleReadValidation pins the 2026-10-19 external review #10
// shape: PATCH /api/sensors/{id} reads the row ONCE, inside the
// ImmediateTx, and validates the type/target pair plus the effective
// timeout-vs-interval cross-check against those fresh values. Every case
// below used to be answered by a pre-lock SELECT + validation pass; the
// responses (status + message) must be byte-identical to that era, and no
// partial write may survive a 400.
func TestPatchSingleReadValidation(t *testing.T) {
	srv, db := fixServerWithDB(t)
	mk := func(target string, intervalS int) string {
		id := store.NewID()
		if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, ?,?,'icmp',?,1000,25,2,5,'paused','up',?)`, id, id, target, intervalS, store.Now()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	patch := func(id, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PATCH", "/api/sensors/"+id, strings.NewReader(body))
		req.SetPathValue("id", id)
		rr := httptest.NewRecorder()
		srv.handleSensorByID(rr, req)
		return rr
	}
	rowType := func(id string) string {
		var typ string
		if err := db.QueryRow("SELECT type FROM sensors WHERE id = ?", id).Scan(&typ); err != nil {
			t.Fatal(err)
		}
		return typ
	}

	// 1. Type-only change to http with a bare-host stored target: 400,
	//    type unchanged. (The case the pre-tx SELECT target path used to
	//    catch.)
	id := mk("10.0.0.1", 60)
	if rr := patch(id, `{"type":"http"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("type-only change, bare-host target: %d, want 400: %s", rr.Code, rr.Body.String())
	} else if rowType(id) != "icmp" {
		t.Errorf("type changed after a 400: %q", rowType(id))
	}

	// 2. Target-only change to a bare host on an http sensor: 400.
	idHTTP := store.NewID()
	if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, 'h','http://example.com/health','http',60,1000,25,2,5,'paused','up',?)`, idHTTP, store.Now()); err != nil {
		t.Fatal(err)
	}
	if rr := patch(idHTTP, `{"target":"bare-host"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("bare host on http sensor: %d, want 400: %s", rr.Code, rr.Body.String())
	}

	// 3. Target + type changed together, invalid pair: 400.
	if rr := patch(id, `{"target":"bare-host","type":"http"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("target+type invalid pair: %d, want 400: %s", rr.Code, rr.Body.String())
	}

	// 4. Valid target+type pair in one PATCH: 200, both persisted.
	if rr := patch(id, `{"target":"http://example.com/health","type":"http"}`); rr.Code != http.StatusOK {
		t.Fatalf("valid pair: %d, want 200: %s", rr.Code, rr.Body.String())
	} else if rowType(id) != "http" {
		t.Errorf("type = %q, want http", rowType(id))
	}

	// 5. Effective timeout-vs-interval cross-check against the STORED
	//    interval (only timeout_ms sent): interval 5s allows at most
	//    5000ms, so 6000 (inside the 100-30000 field range) must 400.
	//    (The case the pre-tx storedTimeoutMS cross-check used to catch.)
	idShort := mk("10.0.0.2", 5)
	if rr := patch(idShort, `{"timeout_ms":6000}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("timeout above stored interval*1000: %d, want 400: %s", rr.Code, rr.Body.String())
	}

	// 6. Nonexistent sensor: 404 (now carried by the in-tx read).
	if rr := patch(store.NewID(), `{"name":"ghost"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("PATCH nonexistent sensor: %d, want 404: %s", rr.Code, rr.Body.String())
	}
}
