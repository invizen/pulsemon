package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	}
	for _, c := range cases {
		if got := validSensorName(c.name); got != c.ok {
			t.Errorf("validSensorName(%q) = %v, want %v", c.name, got, c.ok)
		}
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
	_ = json.NewDecoder(resp.Body).Decode(&out)
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
	json.NewDecoder(resp.Body).Decode(&sensors)
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
	json.NewDecoder(resp.Body).Decode(&events)
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
	json.NewDecoder(resp.Body).Decode(&small)
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
	_ = json.NewDecoder(resp.Body).Decode(&out)
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
	_ = json.NewDecoder(resp.Body).Decode(&out)
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
	_ = json.NewDecoder(resp.Body).Decode(&out)
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
	_ = json.NewDecoder(resp.Body).Decode(&out)
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

	// Fresh DB has no users → auth disabled → endpoints are open.
	if srv.auth.Enabled() {
		t.Fatal("expected auth disabled on fresh test DB")
	}

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
