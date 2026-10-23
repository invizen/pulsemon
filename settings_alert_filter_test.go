package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFix_SettingsAlertFilterBounded pins the alert_filter input gate in
// PUT /api/settings: the field used to be marshaled into the settings
// table with no validation of count, length, or charset — a near-1 MiB
// body could store thousands of unbounded strings that GET /api/settings
// and every shouldAlert decision unmarshal on each read. Entries are now
// trimmed, deduped, and must pass validSensorName (tag names and sensor
// ids both do), capped at 500 entries. An invalid or oversized list 400s
// the whole save and leaves the store untouched — including the other
// fields in the same request (the validate-everything-first contract).
// Fails pre-fix (200 + the garbage stored).
func TestFix_SettingsAlertFilterBounded(t *testing.T) {
	srv, db := fixServerWithDB(t)

	// Baseline values so "untouched after a 400" is checkable.
	_ = db.SetSetting("realert_min", "30")

	// Oversized list (501 entries): 400, and the other field in the same
	// request must NOT be written.
	big := make([]string, 501)
	for i := range big {
		big[i] = fmt.Sprintf("tag%d", i)
	}
	body, _ := json.Marshal(map[string]any{"alert_filter": big, "realert_min": 11})
	req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT 501-entry alert_filter: %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if got := db.GetSetting("realert_min"); got != "30" {
		t.Errorf("realert_min = %q after a 400 PUT, want 30 (a rejected save must not write other fields)", got)
	}
	if v := db.GetSetting("alert_filter"); v != "" {
		t.Errorf("alert_filter = %q after a 400 PUT, want empty (nothing written)", v)
	}

	// Invalid entry — a quote, exactly the string-escape character the
	// tag/name gate blocks: 400, other fields untouched.
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"alert_filter":["ok","x'"],"realert_min":12}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT alert_filter with quote entry: %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if got := db.GetSetting("realert_min"); got != "30" {
		t.Errorf("realert_min = %q after a 400 PUT, want 30 (a rejected save must not write other fields)", got)
	}

	// Overlong entry (61 runes): 400.
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"alert_filter":["`+strings.Repeat("a", 61)+`"]}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT 61-rune entry: %d, want 400: %s", rr.Code, rr.Body.String())
	}

	// Valid list with dups and surrounding whitespace: 200, stored
	// trimmed + deduped (first-seen order).
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"alert_filter":[" prod ", "prod", "core"]}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT valid alert_filter: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var got []string
	if err := json.Unmarshal([]byte(db.GetSetting("alert_filter")), &got); err != nil {
		t.Fatalf("decode stored alert_filter: %v", err)
	}
	if len(got) != 2 || got[0] != "prod" || got[1] != "core" {
		t.Errorf("stored alert_filter = %v, want [prod core] (trimmed + deduped)", got)
	}
}
