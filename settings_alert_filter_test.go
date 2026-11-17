package main

import (
	"bytes"
	"context"
	"log"

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

// TestSettingsPutRejectsEmptyFilterWhenScopeIsNotAll pins the dead-alert
// guard in PUT /api/settings: with alert_scope=tags/sensors and an EMPTY
// effective filter (incoming or stored), shouldAlert matches no sensor —
// the monitor silently stops alerting for everything, the worst failure
// mode for a monitor. The UI can save exactly this state (scope switched
// to "tags" with no tag selected), so the server 400s it before any write;
// scope=all keeps the filter optional. Fails pre-fix (200 + the dead
// state stored).
func TestSettingsPutRejectsEmptyFilterWhenScopeIsNotAll(t *testing.T) {
	srv, db := fixServerWithDB(t)

	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(body))
		rr := httptest.NewRecorder()
		srv.handleSettingsPut(rr, req)
		return rr
	}

	// Fresh store, scope=tags, no filter sent: 400, nothing written.
	if rr := put(`{"alert_scope":"tags"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT scope=tags without filter: %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if v := db.GetSetting("alert_scope"); v != "" {
		t.Errorf("alert_scope = %q after a 400 PUT, want empty (nothing written)", v)
	}

	// Explicit empty filter list: 400.
	if rr := put(`{"alert_scope":"sensors","alert_filter":[]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT scope=sensors with empty filter: %d, want 400: %s", rr.Code, rr.Body.String())
	}

	// Stored non-all scope + incoming empty filter: 400 — the guard checks
	// the EFFECTIVE state (incoming value if sent, else stored), not just
	// the incoming fields.
	_ = db.SetSetting("alert_scope", "tags")
	_ = db.SetSetting("alert_filter", `["prod"]`)
	if rr := put(`{"alert_filter":[]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT empty filter over stored scope=tags: %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if v := db.GetSetting("alert_filter"); v != `["prod"]` {
		t.Errorf("alert_filter = %q after a 400 PUT, want [\"prod\"] (untouched)", v)
	}

	// scope=all accepts an empty filter (no routing — nothing to match).
	if rr := put(`{"alert_scope":"all","alert_filter":[]}`); rr.Code != http.StatusOK {
		t.Fatalf("PUT scope=all with empty filter: %d, want 200: %s", rr.Code, rr.Body.String())
	}

	// The valid state: scope=tags + a real filter: 200, stored.
	if rr := put(`{"alert_scope":"tags","alert_filter":["prod"]}`); rr.Code != http.StatusOK {
		t.Fatalf("PUT scope=tags with filter: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if v := db.GetSetting("alert_filter"); v != `["prod"]` {
		t.Errorf("stored alert_filter = %q, want [\"prod\"]", v)
	}
}

// TestSettingsPutRejectsAllowUnauthWhenAuthOff pins the finding-4 guard in
// PUT /api/settings: allow_unauth_update re-allows the in-dashboard
// self-update button on an auth-off install — i.e. it hands any LAN host the
// power to download a binary, overwrite the running one, and restart the
// service. With auth off, requireAdmin/requireAuth stand down, so without the
// guard any LAN host could PUT {"allow_unauth_update":true} and then POST
// /api/update. The toggle is therefore changeable ONLY while an account
// exists (auth on): a 403 when auth is off, a 200 (both directions) when an
// account exists. The stored VALUE is untouched — only the change is gated —
// and a save that does NOT send the field (the general "save alerts" flow) is
// unaffected. Fails pre-fix (200 + the value written while auth is off).
func TestSettingsPutRejectsAllowUnauthWhenAuthOff(t *testing.T) {
	srv, db := fixServerWithDB(t)

	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(body))
		rr := httptest.NewRecorder()
		srv.handleSettingsPut(rr, req)
		return rr
	}

	// Auth OFF (fresh store, no users): the toggle is 403, nothing written.
	if n, _ := db.UserCount(); n != 0 {
		t.Fatalf("precondition: UserCount = %d, want 0 (auth off)", n)
	}
	if rr := put(`{"allow_unauth_update": true}`); rr.Code != http.StatusForbidden {
		t.Fatalf("PUT allow_unauth_update with auth off: %d, want 403: %s", rr.Code, rr.Body.String())
	}
	if v := db.GetSetting("allow_unauth_update"); v != "" {
		t.Errorf("allow_unauth_update = %q after a 403 PUT, want empty (nothing written)", v)
	}

	// Auth OFF, a save that does NOT send the field: unaffected (200).
	if rr := put(`{"realert_min": 10}`); rr.Code != http.StatusOK {
		t.Fatalf("PUT realert_min with auth off (no allow_unauth_update): %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := db.GetSetting("realert_min"); got != "10" {
		t.Errorf("realert_min = %q after a 200 PUT, want 10", got)
	}

	// Auth ON (an account exists): the toggle is accepted, both directions.
	if err := srv.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if n, _ := db.UserCount(); n != 1 {
		t.Fatalf("precondition: UserCount = %d, want 1 (auth on)", n)
	}
	if rr := put(`{"allow_unauth_update": true}`); rr.Code != http.StatusOK {
		t.Fatalf("PUT allow_unauth_update=true with auth on: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if v := db.GetSetting("allow_unauth_update"); v != "1" {
		t.Errorf("allow_unauth_update = %q after auth-on PUT, want 1", v)
	}
	if rr := put(`{"allow_unauth_update": false}`); rr.Code != http.StatusOK {
		t.Fatalf("PUT allow_unauth_update=false with auth on: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if v := db.GetSetting("allow_unauth_update"); v != "0" {
		t.Errorf("allow_unauth_update = %q after auth-on false PUT, want 0", v)
	}
}

// TestSettingsPutAllowUnauthLiveUserCountInTx pins the in-tx user-count
// re-check: the pre-flight guard reads s.auth.Enabled(), a 2s-TTL cache, so
// an out-of-band `pulsemon auth-user remove` of the LAST account (a direct
// DB delete that does not call refreshEnabledNow) stays invisible to it for
// up to 2s. In that stale-true window auth is effectively off and
// requireAuth stands down — without the in-tx count the PUT would persist
// the unauth-update privilege unauthenticated. The count runs under the
// settings write-lock pin, so it is the authoritative gate for the write.
func TestSettingsPutAllowUnauthLiveUserCountInTx(t *testing.T) {
	srv, db := fixServerWithDB(t)

	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(body))
		rr := httptest.NewRecorder()
		srv.handleSettingsPut(rr, req)
		return rr
	}

	// Seed the Enabled() cache as TRUE with a live account.
	if err := srv.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if !srv.auth.Enabled() {
		t.Fatal("precondition: Enabled() = false after AddUser, want true (cache seeded)")
	}

	// Out-of-band removal of the last account (the auth-user remove path:
	// direct DB delete, NO refreshEnabledNow) — the cache stays true for up
	// to enabledTTL. This is the TOCTOU window.
	if _, err := db.Exec(`DELETE FROM users`); err != nil {
		t.Fatalf("delete last user: %v", err)
	}
	if n, _ := db.UserCount(); n != 0 {
		t.Fatalf("precondition: UserCount = %d, want 0", n)
	}
	if !srv.auth.Enabled() {
		t.Fatal("precondition: Enabled() cache must be stale-true here (the TOCTOU window)")
	}

	// The toggle must be refused by the LIVE in-tx count, not the stale
	// cache, and nothing may be written.
	if rr := put(`{"allow_unauth_update": true}`); rr.Code != http.StatusForbidden {
		t.Fatalf("PUT allow_unauth_update with stale-true Enabled() cache: %d, want 403: %s", rr.Code, rr.Body.String())
	}
	if v := db.GetSetting("allow_unauth_update"); v != "" {
		t.Errorf("allow_unauth_update = %q after a 403 PUT, want empty (nothing written)", v)
	}
}

// TestSettingsPutLogUsesEffectiveValuesFromEcho (2026-11-17 external review
// #8) pins the tail of handleSettingsPut: the "settings updated" log line is
// sourced from the response echo (settingsPayload) instead of three
// redundant GetSetting re-reads of the exact keys settingsPayload() just
// read. The observable contract: the log shows the VALIDATED/DEFAULTED
// values the alert hot path will use, not the raw stored strings. Seed a
// degenerate state the write path can never produce (out-of-range
// realert_min=9999, unset alert_scope) out-of-band, then a no-op PUT must
// log scope=all (defaulted) and realert=30m (clamped to default) — the
// old raw-read shape logged "scope= ... realert=9999m".
func TestSettingsPutLogUsesEffectiveValuesFromEcho(t *testing.T) {
	db := newTestDB(t)
	_ = db.SetSetting("realert_min", "9999") // out-of-range; the PUT 400s this, so only an out-of-band edit leaves it
	srv := NewServer(db, NewProbeWorker(db))

	// Capture the standard logger for the duration of this (deliberately
	// non-parallel) test; a contains-assertion tolerates unrelated lines.
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("no-op settings PUT: got %d, want 200: %s", rr.Code, rr.Body.String())
	}
	want := "API: settings updated (scope=all filter=0 realert=30m)"
	if !strings.Contains(logBuf.String(), want) {
		t.Fatalf("log missing the effective-values line %q; got:\n%s", want, logBuf.String())
	}
}
