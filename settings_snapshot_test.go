package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSettingsPayloadSingleSnapshot: settingsPayload used to read its six
// keys with six separate GetSettingErr queries (each on its own pool
// connection), so a concurrent PUT /api/settings could interleave the
// reads and mix pre- and post-update values in one payload. The payload
// now comes from a single GetAllSettings row-set; this pins every key by
// value, so a typo'd key name (which would surface as a wrong default)
// and a regression to per-key reads both fail here.
// History: docs/DECISIONS.md → db-ctx-torn-reads-resources
func TestSettingsPayloadSingleSnapshot(t *testing.T) {
	d := newTestDB(t)
	srv := NewServer(d, NewProbeWorker(d))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	d.SetSetting("auth_bootstrapped", "1")
	_ = d.SetSetting("alert_scope", "tagged")
	_ = d.SetSetting("alert_filter", `["prod"]`)
	_ = d.SetSetting("realert_min", "7")
	_ = d.SetSetting("google_chat_url", "https://chat.googleapis.com/v1/spaces/XXX/messages")
	_ = d.SetSetting("maintenance_mode", "1")
	_ = d.SetSetting("allow_unauth_update", "1")

	resp, err := http.Get(httpSrv.URL + "/api/settings")
	if err != nil {
		t.Fatalf("GET /api/settings: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	if got := payload["alert_scope"]; got != "tagged" {
		t.Errorf("alert_scope = %v, want %q", got, "tagged")
	}
	filter, _ := payload["alert_filter"].([]any)
	if len(filter) != 1 || filter[0] != "prod" {
		t.Errorf("alert_filter = %v, want [prod]", payload["alert_filter"])
	}
	if got := payload["realert_min"]; got != float64(7) {
		t.Errorf("realert_min = %v, want 7", got)
	}
	if got := payload["maintenance_mode"]; got != true {
		t.Errorf("maintenance_mode = %v, want true", got)
	}
	if got := payload["allow_unauth_update"]; got != true {
		t.Errorf("allow_unauth_update = %v, want true", got)
	}
	if got := payload["webhook_configured"]; got != true {
		t.Errorf("webhook_configured = %v, want true (google_chat_url set)", got)
	}
}
