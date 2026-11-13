package main

// Review 2026-11-13 finding #7: the settings PUT's pre-tx validation reads
// (effScope/alert_filter dead-filter guard, per-provider storedProviderExtra
// snapshot, maintAlreadyOn) used the error-swallowing GetSetting. A
// transient SQLite failure silently MISCOMPUTED the guard inputs:
//   - stored alert_scope read as "" → effScope defaulted to "all" → the
//     dead-alert-filter guard skipped → a scope=tags fleet could be saved
//     with alert_filter=[] (silent stop of ALL alerting, the exact
//     persistent state the guard exists to refuse),
//   - stored maintenance_mode read as "off" on a re-enable PUT → the
//     handler took the off→on branch → a FRESH snapshot replaced the
//     entry-time restore set (sensors paused at entry lose their restore
//     entry — the documented "paused forever" hazard),
//   - provider stored extras read as {} → the effective-state credentials
//     validation degraded (the in-tx SMTP guard remains the backstop).
// Fix: ONE fail-loud bulk pre-flight read (getAllSettings seam) feeds all
// pre-checks, so a read failure answers 500 before any write and every
// pre-check observes a single commit of the settings table.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pulsemon/internal/store"
)

// failSettingsRead swaps the bulk settings seam to a transient failure for
// the duration of fn (the same injection style as the reload tests).
func failSettingsRead(t *testing.T, fn func()) {
	t.Helper()
	orig := getAllSettings
	getAllSettings = func(db *store.Store) (map[string]string, error) {
		return nil, errors.New("simulated transient DB failure")
	}
	defer func() { getAllSettings = orig }()
	fn()
}

func putSettings(t *testing.T, srv *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(body))
	rr := httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	return rr
}

func seedActiveSensor(t *testing.T, db *store.Store, name, id string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?,?,'10.0.0.1','icmp',60,1000,25,2,5,'active','up',?)`, id, name, store.Now())
	if err != nil {
		t.Fatal(err)
	}
}

func TestFix_SettingsPutPreTxReadsFailLoud(t *testing.T) {
	srv, db := fixServerWithDB(t)

	t.Run("dead-filter-guard-not-bypassed", func(t *testing.T) {
		// Stored routing state: scope=tags with a real tag filter.
		if err := db.SetSetting("alert_scope", "tags"); err != nil {
			t.Fatal(err)
		}
		if err := db.SetSetting("alert_filter", `["core"]`); err != nil {
			t.Fatal(err)
		}
		// Control (healthy reads): the guard must fire its 400 and leave
		// the stored filter untouched — pre-flight behavior preserved.
		if rr := putSettings(t, srv, `{"alert_filter": []}`); rr.Code != http.StatusBadRequest {
			t.Fatalf("healthy PUT with empty filter over scope=tags: %d, want 400: %s", rr.Code, rr.Body.String())
		}
		if got := db.GetSetting("alert_filter"); got != `["core"]` {
			t.Fatalf("stored alert_filter = %q after the 400, want untouched", got)
		}
		// Transient failure on the pre-flight read: the PUT must abort 500
		// with the store untouched. Pre-fix the stored scope read as "",
		// effScope defaulted to "all", the guard skipped, and the save
		// PERSISTED scope=tags + filter=[] — the dead-alert state.
		failSettingsRead(t, func() {
			if rr := putSettings(t, srv, `{"alert_filter": []}`); rr.Code != http.StatusInternalServerError {
				t.Fatalf("PUT with failing pre-flight settings read: %d, want 500: %s", rr.Code, rr.Body.String())
			}
		})
		if got := db.GetSetting("alert_filter"); got != `["core"]` {
			t.Fatalf("stored alert_filter = %q after the failed pre-flight read: guard bypassed on a miscomputed scope", got)
		}
	})

	t.Run("maintenance-restore-set-preserved", func(t *testing.T) {
		// Enter maintenance with two sensors: both paused, both in the
		// entry-time restore set.
		a, b := store.NewID(), store.NewID()
		seedActiveSensor(t, db, "ma-a", a)
		seedActiveSensor(t, db, "ma-b", b)
		if rr := putSettings(t, srv, `{"maintenance_mode": true}`); rr.Code != http.StatusOK {
			t.Fatalf("entering maintenance: %d: %s", rr.Code, rr.Body.String())
		}
		snap0 := db.GetSetting("maintenance_active_ids")
		if !strings.Contains(snap0, a) || !strings.Contains(snap0, b) {
			t.Fatalf("entry snapshot = %s, want both sensors", snap0)
		}
		// Operator resumes ONE sensor during maintenance (DB-level: the
		// re-enable pre-check reads the sensors table).
		if _, err := db.Exec(`UPDATE sensors SET state='active' WHERE id=?`, a); err != nil {
			t.Fatal(err)
		}
		// Control: a mode=true save with healthy reads is an idempotent
		// re-enable — the ORIGINAL snapshot is preserved (documented
		// contract), not re-snapshotted.
		if rr := putSettings(t, srv, `{"maintenance_mode": true}`); rr.Code != http.StatusOK {
			t.Fatalf("idempotent re-enable: %d: %s", rr.Code, rr.Body.String())
		}
		if got := db.GetSetting("maintenance_active_ids"); got != snap0 {
			t.Fatalf("entry snapshot replaced on healthy re-enable: %s, want %s", got, snap0)
		}
		// Transient failure on the pre-flight read: pre-fix, stored mode
		// read as "off", the handler took the off→on branch and the fresh
		// snapshot (currently-active = only the resumed sensor) silently
		// replaced the restore set — the sensor still paused at entry
		// would be left paused forever at resume.
		failSettingsRead(t, func() {
			if rr := putSettings(t, srv, `{"maintenance_mode": true}`); rr.Code != http.StatusInternalServerError {
				t.Fatalf("re-enable with failing pre-flight read: %d, want 500: %s", rr.Code, rr.Body.String())
			}
		})
		if got := db.GetSetting("maintenance_active_ids"); got != snap0 {
			t.Fatalf("entry snapshot = %s after the failed pre-flight read, want %s: a miscomputed maintAlreadyOn re-snapshotted the restore set", got, snap0)
		}
	})

	t.Run("provider-preflight-fails-loud", func(t *testing.T) {
		// Stored SMTP credentials; a partial PUT flipping tls_mode to none
		// must be judged against them.
		if err := db.SetSetting("smtp_username", "u"); err != nil {
			t.Fatal(err)
		}
		if err := db.SetSetting("smtp_password", "secret"); err != nil {
			t.Fatal(err)
		}
		if err := db.SetSetting("smtp_tls_mode", "tls"); err != nil {
			t.Fatal(err)
		}
		// Control: healthy pre-flight judges the effective state → 400.
		if rr := putSettings(t, srv, `{"providers":[{"kind":"smtp","extra":{"tls_mode":"none"}}]}`); rr.Code != http.StatusBadRequest {
			t.Fatalf("healthy tls_mode=none over stored creds: %d, want 400: %s", rr.Code, rr.Body.String())
		}
		// Transient failure: the PUT must fail loud at pre-flight (500),
		// not answer the 400 of a degraded effective state. Pre-fix, the
		// swallowed snapshot read "no stored credentials", pre-flight
		// passed, and only the in-tx guard stopped the write (400).
		failSettingsRead(t, func() {
			if rr := putSettings(t, srv, `{"providers":[{"kind":"smtp","extra":{"tls_mode":"none"}}]}`); rr.Code != http.StatusInternalServerError {
				t.Fatalf("preflight with failing settings read: %d, want 500: %s", rr.Code, rr.Body.String())
			}
		})
		if got := db.GetSetting("smtp_tls_mode"); got != "tls" {
			t.Fatalf("stored smtp_tls_mode = %q after the failed pre-flight, want untouched", got)
		}
	})
}

// TestFix_StandaloneApplyProviderUpdateFailLoud pins the standalone twin:
// a stored-extras read failure aborts the whole apply (no partial write),
// and the healthy path still merges (mask semantics preserved).
func TestFix_StandaloneApplyProviderUpdateFailLoud(t *testing.T) {
	srv, db := fixServerWithDB(t)
	if err := db.SetSetting("smtp_username", "u"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting("smtp_password", "s"); err != nil {
		t.Fatal(err)
	}
	orig := getAllSettings
	getAllSettings = func(db *store.Store) (map[string]string, error) {
		return nil, errors.New("simulated transient DB failure")
	}
	defer func() { getAllSettings = orig }()
	if err := srv.applyProviderUpdate("smtp", strPtr("10.0.0.25"), boolPtr(true), map[string]string{"port": "587"}); err == nil {
		t.Fatal("standalone applyProviderUpdate with a failing stored-extras read returned nil: the write proceeded on a degraded effective state")
	}
	if got := db.GetSetting("smtp_port"); got != "" {
		t.Fatalf("smtp_port = %q after the failed apply, want untouched (abort precedes the tx)", got)
	}
}
