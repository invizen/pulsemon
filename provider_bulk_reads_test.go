package main

// Review 2026-11-13 finding #6: provider settings reads via GetSetting
// (swallow-to-"") vs GetSettingErr (fail-loud) were inconsistent across
// resolveDestinationsFromDB (Enabled/HasURL half) and providerStatuses
// (the entire providers array embedded in an otherwise fail-loud
// settingsPayload). A transient SQLite failure silently read as
// "provider unset": the snapshot load installed a HALF-READ snapshot
// (provider dropped, alerts for it stopped until the next settings save —
// there is no periodic reload), and GET /api/settings answered 200 with
// enabled:false/has_url:false rows the PUT echo can write back.
//
// The fix routes every provider-key read through the *Get predicates on
// ONE bulk settings-table read (getAllSettings). These tests pin both
// halves fail-loud.

import (
	"testing"
)

// TestFix_SnapshotLoadFailsLoudOnProviderReads: with a healthy settings
// table the snapshot carries the google_chat dest (legacy: URL present,
// no explicit flag → enabled). DROPping the settings table makes EVERY
// settings read fail; the reload must abort and KEEP the last-good
// snapshot. Pre-fix, Enabled/HasURL read through the swallowing
// GetSetting: every provider looked unset, the load SUCCEEDED with zero
// dests, and the empty snapshot was installed — the exact half-read
// state reloadAlertSettings's comment forbids.
func TestFix_SnapshotLoadFailsLoudOnProviderReads(t *testing.T) {
	pw, db, _, cleanup := newStormTestWorker(t)
	defer cleanup()
	if dests, ok := pw.resolveDestinations(); !ok || len(dests) != 1 || dests[0].p.Kind != "google_chat" {
		t.Fatalf("initial snapshot: ok=%v dests=%v, want exactly the google_chat dest", ok, dests)
	}
	if _, err := db.Exec(`DROP TABLE settings`); err != nil {
		t.Fatal(err)
	}
	pw.reloadAlertSettings()
	if dests, _ := pw.resolveDestinations(); len(dests) != 1 {
		t.Fatalf("reload with a dead settings table installed a half-read snapshot (dests=%v): a swallowed provider read must abort the load and keep the last-good snapshot", dests)
	}
}

// TestFix_ProviderStatusesFailLoud: providerStatuses is built from ONE
// bulk read and every key is fail-loud. Healthy: the telegram row must
// report enabled/has_url and its chat_id extra (bulk-read parity with
// the old per-key reads — including SMTP's display URL living in
// smtp_host). Dead settings table: providerStatuses must return an error,
// so settingsPayload (and with it GET and PUT /api/settings) answers 500
// — pre-fix it returned a full statuses array with silent
// enabled:false/has_url:false states and nil error, inside an otherwise
// fail-loud payload.
func TestFix_ProviderStatusesFailLoud(t *testing.T) {
	pw, db, _, cleanup := newStormTestWorker(t)
	defer cleanup()
	_ = db.SetSetting("telegram_enabled", "1")
	_ = db.SetSetting("telegram_url", "https://api.telegram.org/botTOK/m")
	_ = db.SetSetting("telegram_chat_id", "42")
	st, err := pw.providerStatuses()
	if err != nil {
		t.Fatalf("healthy providerStatuses: %v", err)
	}
	var tg, gc bool
	for _, p := range st {
		switch p.Kind {
		case "telegram":
			tg = true
			if !p.Enabled || !p.HasURL || p.Extra["chat_id"] != "42" {
				t.Fatalf("telegram status after bulk read = %+v, want enabled+has_url+chat_id=42 (bulk-read parity)", p)
			}
		case "google_chat":
			gc = true
			if !p.Enabled || !p.HasURL {
				t.Fatalf("google_chat status = %+v, want enabled+has_url (legacy URL default)", p)
			}
		}
	}
	if !tg || !gc {
		t.Fatalf("statuses missing providers: %+v", st)
	}
	if _, err := db.Exec(`DROP TABLE settings`); err != nil {
		t.Fatal(err)
	}
	st2, err := pw.providerStatuses()
	if err == nil {
		t.Fatalf("providerStatuses with a dead settings table returned %d rows and nil error: swallowed reads answered 200 with silent false states", len(st2))
	}
	if st2 != nil {
		t.Fatalf("providerStatuses returned rows alongside error: %v / %v", st2, err)
	}
}
