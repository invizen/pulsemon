package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestParseTSForRealert locks the alert-state timestamp parser. It must accept
// BOTH the new RFC3339Nano writer output (fractional seconds) and the integer-
// second rows that older versions already stored in alert_state.last_ts.
// Re-alert timing keys off this parse (maybeRealert), so a layout mismatch
// would silently reset the re-alert timer on every probe tick for existing
// sensors. Verified against the real stdlib: time.Parse under the RFC3339Nano
// layout accepts a fractional string AND an integer-second string, so one
// layout covers both. This test locks that compatibility so a future layout
// change can't quietly break either side.
func TestParseTSForRealert(t *testing.T) {
	cases := []struct {
		name string
		ts   string
		want time.Time
	}{
		{"nano", "2026-10-04T18:07:27.123456789Z", time.Date(2026, 10, 4, 18, 7, 27, 123456789, time.UTC)},
		{"nano-short", "2026-10-04T18:07:27.9Z", time.Date(2026, 10, 4, 18, 7, 27, 900000000, time.UTC)},
		{"integer-legacy", "2026-10-04T18:07:27Z", time.Date(2026, 10, 4, 18, 7, 27, 0, time.UTC)},
	}
	for _, c := range cases {
		got, err := parseTSForRealert(c.ts)
		if err != nil {
			t.Errorf("%s: parse %q = error %v, want OK", c.name, c.ts, err)
			continue
		}
		if !got.Equal(c.want) {
			t.Errorf("%s: parse %q = %v, want %v", c.name, c.ts, got, c.want)
		}
	}
}

// TestTimestampWritersAreUniform locks the format-standardization change: every
// writer-side timestamp this app produces must be RFC3339Nano UTC, and every
// value the re-alert parser accepts must round-trip through that format. This
// is the guarantee that makes the string-sorted columns (probes.ts, events.ts)
// and the parsed column (alert_state.last_ts) all share one layout, so a
// future ORDER BY on any of them is well-defined.
//
// It checks tsNow() (the single writer helper) produces an RFC3339Nano value
// that (a) has a 'T' separator and 'Z' suffix, (b) parses back to the same
// instant under RFC3339Nano, and (c) matches what setAlertState would store.
func TestTimestampWritersAreUniform(t *testing.T) {
	// tsNow() is the single source for new writer timestamps.
	s := tsNow()
	if !strings.Contains(s, "T") || !strings.HasSuffix(s, "Z") {
		t.Fatalf("tsNow() = %q, want an RFC3339 (T-separated, Z-suffixed) value", s)
	}
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("tsNow() %q does not parse under RFC3339Nano: %v", s, err)
	}
	// Round-trip: formatting the parsed instant must give back an equal value.
	if got := parsed.Format(time.RFC3339Nano); got != s {
		t.Errorf("tsNow() round-trip: %q -> %q, want unchanged", s, got)
	}

	// The re-alert parser must accept tsNow()'s output (the new writer format).
	if _, err := parseTSForRealert(s); err != nil {
		t.Errorf("parseTSForRealert(tsNow()) = %v, want OK (new writer output must be parseable)", err)
	}

	// setAlertState stores via the same format: write a known instant to a real
	// DB and confirm it round-trips through parseTSForRealert.
	db, err := NewDB(filepath.Join(t.TempDir(), "ts.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
		VALUES ('a','a','127.0.0.1',15,1000,25,4,'active','up','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	pw := NewProbeWorker(db)
	fixed := time.Date(2026, 10, 4, 18, 7, 27, 123456789, time.UTC)
	pw.setAlertState("a", "error", fixed)
	var stored string
	if err := db.QueryRow("SELECT last_ts FROM alert_state WHERE sensor_id = 'a'").Scan(&stored); err != nil {
		t.Fatalf("read last_ts: %v", err)
	}
	back, err := parseTSForRealert(stored)
	if err != nil {
		t.Fatalf("parse stored last_ts %q: %v", stored, err)
	}
	if !back.Equal(fixed) {
		t.Errorf("setAlertState stored %q, parsed back to %v, want %v", stored, back, fixed)
	}
}
