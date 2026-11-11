package main

// Review 2026-10-24 minor batch — SensorTagsFor swallowed its chunk QUERY
// error (the mid-stream error was logged, the query error was not): on
// failure the caller received a map with no entries, so every affected
// sensor kept routing alerts as if it had NO tags, silently. Query failures
// and corrupt rows now log like the rest of the scan sites.
//
// Review 2026-11-11 #5 moved the failure policy to the callers: the store
// now RETURNS the query error (no log inside), and each caller decides —
// syncSensors (background) keeps the 2026-10-24 tradeoff: log with the same
// message and reconcile the rest. This test drives that seam end-to-end:
// drop sensor_tags, run a sync, assert the sync pass logs the untagged-
// routing warning (the failure is visible, not swallowed).

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"pulsemon/internal/store"
)

func TestSensorTagsForLogsQueryFailure(t *testing.T) {
	db := newTestDB(t)
	// A sensor must exist for syncSensors to build a non-empty id list —
	// with zero configs the batched tag query (and its failure log) is
	// never reached.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('logtag-s1', 'logtag-s1', '127.0.0.1', 'icmp', 60, 1000, 25, 2, 3, 'active', 'up', ?)`, store.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE sensor_tags`); err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prev) })

	// Store-level: the error is now RETURNED, not swallowed.
	if m, err := db.SensorTagsFor(context.Background(), []string{"s1", "s2"}); err == nil || len(m) != 0 {
		t.Fatalf("SensorTagsFor on dropped table: map=%v err=%v, want empty map + non-nil error", m, err)
	}

	// Caller-level: the background sync keeps reconciling and logs.
	pw := NewProbeWorker(db)
	pw.syncSensors(context.Background())
	if s := logBuf.String(); !strings.Contains(s, "sensor tag batch query failed") {
		t.Fatalf("query failure was swallowed, log = %q", s)
	}
}
