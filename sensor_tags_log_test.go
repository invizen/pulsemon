package main

// Review 2026-10-24 minor batch — SensorTagsFor swallowed its chunk QUERY
// error (the mid-stream error was logged, the query error was not): on
// failure the caller received a map with no entries, so every affected
// sensor kept routing alerts as if it had NO tags, silently. Query failures
// and corrupt rows now log like the rest of the scan sites.

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestSensorTagsForLogsQueryFailure(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.Exec(`DROP TABLE sensor_tags`); err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prev) })

	got := db.SensorTagsFor([]string{"s1", "s2"})
	if len(got) != 0 {
		t.Fatalf("expected empty map on query failure, got %v", got)
	}
	if s := logBuf.String(); !strings.Contains(s, "sensor tag batch query failed") {
		t.Fatalf("query failure was swallowed, log = %q", s)
	}
}
