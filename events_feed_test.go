package main

import (
	"strings"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// TestEventsFeedSortUsesTSGlobalIndex pins the /api/events feed plan: the
// cross-sensor ORDER BY e.ts DESC LIMIT n must be served by the single-
// column idx_events_ts (a backward index scan) — the composite
// (sensor_id, ts) index cannot serve a cross-sensor sort, and without the
// global index the plan degrades to a full table scan + TEMP B-TREE sort
// on every dashboard poll. TSLayout is fixed-precision
// (2006-01-02T15:04:05.000000000Z, UTC), so TEXT order == chronological
// order for this column.
func TestEventsFeedSortUsesTSGlobalIndex(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "s1", "s1", "active")
	fcSensor(t, db, "s2", "s2", "active")
	// Enough rows that the full-sort plan is the obvious fallback.
	for i := 0; i < 500; i++ {
		sensor := "s1"
		if i%2 == 1 {
			sensor = "s2"
		}
		ts := time.Now().UTC().Add(-time.Duration(i) * time.Second)
		if _, err := db.Exec(`INSERT INTO events (sensor_id, ts, from_status, to_status) VALUES (?, ?, 'up', 'error')`,
			sensor, store.FormatTS(ts)); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Query(`EXPLAIN QUERY PLAN SELECT e.id, e.sensor_id, COALESCE(s.name, e.sensor_id), e.ts, e.from_status, e.to_status, e.note
		FROM events e LEFT JOIN sensors s ON s.id = e.sensor_id
		ORDER BY e.ts DESC LIMIT 500`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan += detail + "\n"
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "idx_events_ts") {
		t.Fatalf("feed plan does not use idx_events_ts (full-scan regression):\n%s", plan)
	}
	if strings.Contains(plan, "TEMP B-TREE") {
		t.Fatalf("feed plan sorts via a temp B-tree (index missing?):\n%s", plan)
	}
}
