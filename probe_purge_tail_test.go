package main

import (
	"context"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// TestPurgeOldKeepsLast60Tail pins finding #6: 24h retention must EXEMPT each
// sensor's newest seriesTailProbes probe rows. The live raw tier keeps
// max(1h, last 60), so an unconditional 24h purge deletes history the running
// process still serves — and after a restart warmStats can never rebuild it
// (the rows are gone), shrinking a slow sensor's 60-probe inspector window
// from 60 to ~24. The exemption keeps the invariant DB ⊇ live series.
// events need no exemption (transitions are sparse; nothing mirrors a tail).
func TestPurgeOldKeepsLast60Tail(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "slow", "slow", "active")
	fcSensor(t, db, "fast", "fast", "active")

	// slow: 73 probes at 1h spacing (hoursAgo 0..72). 24h retention keeps
	// 0..23; the tail exemption must additionally keep 24..59.
	var t59 time.Time
	for h := 0; h <= 72; h++ {
		ts := time.Now().UTC().Add(-time.Duration(h) * time.Hour)
		if h == 59 {
			t59 = ts
		}
		fcProbe(t, db, "slow", ts, 1.0)
	}
	// fast: 10 probes inside 1h + 1 at 25h. The sensor has 11 probes total,
	// ALL inside its 60-row tail — the live series keeps every probe of a
	// sensor with <= 60 raw, so the invariant (DB ⊇ live series) keeps all 11,
	// including the 25h row. (Rows beyond the tail DO purge — see 'slow'.)
	for k := 0; k < 10; k++ {
		fcProbe(t, db, "fast", time.Now().UTC().Add(-time.Duration(k)*time.Minute), 1.0)
	}
	fcProbe(t, db, "fast", time.Now().UTC().Add(-25*time.Hour), 1.0)
	// an old event row must be purged (no events exemption)
	if _, err := db.Exec(`INSERT INTO events (sensor_id, ts, from_status, to_status, note) VALUES ('slow', ?, 'up', 'warning', 'old')`,
		store.FormatTS(time.Now().UTC().Add(-25*time.Hour))); err != nil {
		t.Fatal(err)
	}

	pw := NewProbeWorker(db)
	pw.purgeOld(context.Background())

	var nSlow int
	var oldest string
	if err := db.QueryRow(`SELECT COUNT(*), MIN(ts) FROM probes WHERE sensor_id='slow'`).Scan(&nSlow, &oldest); err != nil {
		t.Fatal(err)
	}
	if nSlow != seriesTailProbes {
		t.Fatalf("slow sensor kept %d probes, want exactly the last %d (24h window + tail exemption)", nSlow, seriesTailProbes)
	}
	// survivors are the 60 NEWEST: exact seeded ts of hoursAgo 59.
	if want := store.FormatTS(t59); oldest != want {
		t.Fatalf("oldest surviving slow probe = %s, want the 60th newest (%s); the exemption must keep the newest tail, not older rows", oldest, want)
	}
	var nFast int
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes WHERE sensor_id='fast'`).Scan(&nFast); err != nil {
		t.Fatal(err)
	}
	if nFast != 11 {
		t.Fatalf("fast sensor kept %d probes, want 11 (11 total <= tail 60, so the exemption keeps all; per-sensor tail, not per-table)", nFast)
	}
	var nEv int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE sensor_id='slow'`).Scan(&nEv); err != nil {
		t.Fatal(err)
	}
	if nEv != 0 {
		t.Fatalf("%d old events survived the purge; events take no tail exemption", nEv)
	}

	// Idempotent: a second sweep changes nothing.
	pw.purgeOld(context.Background())
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes WHERE sensor_id='slow'`).Scan(&nSlow); err != nil {
		t.Fatal(err)
	}
	if nSlow != seriesTailProbes {
		t.Fatalf("second purge changed the exempted tail: %d, want %d", nSlow, seriesTailProbes)
	}
}

// TestWarmStatsRebuildsTailAfterPurge pins the restart half of finding #6:
// after the startup purgeOld, warmStats phase 2 must rebuild the exempted
// tail so a 1h-interval sensor shows the SAME 60-probe inspector window after
// a restart as before it. Old behavior: purge deleted the tail, warmStats
// loaded only the 24h rows (~24), and the inspector shrank across every
// deploy.
func TestWarmStatsRebuildsTailAfterPurge(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "slow", "slow", "active")
	for h := 0; h <= 72; h++ {
		fcProbe(t, db, "slow", time.Now().UTC().Add(-time.Duration(h)*time.Hour), 1.0)
	}
	pw := NewProbeWorker(db)
	pw.purgeOld(context.Background())

	pw.warmStats(context.Background())
	s := pw.statsCache["slow"]
	if s == nil {
		t.Fatal("warmStats left no series for the slow sensor")
	}
	if got := s.len(); got != seriesTailProbes {
		t.Fatalf("post-restart series holds %d probes, want %d — phase 2 cannot rebuild a tail the purge deleted", got, seriesTailProbes)
	}
}
