package main

import (
	"context"
	"math"
	"path/filepath"
	"pulsemon/internal/store"
	"testing"
	"time"
)

// TestPulseNowNeverAffectsStatus pins the 2026-10-20 external-review fix:
// a "Pulse Now" row is RECORDED (sparkline honesty) but tagged manual=1
// and excluded from status derivation, so a manual pulse can never count
// toward loss % or the consecutive-loss/down_after test. Before the tag,
// the manual row was indistinguishable from a scheduled loss, so ONE lost
// manual pulse + one lost scheduled probe tripped a down_after=2 sensor
// to "error" (an alert) — while the docs promised the opposite.
func TestPulseNowNeverAffectsStatus(t *testing.T) {
	db, err := store.NewStore(filepath.Join(t.TempDir(), "pulse-status.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	const id = "p1"
	// down_after=2 is the finding's scenario: two consecutive losses
	// (as the status logic sees them) mean "error" + alert.
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 'icmp', 60, 2000, 25, 2, 3, 'active', 'up', ?)`,
		id, id, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}

	// Stub the transport: every pulse is LOST.
	origTarget := probeTarget
	probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
		return probeOutcome{lost: true, ip: "127.0.0.1"}
	}
	defer func() { probeTarget = origTarget }()

	pw := NewProbeWorker(db)

	// (1) The reported sequence: a lost manual pulse, then one lost
	// SCHEDULED probe.
	o, err := pw.PingNow(context.Background(), id)
	if err != nil || !o.lost {
		t.Fatalf("PingNow = (lost=%v, err=%v), want a lost pulse", o.lost, err)
	}
	var manual int
	if err := db.QueryRow(`SELECT manual FROM probes WHERE sensor_id = ?`, id).Scan(&manual); err != nil || manual != 1 {
		t.Fatalf("pulse row manual = %d (err=%v), want 1 — the row must be tagged so derivation can exclude it", manual, err)
	}
	base := time.Now().UTC().Add(2 * time.Second)
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms, manual) VALUES (?, ?, NULL, 0)`,
		id, store.FormatTS(base)); err != nil {
		t.Fatalf("insert scheduled loss: %v", err)
	}

	cfg := sensorConfig{id: id, name: id, target: "127.0.0.1", probeType: "icmp",
		intervalS: 60, timeoutMS: 2000, lossWarn: 25, downAfter: 2}

	// (2) The manual loss must NOT join the consecutive-loss test: one
	// scheduled loss is below down_after=2, so no "error". (100% loss in a
	// 1-probe window reads "warning" via loss_warn — dashboard-only, never
	// an alert. The assertion is "not error", which is the alert trigger.)
	if st := pw.deriveStatus(cfg, "up"); st == "error" {
		t.Fatalf("deriveStatus = %q after 1 lost manual pulse + 1 lost scheduled probe — the manual pulse must not count toward down_after (would fire an alert)", st)
	}

	// (3) Control: two SCHEDULED losses still trip it — the consecutive-
	// loss logic itself is intact.
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms, manual) VALUES (?, ?, NULL, 0)`,
		id, store.FormatTS(base.Add(time.Second))); err != nil {
		t.Fatalf("insert second scheduled loss: %v", err)
	}
	if st := pw.deriveStatus(cfg, "up"); st != "error" {
		t.Fatalf("deriveStatus = %q after 2 consecutive scheduled losses, want error (consecutive-loss logic regression)", st)
	}

	// (4) History honesty: the manual row is STILL in the table (sparkline
	// / graph / inspector read it unfiltered) — 3 rows total.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes WHERE sensor_id = ?`, id).Scan(&n); err != nil || n != 3 {
		t.Fatalf("probe history rows = %d (err=%v), want 3 — manual rows stay in history", n, err)
	}

	// (5) recentFromDB returns only scheduled rows.
	recent, err := pw.recentFromDB(id, 8)
	if err != nil {
		t.Fatalf("recentFromDB: %v", err)
	}
	if len(recent) != 2 {
		t.Fatalf("recentFromDB = %d rows, want 2 (manual row must be filtered)", len(recent))
	}

	// (6) recentFromCache skips manual entries and NEVER returns a partial
	// window (a diluted tail falls back to the DB instead).
	pw2 := NewProbeWorker(db)
	rtt := float32(5)
	// "c1": 8 scheduled UP + a NEWER manual LOST → the window is the 8
	// scheduled rows (all non-nil), the manual loss excluded.
	for i := 0; i < 8; i++ {
		pw2.recordProbe("c1", probeEntry{ts: int64(1000 + i), rtt: rtt})
	}
	pw2.recordProbe("c1", probeEntry{ts: 1008, rtt: float32(math.NaN()), manual: true}) // lost → rtt NaN
	c1, ok := pw2.recentFromCache("c1", 8)
	if !ok || len(c1) != 8 {
		t.Fatalf("recentFromCache(c1) = (%d rows, ok=%v), want 8 rows — the manual tail must be skipped, not count", len(c1), ok)
	}
	for i, r := range c1 {
		if isLost(r) {
			t.Fatalf("recentFromCache(c1)[%d] = lost — the manual LOST leaked into the status window", i)
		}
	}
	// "c2": 1 manual LOST + 1 scheduled LOST, limit 2 → only ONE scheduled
	// row exists, so the cache must refuse (DB fallback), not compute on a
	// partial window.
	pw2.recordProbe("c2", probeEntry{ts: 2000, rtt: rtt})
	pw2.recordProbe("c2", probeEntry{ts: 2001, rtt: float32(math.NaN()), manual: true})
	if _, ok := pw2.recentFromCache("c2", 2); ok {
		t.Fatal("recentFromCache(c2) = ok with only 1 scheduled entry — a partial window must fall back to the DB")
	}
}
