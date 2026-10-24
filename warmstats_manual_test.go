package main

// Review 2026-10-24 (Major): warmStats selected only (sensor_id, ts, rtt_ms)
// and built probeEntry WITHOUT the manual flag, so every Pulse-Now row warmed
// from the DB entered the cache as a SCHEDULED probe. Consequences after each
// restart: a lost manual pulse as the newest entry could feed deriveStatus's
// consecutive-loss tests (false error transition — the exact failure the
// manual=0 exclusion was added to prevent), and manual rows re-contaminated
// total24/lost24 for up to 24h. The fix selects manual in both UNION branches;
// these tests pin the flag AND the counter exclusion on the warm path.

import (
	"path/filepath"
	"testing"
	"time"
)

func TestWarmStatsCarriesManualFlag(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "warm-manual.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	const id = "warmman"
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 30, 1000, 25, 4, 3, 'active', 'up', ?)`,
		id, id, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}
	// 4 scheduled probes (3 up, 1 lost).
	for i := 0; i < 4; i++ {
		ts := now.Add(-time.Duration(90-i*30) * time.Second).Format(time.RFC3339)
		var val interface{} = 10.0
		if i == 2 {
			val = nil
		}
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, ?, '127.0.0.1')", id, ts, val); err != nil {
			t.Fatalf("insert scheduled probe %d: %v", i, err)
		}
	}
	// One MANUAL lost probe, the newest row overall.
	manTs := now.Add(-5 * time.Second)
	if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip, manual) VALUES (?, ?, NULL, '127.0.0.1', 1)",
		id, manTs.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert manual probe: %v", err)
	}

	pw := &ProbeWorker{db: db, statsCache: make(map[string]*probeSeries)}
	pw.warmStats()
	series, ok := pw.statsCache[id]
	if !ok {
		t.Fatalf("warmStats did not load sensor %q", id)
	}
	snap := series.snapshot()
	manUnix := manTs.UTC().Unix()
	var found bool
	for _, e := range snap {
		if e.ts == manUnix {
			found = true
			if !e.manual {
				t.Fatalf("warmed Pulse-Now row entered the series as a scheduled probe (manual=false) — warmStats must select the manual column")
			}
		}
	}
	if !found {
		t.Fatalf("manual row not in warmed series at all (ts %d)", manUnix)
	}
	// Counters: only the 4 scheduled rows count; the manual loss is excluded.
	if series.total24 != 4 {
		t.Errorf("total24 = %d, want 4 (manual row must not enter the 24h counters)", series.total24)
	}
	if series.lost24 != 1 {
		t.Errorf("lost24 = %d, want 1 (the manual loss must not be counted)", series.lost24)
	}
}
