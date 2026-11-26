package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"pulsemon/internal/store"
)

// TestFinalRecoveryAfterPartialRecoveryAlerts is the MINOR-20 pin: an
// outage that heals THROUGH warning (error -> warning "partial recovery",
// then warning -> up) must end with a final "recovered" alert. Pre-fix,
// alertableTransition("warning","up") is false, so the notification
// channel's last word stayed "partial recovery (warning)" on a sensor
// that was fully up. The decision reads the durable events log, so the
// distinction survives a process restart between the two transitions.
// History: docs/DECISIONS.md → final-recovery-after-partial-recovery.
func TestFinalRecoveryAfterPartialRecoveryAlerts(t *testing.T) {
	withPlainTransport(t, func() {
		db := newTestDB(t)
		fcSensor(t, db, "fr1", "fr1", "active")
		pw := NewProbeWorker(db)
		var hits atomic.Int32
		relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer relay.Close()
		pw.alertCfg.Store(&alertSettings{
			maintenance: false,
			scope:       "all",
			filter:      map[string]bool{},
			realertMin:  30,
			dests:       []dest{{p: providerList[0], url: relay.URL}},
		})
		// The sensor sits in "warning" entered from "error": the durable
		// previous event is the alerted partial recovery.
		if _, err := db.Exec(`UPDATE sensors SET status='warning' WHERE id='fr1'`); err != nil {
			t.Fatalf("set warning: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO events (sensor_id, ts, from_status, to_status, note)
			VALUES ('fr1', ?, 'error', 'warning', 'error -> warning')`,
			store.FormatTS(time.Now().UTC().Add(-time.Minute))); err != nil {
			t.Fatalf("seed previous event: %v", err)
		}
		pw.sensors["fr1"] = &ProbeState{id: "fr1"}
		old := probeTarget
		defer func() { probeTarget = old }()
		probeTarget = func(ctx context.Context, typ, target string, d time.Duration) probeOutcome {
			return probeOutcome{rttMs: 1}
		}
		c := sensorConfig{id: "fr1", sk: sensorSK(t, db, "fr1"), name: "fr1", target: "10.0.0.1", probeType: "icmp", intervalS: 60, timeoutMS: 100, lossWarn: 25, downAfter: 2}
		pw.doProbe(context.Background(), c)
		pw.DrainAlerts(5 * time.Second)
		if got := hits.Load(); got != 1 {
			t.Fatalf("relay hits = %d, want 1 (final recovery after an alerted partial recovery must alert)", got)
		}
		var st string
		if err := db.QueryRow(`SELECT status FROM sensors WHERE id='fr1'`).Scan(&st); err != nil {
			t.Fatalf("read status: %v", err)
		}
		if st != "up" {
			t.Fatalf("status = %q, want up", st)
		}
	})
}

// TestWarningFlapRecoveryStaysSilent pins the other half of MINOR-20:
// up -> warning -> up (loss flapping, no error ever) must NOT alert on
// the recovery — the previous event was up -> warning, and warning-only
// movement is dashboard-only in both directions. The pure gate matrix is
// unchanged (alertableTransition("warning","up") stays false); the fix is
// the extra doProbe clause, so this test fails only if the flap case
// starts alerting (a matrix change or a wrong previous-event read).
func TestWarningFlapRecoveryStaysSilent(t *testing.T) {
	withPlainTransport(t, func() {
		db := newTestDB(t)
		fcSensor(t, db, "fr2", "fr2", "active")
		pw := NewProbeWorker(db)
		var hits atomic.Int32
		relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer relay.Close()
		pw.alertCfg.Store(&alertSettings{
			maintenance: false,
			scope:       "all",
			filter:      map[string]bool{},
			realertMin:  30,
			dests:       []dest{{p: providerList[0], url: relay.URL}},
		})
		// Same warning baseline, but the previous event was up -> warning
		// (flapping, never an alerted outage).
		if _, err := db.Exec(`UPDATE sensors SET status='warning' WHERE id='fr2'`); err != nil {
			t.Fatalf("set warning: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO events (sensor_id, ts, from_status, to_status, note)
			VALUES ('fr2', ?, 'up', 'warning', 'up -> warning')`,
			store.FormatTS(time.Now().UTC().Add(-time.Minute))); err != nil {
			t.Fatalf("seed previous event: %v", err)
		}
		if alertableTransition("warning", "up") {
			t.Fatal("precondition: alertableTransition(warning, up) must stay false (the gate matrix is unchanged)")
		}
		pw.sensors["fr2"] = &ProbeState{id: "fr2"}
		old := probeTarget
		defer func() { probeTarget = old }()
		probeTarget = func(ctx context.Context, typ, target string, d time.Duration) probeOutcome {
			return probeOutcome{rttMs: 1}
		}
		c := sensorConfig{id: "fr2", sk: sensorSK(t, db, "fr2"), name: "fr2", target: "10.0.0.1", probeType: "icmp", intervalS: 60, timeoutMS: 100, lossWarn: 25, downAfter: 2}
		pw.doProbe(context.Background(), c)
		pw.DrainAlerts(5 * time.Second)
		if got := hits.Load(); got != 0 {
			t.Fatalf("relay hits = %d, want 0 (up -> warning -> up flapping must stay silent)", got)
		}
	})
}
