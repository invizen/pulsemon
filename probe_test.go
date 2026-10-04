package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// baseProbeTime is the start of the synthetic probe timeline; each probe in
// a test is 1s after the previous one so ORDER BY ts is deterministic.
var baseProbeTime = time.Now().Add(-time.Minute).UTC().Truncate(time.Second)

var probeSeq int

// seedSensor inserts a sensor (id is also its unique name) and its probes,
// oldest to newest. rtt[i] == nil means a lost probe. Returns a
// ProbeWorker whose deriveStatus can be called for that sensor.
func seedSensor(t *testing.T, db *DB, id string, lossWarn, downAfter, spikeMult int, rtt []*float64) *ProbeWorker {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 15, 1000, ?, ?, ?, 'active', 'up', ?)`,
		id, id, lossWarn, downAfter, spikeMult, now); err != nil {
		t.Fatalf("insert sensor %s: %v", id, err)
	}
	for _, v := range rtt {
		probeSeq++
		ts := baseProbeTime.Add(time.Duration(probeSeq) * time.Second).Format(time.RFC3339Nano)
		var val interface{}
		if v != nil {
			val = *v
		}
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, ?, '127.0.0.1')", id, ts, val); err != nil {
			t.Fatalf("insert probe for %s: %v", id, err)
		}
	}
	return &ProbeWorker{
		sensors: make(map[string]*ProbeState),
		loops:   make(map[string]context.CancelFunc),
		db:      db,
	}
}

// f builds a slice of successful probes (newest last) with per-index RTTs.
func f(vals ...float64) []*float64 {
	out := make([]*float64, len(vals))
	for i, v := range vals {
		v := v
		out[i] = &v
	}
	return out
}

// f64 returns a pointer to v.
func f64(v float64) *float64 { return &v }

func TestDeriveStatus(t *testing.T) {
	probeErrCount.Store(0) // no simulated socket errors

	db, err := NewDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	type tc struct {
		id         string
		lossWarn   int
		downAfter  int
		spikeMult  int
		rtt        []*float64 // oldest -> newest
		want       string
	}

	tests := []tc{
		{
			id: "clean", lossWarn: 25, downAfter: 4, spikeMult: 3,
			rtt: f(10, 10, 10, 10, 10, 10, 10, 10, 10, 10), // 0% loss, flat RTT
			want: "up",
		},
		{
			id: "loss", lossWarn: 25, downAfter: 4, spikeMult: 3,
			// 4 of 10 lost = 40% >= 25%; no run of 4 consecutive losses
			rtt: []*float64{
				f64(10), f64(10), nil, f64(10),
				f64(10), nil, f64(10), f64(10),
				nil, nil,
			},
			want: "warning",
		},
		{
			id: "loss-boundary", lossWarn: 25, downAfter: 4, spikeMult: 3,
			// 3 of 12 lost = 25% exactly meets loss_warn (>=)
			rtt: []*float64{
				f64(10), f64(10), f64(10), nil,
				f64(10), f64(10), f64(10), f64(10),
				nil, nil, f64(10), f64(10),
			},
			want: "warning",
		},
		{
			id: "loss-below", lossWarn: 25, downAfter: 4, spikeMult: 3,
			// 2 of 10 lost = 20% < 25%; losses mid-window, newest 2 both OK
			rtt: []*float64{
				f64(10), nil, f64(10), f64(10),
				f64(10), f64(10), f64(10), nil,
				f64(10), f64(10),
			},
			want: "up",
		},
		{
			id: "error", lossWarn: 25, downAfter: 4, spikeMult: 3,
			// 4 consecutive losses from the newest probe
			rtt: []*float64{
				f64(10), f64(10), f64(10), f64(10),
				nil, nil, nil, nil,
			},
			want: "error",
		},
		{
			id: "error-beats-loss", lossWarn: 1, downAfter: 4, spikeMult: 3,
			// loss_warn=1 would flag any loss, but 4 consecutive losses -> error
			rtt: []*float64{
				f64(10), f64(10), f64(10), f64(10),
				nil, nil, nil, nil,
			},
			want: "error",
		},
		{
			id: "spike-no-status", lossWarn: 25, downAfter: 4, spikeMult: 3,
			// newest 40ms vs avg(10x9)=10ms is a 4x spike, but spike no longer
			// changes status (dashboard-only); 0% loss, newest 2 OK -> up
			rtt: f(10, 10, 10, 10, 10, 10, 10, 10, 10, 40),
			want: "up",
		},
		{
			id: "error-after-large", lossWarn: 25, downAfter: 50, spikeMult: 3,
			// 50 consecutive losses with down_after=50: the window read must be
			// max(statusWindow, down_after)=60 rows, not a fixed 60 that would
			// truncate the consecutive run.
			rtt: append(f(10, 10, 10, 10), make([]*float64, 50)...),
			want: "error",
		},
		{
			id: "no-data", lossWarn: 25, downAfter: 4, spikeMult: 3,
			rtt:  nil,
			want: "up",
		},
		{
			id: "single-success", lossWarn: 25, downAfter: 4, spikeMult: 3,
			rtt:  f(15),
			want: "up",
		},
		{
			id: "alternating", lossWarn: 25, downAfter: 4, spikeMult: 3,
			// L U L U ... L U (newest OK): 50% loss >= 25%
			rtt: []*float64{nil, f64(10), nil, f64(10), nil, f64(10), nil, f64(10), nil, f64(10)},
			want: "warning",
		},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			pw := seedSensor(t, db, tt.id, tt.lossWarn, tt.downAfter, tt.spikeMult, tt.rtt)
			c := sensorConfig{id: tt.id, lossWarn: tt.lossWarn, downAfter: tt.downAfter, spikeMult: tt.spikeMult}
			if got := pw.deriveStatus(c); got != tt.want {
				t.Errorf("deriveStatus(%s): got %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

// TestAlertPolicy locks which transitions send an alert: warning (loss) is
// dashboard-only, error (and recovery) alert. This is the noise-reduction
// policy — up<->warning flapping must never fire an alert.
func TestAlertPolicy(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// alertable() is the unit test: warning never alerts, everything else does.
	for status, want := range map[string]bool{
		"warning": false,
		"error":   true,
		"up":      true, // recovery
	} {
		if got := alertable(status); got != want {
			t.Errorf("alertable(%q) = %v, want %v", status, got, want)
		}
	}

	// shouldAlertNow: with default routing (all sensors, maintenance off),
	// only the status gate distinguishes warning from the rest.
	pw := &ProbeWorker{
		sensors: make(map[string]*ProbeState),
		loops:   make(map[string]context.CancelFunc),
		db:      db,
	}
	c := sensorConfig{id: "policy-sensor"}
	if pw.shouldAlertNow(c, "warning") {
		t.Error("shouldAlertNow(warning) = true, want false (loss is dashboard-only)")
	}
	for _, st := range []string{"error", "up"} {
		if !pw.shouldAlertNow(c, st) {
			t.Errorf("shouldAlertNow(%q) = false, want true", st)
		}
	}

	// Maintenance mode silences even error alerts.
	if err := db.SetSetting("maintenance_mode", "1"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if pw.shouldAlertNow(c, "error") {
		t.Error("shouldAlertNow(error) = true while maintenance ON, want false")
	}
}
