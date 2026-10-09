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
		id        string
		lossWarn  int
		downAfter int
		spikeMult int
		rtt       []*float64 // oldest -> newest
		last      string     // sensor's current status before this derivation
		want      string
	}

	tests := []tc{
		{
			id: "clean", lossWarn: 25, downAfter: 4, spikeMult: 3,
			rtt:  f(10, 10, 10, 10, 10, 10, 10, 10, 10, 10), // 0% loss, flat RTT
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
			// 2 of 8 lost = 25% exactly meets loss_warn (>=). The newest
			// probe is a loss, so not up; consec 1 < 4, so not error.
			rtt: []*float64{
				f64(10), f64(10), f64(10), nil,
				f64(10), f64(10), f64(10), nil,
			},
			want: "warning",
		},
		{
			id: "up-at-boundary", lossWarn: 25, downAfter: 4, spikeMult: 3,
			// 12 probes, 3 lost = 25% overall (and 2/8 = 25% in the status
			// window — exactly the threshold). But the newest 2 probes both
			// succeeded, and up is checked FIRST, so it reads up. This is
			// the intended up-first consequence: recovery beats the loss
			// boundary (previously this case read warning).
			rtt: []*float64{
				f64(10), f64(10), f64(10), nil,
				f64(10), f64(10), f64(10), f64(10),
				nil, nil, f64(10), f64(10),
			},
			want: "up",
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
			rtt:  f(10, 10, 10, 10, 10, 10, 10, 10, 10, 40),
			want: "up",
		},
		{
			id: "error-after-large", lossWarn: 25, downAfter: 50, spikeMult: 3,
			// 4 successes then 50 consecutive losses (newest = loss): the
			// window read must be max(statusWindow, down_after)=50 rows, not a
			// fixed 8 — a fixed 8 would see consec=8 < 50 and (correctly, for
			// a fixed-8 world) warn instead of error. With the full run,
			// consec=50 >= down_after -> error.
			rtt:  append(f(10, 10, 10, 10), make([]*float64, 50)...),
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
			// L U L U ... then U: the last 8 hold 3 losses = 37.5% window
			// loss, newest probe succeeded but the previous one was a loss
			// and the sensor is NOT recovering from error — a flapping
			// sensor reads warning, not up (one good probe amid ongoing
			// loss is not "recovered").
			rtt:  []*float64{nil, f64(10), nil, f64(10), nil, f64(10), nil, f64(10), nil, f64(10)},
			last: "warning",
			want: "warning",
		},
		{
			id: "recovery-after-outage", lossWarn: 25, downAfter: 4, spikeMult: 3,
			// An hour of total loss, then 2 successes: 75% window loss, but
			// the newest 2 both succeeded, so the sensor reads up
			// IMMEDIATELY — no waiting for the window to wash out.
			rtt:  append(make([]*float64, 60), f64(10), f64(10)),
			last: "warning",
			want: "up",
		},
		{
			id: "recovery-one-success-from-warning", lossWarn: 25, downAfter: 4, spikeMult: 3,
			// Same outage but only 1 success so far: newest probe succeeded,
			// 2nd-newest lost, sensor was in WARNING. Not up (fast recovery
			// only applies when the sensor was in ERROR — a single success
			// after packet LOSS is not proof of recovery), not error
			// (consec 1 < 4), window 87.5% >= 25% -> warning.
			rtt:  append(make([]*float64, 60), f64(10)),
			last: "warning",
			want: "warning",
		},
		{
			id: "fast-recovery-one-success", lossWarn: 25, downAfter: 4, spikeMult: 3,
			// A confirmed-down sensor (last status ERROR) answers ONE probe:
			// that single success flips it back to up immediately — the
			// error->up = 1 successful ping rule.
			rtt:  append(make([]*float64, 60), f64(10)),
			last: "error",
			want: "up",
		},
		{
			id: "still-down", lossWarn: 25, downAfter: 4, spikeMult: 3,
			// Confirmed-down sensor, newest probe lost: still error (consec
			// losses keep climbing, so the fast-retry loop keeps polling it
			// at the 30s cadence until a probe succeeds).
			rtt:  append(make([]*float64, 60), nil, nil),
			last: "error",
			want: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			pw := seedSensor(t, db, tt.id, tt.lossWarn, tt.downAfter, tt.spikeMult, tt.rtt)
			c := sensorConfig{id: tt.id, lossWarn: tt.lossWarn, downAfter: tt.downAfter, spikeMult: tt.spikeMult}
			if got := pw.deriveStatus(c, tt.last); got != tt.want {
				t.Errorf("deriveStatus(%s, last=%q): got %q, want %q", tt.id, tt.last, got, tt.want)
			}
		})
	}
}

// TestAlertPolicy locks which transitions send an alert: warning is
// dashboard-only in BOTH directions (up<->warning flapping never alerts);
// everything involving error alerts — into error, error->warning (partial
// recovery), and error->up (recovery). This is the noise-reduction policy.
func TestAlertPolicy(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// alertableTransition() is the unit test: the full transition matrix.
	// Same-state pairs are false (re-alerts have their own schedule via
	// alertGates, not this gate).
	for _, tc := range []struct {
		old, new string
		want     bool
	}{
		{"up", "warning", false},   // into warning: loss is dashboard noise
		{"warning", "up", false},   // out of warning: not a real recovery
		{"up", "error", true},      // into error
		{"error", "up", true},      // full recovery
		{"error", "warning", true}, // partial recovery
		{"warning", "error", true}, // into error (worse)
		{"up", "up", false},
		{"warning", "warning", false},
		{"error", "error", false},
	} {
		if got := alertableTransition(tc.old, tc.new); got != tc.want {
			t.Errorf("alertableTransition(%q, %q) = %v, want %v", tc.old, tc.new, got, tc.want)
		}
	}

	// shouldAlertNow: with default routing (all sensors, maintenance off),
	// only the transition gate distinguishes alertable from silent pairs.
	pw := &ProbeWorker{
		sensors: make(map[string]*ProbeState),
		loops:   make(map[string]context.CancelFunc),
		db:      db,
	}
	c := sensorConfig{id: "policy-sensor"}
	if pw.shouldAlertNow(c, "up", "warning") {
		t.Error("shouldAlertNow(up, warning) = true, want false (loss is dashboard-only)")
	}
	if pw.shouldAlertNow(c, "warning", "up") {
		t.Error("shouldAlertNow(warning, up) = true, want false (warning-only recovery is dashboard-only)")
	}
	for _, p := range [][2]string{{"up", "error"}, {"error", "up"}, {"error", "warning"}, {"warning", "error"}} {
		if !pw.shouldAlertNow(c, p[0], p[1]) {
			t.Errorf("shouldAlertNow(%q, %q) = false, want true", p[0], p[1])
		}
	}

	// Maintenance mode silences even error alerts.
	if err := db.SetSetting("maintenance_mode", "1"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if pw.shouldAlertNow(c, "up", "error") {
		t.Error("shouldAlertNow(up, error) = true while maintenance ON, want false")
	}
}

// TestValidTarget locks the target-validation contract:
//   - in-range IPv4 accepted; OUT-OF-RANGE octets (999.999.999.999) rejected
//     up front — before the fix they passed the \d{1,3} regex and then failed
//     DNS every probe tick
//   - dotted hostnames accepted (router.local, sub.example.com)
//   - bare single-label names REJECTED on purpose (typo-class input for an
//     ICMP tool; must fail at save time, not hang every tick)
//   - IPv6 rejected (not a supported probe target — ICMPv4 only)
//   - junk (empty, SQL-ish, scheme-prefixed, whitespace) rejected
func TestValidTarget(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		// In-range IPv4.
		{"10.99.99.1", true},
		{"10.0.0.1", true},
		{"8.8.8.8", true},
		{"127.0.0.1", true},
		{"0.0.0.0", true},
		// Out-of-range octets — the pre-fix gap: \d{1,3} accepted 999.
		{"999.999.999.999", false},
		{"256.1.1.1", false},
		{"1.1.1.256", false},
		{"1.2.3", false},     // too few octets
		{"1.2.3.4.5", false}, // too many
		{"1.2.3.-4", false},  // negative
		{"1.2.3.4 ", false},  // trailing whitespace
		{" 1.2.3.4", false},  // leading whitespace
		{"1.2.3.4x", false},  // trailing junk
		// Dotted hostnames (one or more labels, alphabetic TLD).
		{"router.local", true},
		{"nas.home.lab", true},
		{"sub.example.com", true},
		{"a-b.example.co", true},
		{"9router.local", true}, // digits in a label are fine
		// Bare single-label hostnames: deliberately rejected.
		{"router", false},
		{"NAS", false},
		{"home", false},
		{"9", false}, // bare label, even numeric
		// IPv6 is not a supported probe target.
		{"::1", false},
		{"fe80::1", false},
		{"2001:db8::1", false},
		// Junk.
		{"", false},
		{" ", false},
		{"1.1.1.1; DROP TABLE", false},
		{"http://1.1.1.1", false},
		{"example.com/", false},
		{"-router.local", false}, // label can't start with '-'
		{"router..local", false}, // empty label
		{".router.local", false}, // leading dot
	}
	for _, tc := range cases {
		if got := validTarget(tc.target); got != tc.want {
			t.Errorf("validTarget(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}
