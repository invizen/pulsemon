package main

import (
	"path/filepath"
	"testing"
)

// TestLossWarnIsARealGate pins the fix for the dead loss_warn setting:
// pre-fix deriveStatus ended with an unconditional `return "warning"`
// fallback, so ANY single loss in the 8-probe status window warned
// (1/8 = 12.5% < the 25% default) and flapped back to up on the next
// good probe — the per-sensor loss_warn threshold was dead code and
// prod boxes warned on sensors with ~5% hourly loss. Post-fix,
// loss_warn is the SOLE warning gate: below it the sensor reads up
// (the LOSS metric and the red sparkline bar still show the blip);
// at/above it, warning.
//
// seedSensor inserts the rtt slice oldest→newest; deriveStatus reads
// DESC, so the LAST element is the newest probe.
func TestLossWarnIsARealGate(t *testing.T) {
	probeErrCount.Store(0) // isolate from the broken-socket gate
	db, err := NewDB(filepath.Join(t.TempDir(), "losswarn.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	mk := func(id string, rtt []*float64) string {
		pw := seedSensor(t, db, id, 25, 2, 3, rtt)
		c := sensorConfig{id: id, lossWarn: 25, downAfter: 2}
		c.lastErrCount = probeErrCount.Load()
		return pw.deriveStatus(c, "up")
	}

	// Single loss as the NEWEST probe: 1/8 = 12.5% < 25 → up.
	// (Pre-fix: warning — the exact prod false-positive this fixes.)
	if got := mk("lw-single-newest", []*float64{f64(10), f64(10), f64(10), f64(10), f64(10), f64(10), f64(10), nil}); got != "up" {
		t.Errorf("single newest loss below threshold = %q, want up (loss_warn is a real gate)", got)
	}

	// Single loss in FLAP shape (newest success, 2nd-newest loss):
	// 12.5% < 25 → up. (Pre-fix: warning.)
	if got := mk("lw-flap", []*float64{f64(10), nil, f64(10), f64(10), f64(10), f64(10), f64(10), f64(10)}); got != "up" {
		t.Errorf("flap below threshold = %q, want up", got)
	}

	// 2 losses in 8 = exactly 25% >= 25 → warning (threshold is
	// inclusive). Newest is a loss so the up rule can't short-circuit.
	if got := mk("lw-at-threshold", []*float64{f64(10), nil, f64(10), f64(10), f64(10), f64(10), f64(10), nil}); got != "warning" {
		t.Errorf("2/8 losses at threshold = %q, want warning", got)
	}

	// 3 losses in 8 = 37.5% > 25 → warning.
	if got := mk("lw-over-threshold", []*float64{nil, f64(10), nil, f64(10), f64(10), f64(10), f64(10), nil}); got != "warning" {
		t.Errorf("3/8 losses over threshold = %q, want warning", got)
	}

	// Fast-recovery shortcut preserved: lastStatus=error + a newest
	// success reads up on the FIRST good probe, even after 4 consecutive
	// losses (the up rule precedes the error/loss checks).
	{
		pw := seedSensor(t, db, "lw-recovery", 25, 2, 3,
			[]*float64{nil, nil, nil, nil, f64(10)})
		c := sensorConfig{id: "lw-recovery", lossWarn: 25, downAfter: 2}
		c.lastErrCount = probeErrCount.Load()
		if got := pw.deriveStatus(c, "error"); got != "up" {
			t.Errorf("recovery from error on first good probe = %q, want up", got)
		}
	}

	// The per-sensor knob works in BOTH directions: with loss_warn=10 a
	// single loss (12.5%) is a warning — proving the setting is honored,
	// not just a floor that's never enforced.
	{
		pw := seedSensor(t, db, "lw-low-threshold", 10, 2, 3,
			[]*float64{f64(10), f64(10), f64(10), f64(10), f64(10), f64(10), f64(10), nil})
		c := sensorConfig{id: "lw-low-threshold", lossWarn: 10, downAfter: 2}
		c.lastErrCount = probeErrCount.Load()
		if got := pw.deriveStatus(c, "up"); got != "warning" {
			t.Errorf("single loss with loss_warn=10 = %q, want warning (per-sensor threshold honored)", got)
		}
	}
}
