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
	t.Cleanup(func() { db.Close() })

	mk := func(id string, rtt []*float64) string {
		pw := seedSensor(t, db, id, 25, 2, 3, rtt)
		c := sensorConfig{id: id, lossWarn: 25, downAfter: 2}
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
		if got := pw.deriveStatus(c, "up"); got != "warning" {
			t.Errorf("single loss with loss_warn=10 = %q, want warning (per-sensor threshold honored)", got)
		}
	}

	// warning->up transition (lastStatus="warning"): a sub-threshold flap
	// (newest success, 2nd-newest loss, 1/8 = 12.5%) now reads UP — the
	// pre-fix code held it in warning via the unconditional fallback, and
	// every case above runs lastStatus="up", so this path was uncovered.
	{
		pw := seedSensor(t, db, "lw-warn-flap-up", 25, 2, 3,
			[]*float64{f64(10), nil, f64(10), f64(10), f64(10), f64(10), f64(10), f64(10)})
		c := sensorConfig{id: "lw-warn-flap-up", lossWarn: 25, downAfter: 2}
		if got := pw.deriveStatus(c, "warning"); got != "up" {
			t.Errorf("sub-threshold flap from warning = %q, want up (blip below loss_warn recovers)", got)
		}
	}

	// At-threshold flap from warning stays warning: 2/8 = 25% >= 25 with
	// newest success + 2nd-newest loss — neither the up rule nor the
	// sub-threshold fallthrough may rescue it.
	{
		pw := seedSensor(t, db, "lw-warn-flap-stay", 25, 2, 3,
			[]*float64{nil, f64(10), nil, f64(10), f64(10), f64(10), f64(10), f64(10)})
		c := sensorConfig{id: "lw-warn-flap-stay", lossWarn: 25, downAfter: 2}
		if got := pw.deriveStatus(c, "warning"); got != "warning" {
			t.Errorf("at-threshold flap from warning = %q, want warning (loss gate holds)", got)
		}
	}

	// Steady state (newest two ok) with 3/8 = 37.5% loss reads warning: the
	// up rule checks the window loss before returning up, so a flapping
	// sensor above the threshold can't ride a 2-straight-good tick back to
	// up. (Pre-v0.3.15 this shape read up — the short-circuit this fixes.)
	{
		pw := seedSensor(t, db, "lw-steady-over", 25, 2, 3,
			[]*float64{nil, f64(10), nil, f64(10), nil, f64(10), f64(10), f64(10)})
		c := sensorConfig{id: "lw-steady-over", lossWarn: 25, downAfter: 2}
		if got := pw.deriveStatus(c, "up"); got != "warning" {
			t.Errorf("steady state at 37.5%% loss = %q, want warning (up rule honors loss_warn)", got)
		}
	}

	// down_after > statusWindow: loss% is over the newest 8 probes, not the
	// 20-row read. 4 losses in the newest 8 (50%) warn even though 4/20 =
	// 20% < 25 — the pre-fix denominator diluted the threshold.
	{
		rtt := make([]*float64, 0, 20)
		for i := 0; i < 12; i++ {
			rtt = append(rtt, f64(10))
		}
		rtt = append(rtt, f64(10), nil, f64(10), nil, f64(10), nil, f64(10), nil)
		pw := seedSensor(t, db, "lw-diluted", 25, 20, 3, rtt)
		c := sensorConfig{id: "lw-diluted", lossWarn: 25, downAfter: 20}
		if got := pw.deriveStatus(c, "up"); got != "warning" {
			t.Errorf("down_after=20, 4 losses in newest 8 = %q, want warning (loss%% over 8, not 20)", got)
		}
	}

	// down_after > statusWindow, at-threshold: 2 losses in the newest 8
	// (25%) with down_after=12 reads warning — 2/12 = 16.7% would have read
	// up with the diluted denominator. The 2/8 = 25% is the same number the
	// inspector displays, so badge and inspector agree.
	{
		rtt := make([]*float64, 0, 12)
		for i := 0; i < 4; i++ {
			rtt = append(rtt, f64(10))
		}
		rtt = append(rtt, f64(10), f64(10), f64(10), f64(10), nil, f64(10), nil, f64(10))
		pw := seedSensor(t, db, "lw-window8", 25, 12, 3, rtt)
		c := sensorConfig{id: "lw-window8", lossWarn: 25, downAfter: 12}
		if got := pw.deriveStatus(c, "up"); got != "warning" {
			t.Errorf("down_after=12, 2 losses in newest 8 = %q, want warning (2/8=25%%, not 2/12)", got)
		}
	}
}

// TestLossWarnZeroedRowNeverReadsUp pins the defensive contract after the
// unreachable loss_warn == 0 branch was deleted: loss_warn is API-enforced
// to 1-100, but a hand-zeroed row (DB surgery) must NEVER read up — the up
// rule's threshold comparison (lossPct < 0) can never pass, and any window
// loss meets the (always-true) warning test. The first case fails on the
// pre-deletion code: its `c.lossWarn == 0 ||` up-rule arm read up on a
// 2-straight-good tick.
func TestLossWarnZeroedRowNeverReadsUp(t *testing.T) {
	probeErrCount.Store(0) // isolate from the broken-socket gate
	db, err := NewDB(filepath.Join(t.TempDir(), "losswarn0.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Steady state (newest two ok) with 2/8 = 25% window loss.
	pw := seedSensor(t, db, "lw0-steady", 0, 2, 3,
		[]*float64{nil, f64(10), nil, f64(10), f64(10), f64(10), f64(10), f64(10)})
	c := sensorConfig{id: "lw0-steady", lossWarn: 0, downAfter: 2}
	if got := pw.deriveStatus(c, "up"); got != "warning" {
		t.Errorf("zeroed row, steady state = %q, want warning (zeroed row never reads up)", got)
	}

	// Single loss as the newest probe: any loss meets the threshold.
	pw = seedSensor(t, db, "lw0-single", 0, 2, 3,
		[]*float64{f64(10), f64(10), f64(10), f64(10), f64(10), f64(10), f64(10), nil})
	c = sensorConfig{id: "lw0-single", lossWarn: 0, downAfter: 2}
	if got := pw.deriveStatus(c, "up"); got != "warning" {
		t.Errorf("zeroed row, single newest loss = %q, want warning", got)
	}

	// down_after consecutive losses still beats the zeroed threshold.
	pw = seedSensor(t, db, "lw0-down", 0, 2, 3,
		[]*float64{f64(10), f64(10), nil, nil})
	c = sensorConfig{id: "lw0-down", lossWarn: 0, downAfter: 2}
	if got := pw.deriveStatus(c, "up"); got != "error" {
		t.Errorf("zeroed row, 2 consecutive losses = %q, want error", got)
	}
}
