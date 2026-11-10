package main

import "testing"

// TestValidateDownAfterRetention pins finding #3: a down_after × interval_s
// product beyond the 24h probe-retention window can never accumulate
// down_after consecutive losses (purgeOld keeps only 24h of probes, so the
// longest observable loss run is 24h/interval_s). A 100%-dead sensor with
// such a combination sits in warning forever and never reaches error — and
// warnings are never alerted. The write path must reject it.
func TestValidateDownAfterRetention(t *testing.T) {
	base := func(intervalS, downAfter int) sensorSpec {
		return sensorSpec{
			Name: "rt", Target: "10.0.0.1", Type: "icmp",
			IntervalS: intervalS, TimeoutMS: 1000,
			LossWarn: 25, DownAfter: downAfter, SpikeMult: 5,
		}
	}
	cases := []struct {
		intervalS int
		downAfter int
		wantErr   bool
	}{
		{3600, 30, true},  // 108000 > 86400 — the finding's example
		{3600, 24, false}, // 86400 == 86400 — boundary is inclusive (rule is >)
		{3600, 23, false}, // 82800 < 86400
		{1800, 49, true},  // 88200 > 86400
		{1800, 48, false}, // 86400 == 86400
		{60, 100, false},  // 6000 < 86400 — max down_after at a normal interval
		{5, 100, false},   // 500 < 86400 — fastest interval
		{3600, 1, false},  // 3600 < 86400
	}
	for _, c := range cases {
		s := base(c.intervalS, c.downAfter)
		err := s.validate()
		if (err != nil) != c.wantErr {
			t.Errorf("validate(interval_s=%d, down_after=%d) = %v, wantErr=%v",
				c.intervalS, c.downAfter, err, c.wantErr)
		}
	}
}

// TestClampDownAfterRetention pins the clone path: clamp() can't reject (it
// only adjusts), so it must floor down_after to what fits the 24h retention
// window — retentionSeconds / interval_s — mirroring how clamp already floors
// a timeout that exceeds the interval.
func TestClampDownAfterRetention(t *testing.T) {
	base := func(intervalS, downAfter int) sensorSpec {
		return sensorSpec{
			Name: "rt", Target: "10.0.0.1", Type: "icmp",
			IntervalS: intervalS, TimeoutMS: 1000,
			LossWarn: 25, DownAfter: downAfter, SpikeMult: 5,
		}
	}
	cases := []struct {
		intervalS int
		downAfter int
		want      int // expected down_after after clamp
	}{
		{3600, 30, 24}, // 86400/3600 = 24
		{3600, 24, 24}, // already at the floor
		{3600, 1, 1},   // below the floor — untouched
		{1800, 50, 48}, // 86400/1800 = 48
		{60, 100, 100}, // 86400/60 = 1440 > 100 — untouched
	}
	for _, c := range cases {
		s := base(c.intervalS, c.downAfter)
		s.clamp()
		if s.DownAfter != c.want {
			t.Errorf("clamp(interval_s=%d, down_after=%d).DownAfter = %d, want %d",
				c.intervalS, c.downAfter, s.DownAfter, c.want)
		}
		// A clamped spec must pass validation (the clone path produces a
		// valid sensor, never a silently-warning one).
		if err := s.validate(); err != nil {
			t.Errorf("clamped spec (interval_s=%d) failed validate: %v", c.intervalS, err)
		}
	}
}
