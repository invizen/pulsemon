package main

import (
	"math"
)

// Status derivation: deriveStatus turns a sensor's recent probe window
// into the up/warning/error badge (see the deriveStatus doc for the contract).

// statusWindow is the probe count used for loss% detection. It must also be
// >= down_after (the API allows down_after down to 1; the window read takes
// the max) so the consecutive-loss test always has enough history. At the
// default 15s interval, 8 probes is ~2 min of history — short enough that a
// recovered sensor's status washes out in minutes, not an hour.
const statusWindow = 8

// Status is derived from the sensor's most recent probes with fixed
// precedence:
//
//	up        — (a) fast recovery: a sensor back from ERROR reads up on its
//	            FIRST good probe (it was already confirmed down, one reply
//	            is sufficient proof of return); (b) a brand-new sensor with
//	            a single recorded success; (c) steady state: the newest two
//	            probes succeeded AND the window loss% (last `statusWindow`
//	            probes) is BELOW loss_warn; (d) a single recent loss (newest
//	            probe lost) amid sub-threshold window stats — a blip, shown
//	            by the LOSS metric and the red sparkline bar.
//	error     — `down_after` consecutive losses from the newest probe
//	warning   — window loss% (last `statusWindow` probes) >= loss_warn
//	            (and not error)
//
// loss_warn is the SOLE warning gate, and the up rule honors it: the
// steady-state branch checks the window loss% before returning up, so a
// flapping sensor whose window loss has crossed loss_warn reads warning —
// not up — on every tick (including 2-straight-good ticks) until the
// window loss falls back under the threshold.
//
// The window read is max(statusWindow, down_after) rows so that a sensor
// configured with down_after > statusWindow still has enough history for
// the consecutive-loss test; the extra rows feed ONLY that test — loss% is
// always computed over the newest statusWindow probes, the same window the
// inspector displays. A probe-level ICMP error (broken socket) forces
// warning so a dead probe path never reads as "up".
//
// loss_warn is API-enforced to 1-100 (create and PATCH both reject 0), so
// the threshold is always a real value. A hand-zeroed row (DB surgery)
// reads warning by construction — it never reads up.
func (pw *ProbeWorker) deriveStatus(c sensorConfig, lastStatus string) string {
	// Broken probe path (the ICMP engine is unusable): this probe never
	// landed, so we cannot know the real state — flag warning, never up. An
	// already-confirmed ERROR stays ERROR: a dead probe path must not fake a
	// "partial recovery" (error -> warning is an alertable transition).
	if c.probeBroken {
		if lastStatus == "error" {
			return "error"
		}
		return "warning"
	}

	// Fetch enough history for the loss% window AND the consecutive-loss
	// test, newest first.
	limit := statusWindow
	if c.downAfter > limit {
		limit = c.downAfter
	}
	// Warm sensors answer from the in-memory series (no SQL); a cold or short
	// series (fresh process, new sensor, test) falls back to the DB.
	recent, ok := pw.recentFromCache(c.id, limit)
	if !ok {
		var err error
		recent, err = pw.recentFromDB(c.id, limit)
		if err != nil {
			// Can't read the probe history, so we can't know the real state.
			// Retain the last known status (lastStatus) rather than manufacturing a
			// transition: a monitoring tool must not fake a recovery it can't confirm,
			// AND it must not fabricate a spurious one. (Returning "warning" here was
			// a BUG for a sensor in "error": error -> warning is an alertable
			// "partial recovery", so a transient SQLite hiccup on a downed sensor fired
			// a false recovery webhook and corrupted the DB status.) A brand-new
			// sensor (lastStatus == "") has no known state, so it reads "warning"
			// (unknown) - never "up". Self-clears next tick once the DB is healthy.
			if lastStatus != "" {
				return lastStatus
			}
			return "warning"
		}
	}

	if len(recent) == 0 {
		return "up" // no data yet
	}

	// Window loss% over the STATUS WINDOW (newest statusWindow probes) —
	// the same 8-probe window the inspector displays, so the badge and the
	// inspector number always agree. The read above fetches
	// max(statusWindow, down_after) rows; the extra rows feed only the
	// consecutive-loss test below, never this math.
	sw := recent
	if len(sw) > statusWindow {
		sw = sw[:statusWindow]
	}
	totalLost := 0
	for _, r := range sw {
		if isLost(r) {
			totalLost++
		}
	}
	lossPct := float64(totalLost) / float64(len(sw)) * 100

	// UP (highest precedence): the newest probe succeeded, and the sensor
	// is either recovering from ERROR (fast recovery — one good reply is
	// enough once it was confirmed down), a brand-new sensor with a single
	// recorded success, or steady state (the previous probe also succeeded)
	// with the window loss BELOW loss_warn. The steady-state branch is
	// gated on the threshold so the up rule can't short-circuit the sole
	// warning gate: a flapping sensor whose window loss has crossed
	// loss_warn reads warning, not up, even on a 2-straight-good tick.
	upRule := false
	if !isLost(recent[0]) {
		switch {
		case lastStatus == "error" || len(recent) == 1:
			upRule = true
		case !isLost(recent[1]) && lossPct < float64(c.lossWarn):
			upRule = true
		}
	}
	if upRule {
		return "up"
	}

	// ERROR: down_after consecutive losses from the newest probe. (The
	// newest probe is a loss here, so this and the up check are mutually
	// exclusive.)
	consec := 0
	for _, r := range recent {
		if isLost(r) {
			consec++
		} else {
			break
		}
	}
	if consec >= c.downAfter {
		return "error"
	}

	// WARNING: loss% over the status window meets loss_warn. This is the
	// SOLE warning gate: loss_warn is a real threshold, not a decoration.
	// A sensor whose window loss is below it reads "up" even when the
	// newest probe is a single loss — the LOSS metric and the red
	// sparkline bar still show the blip. (A zeroed loss_warn — impossible
	// via the API — meets this test for any loss, so a corrupted row
	// degrades loudly rather than reading up while dropping packets.)
	if lossPct >= float64(c.lossWarn) {
		return "warning"
	}
	// Below the threshold: the window is statistically healthy, so the
	// sensor reads up (a single recent loss among sub-threshold stats
	// is a blip, not degradation).
	return "up"
}

// recentFromCache returns up to limit most-recent RTTs (index 0 = newest,
// NaN = lost) from the in-memory series. ok is false when the series holds
// fewer than limit entries, in which case the DB may know more history.
func (pw *ProbeWorker) recentFromCache(id string, limit int) ([]float32, bool) {
	pw.statsMu.RLock()
	defer pw.statsMu.RUnlock()
	s, ok := pw.statsCache[id]
	if !ok || s.len() < limit {
		return nil, false
	}
	out := make([]float32, 0, limit)
	for i := len(s.data) - 1; i >= s.start && len(out) < limit; i-- {
		// Manual "Pulse Now" rows are excluded from status derivation
		// (probes.manual): they stay in the series for the 60-probe
		// inspector window, but never count toward loss % or the
		// consecutive-loss test (see the PingNow doc; the loss/uptime aggregates skip them too).
		if s.data[i].manual {
			continue
		}
		out = append(out, s.data[i].rtt)
	}
	// A FULL window of scheduled probes is required. Manual pulses can
	// dilute the tail (a 2s cooldown allows many), and a partial window
	// would change the loss math — so fall back to the DB, which filters
	// the same way.
	if len(out) < limit {
		return nil, false
	}
	return out, true
}

// recentFromDB is the durable equivalent of recentFromCache. manual = 0
// excludes "Pulse Now" rows from status derivation (see PingNow).
func (pw *ProbeWorker) recentFromDB(id string, limit int) ([]float32, error) {
	rows, err := pw.db.Query("SELECT rtt_ms FROM probes WHERE sensor_id = ? AND manual = 0 ORDER BY ts DESC LIMIT ?", id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() // top-level: closed on every return path (the pool is capped; a leak would hang)
	var recent []float32
	for rows.Next() {
		var rtt *float64
		if err := rows.Scan(&rtt); err != nil {
			return nil, err
		}
		v := float32(math.NaN())
		if rtt != nil {
			v = float32(*rtt)
		}
		recent = append(recent, v)
	}
	return recent, rows.Err()
}
