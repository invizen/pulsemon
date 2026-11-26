package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"math/rand"
	"pulsemon/internal/store"
	"time"
)

// finalRecoveryFromWarning reports whether a warning -> up transition is
// the tail of an outage: the warning was entered from error (an alerted
// partial recovery), so this tick sends the final "recovered" alert that
// the silent warning -> up gate (alertableTransition) would otherwise
// swallow — the chat's last word would stay "partial recovery" on a
// sensor that is fully up. up -> warning -> up flapping stays silent: its
// previous event was up -> warning. The check reads the durable events
// log (the current warning -> up row is already committed by the caller,
// so the row before it is the previous transition), which keeps the
// distinction across a process restart between the two transitions.
// History: docs/DECISIONS.md → final-recovery-after-partial-recovery.
func (pw *ProbeWorker) finalRecoveryFromWarning(id, oldStatus, newStatus string) bool {
	if oldStatus != "warning" || newStatus != "up" {
		return false
	}
	var from, to string
	err := pw.db.QueryRow(`SELECT from_status, to_status FROM events
		WHERE sensor_id = ? ORDER BY ts DESC LIMIT 1 OFFSET 1`, id).Scan(&from, &to)
	if err != nil {
		return false // no prior event (fresh sensor, 24h-purged history): no evidence of an alerted outage
	}
	return from == "error" && to == "warning"
}

// alertMemEntry is the in-memory copy of one alert_state row (see the
// ProbeWorker.alertMem field comment).
type alertMemEntry struct {
	status string
	ts     time.Time
}

// alertStateSelect reads a sensor's durable alert_state row. Seam: tests
// count lookups to pin the in-memory cache in front of it.
var alertStateSelect = func(db *store.Store, id string) (string, string, error) {
	var status, ts string
	err := db.QueryRow("SELECT status, last_ts FROM alert_state WHERE sensor_id = ?", id).Scan(&status, &ts)
	return status, ts, err
}

// maybeRealert re-notifies while a sensor stays in the same non-up state,
// at most once per re-alert interval (default 30 min). The state read goes
// through the in-memory alert-state copy first: a steady non-up sensor hits
// no SELECT at all, and the DB row remains the durable copy (re-read on
// miss: fresh process, deleted/evicted id). A valid re-read STAMPS the
// in-memory copy, so the miss happens at most once per sensor per process
// — without that stamp, the early-return paths below (alert-once-only,
// interval not elapsed) never write, and a cold cache would re-query
// SQLite on every tick for the whole re-alert interval.
func (pw *ProbeWorker) maybeRealert(ctx context.Context, c sensorConfig, status string, rttMs float64) {
	now := time.Now().UTC()
	var lastStatus, lastTs string
	pw.alertMemMu.Lock()
	mem, inMem := pw.alertMem[c.id]
	pw.alertMemMu.Unlock()
	if inMem {
		lastStatus, lastTs = mem.status, store.FormatTS(mem.ts)
	} else {
		ls, lt, err := alertStateSelect(pw.db, c.id)
		if err != nil {
			// Only a genuinely MISSING row (sql.ErrNoRows) seeds: there is
			// no durable state for this sensor, and stamping "now" is the
			// correct first write. Any other error is transient (BUSY,
			// I/O, deadline) — seeding would reset the re-alert clock and
			// suppress an imminent re-alert, so return without touching
			// state; the next tick retries the read.
			if errors.Is(err, sql.ErrNoRows) {
				pw.setAlertState(ctx, c.id, status, now)
			}
			return
		}
		// Stamp the in-memory copy so steady ticks hit no SELECT (see the
		// function doc). Unparseable last_ts is not stamped: the parse
		// failure below seeds a fresh state, which stamps on success.
		if t, err := parseTSForRealert(lt); err == nil {
			pw.alertMemMu.Lock()
			if pw.alertMem == nil {
				pw.alertMem = make(map[string]alertMemEntry)
			}
			pw.alertMem[c.id] = alertMemEntry{status: ls, ts: t}
			pw.alertMemMu.Unlock()
		}
		lastStatus, lastTs = ls, lt
	}
	if lastStatus != status {
		pw.setAlertState(ctx, c.id, status, now)
		return
	}
	if pw.realertMin() == 0 {
		// 0 = "alert once only": no periodic re-alerts while the sensor
		// stays in the same non-up state. (Without this guard the
		// interval check below degenerates to "elapsed < 0", i.e. a
		// re-alert fired on EVERY probe tick.) State transitions and
		// recoveries still alert via doProbe.
		return
	}
	t, err := parseTSForRealert(lastTs)
	if err != nil {
		pw.setAlertState(ctx, c.id, status, now)
		return
	}
	if now.Sub(t) < time.Duration(pw.realertMin())*time.Minute {
		return
	}
	pw.setAlertState(ctx, c.id, status, now)
	// A sustained error re-alerts on its own schedule (error -> error is
	// not a transition); only the maintenance + routing gates apply.
	if pw.alertGates(c) {
		pw.launchAlert(func() {
			if !pw.sendRealert(c.id, c.name, c.target, status, rttMs) {
				pw.scheduleAlertRetry(c.id, status) // all providers failed: try again soon, not in 30 min
			}
		})
	}
}

// setAlertState upserts a sensor's alert state on the capped probe-write
// handle (ProbeExecContext): it is on the probe hot path (doProbe,
// maybeRealert), and a stalled writer must park the sensor loop for at
// most store.ProbeWriteTimeout, not the main pool's 15s busy_timeout — the
// same capping rationale as the probe INSERT.
//
// The INSERT is guarded by SELECTing the sensor id: for a sensor deleted
// concurrently, the SELECT yields no row and nothing is written, so alert
// state can never be resurrected for a deleted sensor (the guard is
// explicit and self-contained; the alert_state FK is also enforced —
// schema ON DELETE CASCADE + DSN foreign_keys(1), see store.NewStore). The
// write error is NOT swallowed: a failed upsert is logged and the in-
// memory copy is deliberately NOT stamped, so the durable row stays
// authoritative and the next tick's maybeRealert re-reads it (cache miss),
// sees the status mismatch, and retries — a transient DB failure
// self-heals; a sustained one leaves a log trail instead of silently
// resetting re-alert timing on the next restart.
//
// The in-memory stamp is gated on RowsAffected > 0: a guard that matched
// no sensor row (concurrent delete) writes nothing, and stamping would
// leave a ghost alertMem entry. For a live sensor the SELECT yields
// exactly one row (identical to a plain upsert), and the statement is
// atomic, so there is no delete/upsert TOCTOU.
// History: docs/DECISIONS.md → sensor-delete-alert-state.
func (pw *ProbeWorker) setAlertState(ctx context.Context, id, status string, ts time.Time) {
	res, err := pw.db.ProbeExecContext(ctx, `INSERT INTO alert_state (sensor_id, status, last_ts)
		SELECT id, ?, ? FROM sensors WHERE id = ?
		ON CONFLICT(sensor_id) DO UPDATE SET status = excluded.status, last_ts = excluded.last_ts`,
		status, store.FormatTS(ts), id)
	if err != nil {
		log.Printf("alert: failed to persist alert_state for %s: %v", id, err)
		return
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		// The guard matched no sensor row (concurrent delete): nothing
		// was written, so no in-memory copy is stamped either.
		return
	}
	// Write-through so the in-memory copy mirrors the durable row (it is
	// seeded from writes, re-read from the DB only on miss).
	pw.alertMemMu.Lock()
	if pw.alertMem == nil {
		pw.alertMem = make(map[string]alertMemEntry)
	}
	pw.alertMem[id] = alertMemEntry{status: status, ts: ts}
	pw.alertMemMu.Unlock()
}

// alertRetryAfter is how soon a re-alert is retried after every provider
// failed (instead of waiting out the full re-alert interval). A var for tests.
var alertRetryAfter = time.Minute

// scheduleAlertRetry backdates alert_state.last_ts so the sustained-error
// re-alert path (maybeRealert) fires again in about alertRetryAfter. It is a
// no-op for "alert once only" (realert_min = 0), and only touches the row if it
// is still tracking the same status (a sensor that recovered meanwhile keeps
// its newer state). The in-memory copy is backdated with it (write-through,
// same status guard): maybeRealert reads alertMem first, so a DB-only
// backdate would be invisible and the ~1-minute retry would never fire.
func (pw *ProbeWorker) scheduleAlertRetry(id, status string) {
	m := pw.realertMin()
	if m == 0 {
		return
	}
	back := time.Duration(m)*time.Minute - alertRetryAfter
	if back < 0 {
		back = 0
	}
	backdated := time.Now().UTC().Add(-back)
	res, err := pw.db.Exec(`UPDATE alert_state SET last_ts = ? WHERE sensor_id = ? AND status = ?`,
		store.FormatTS(backdated), id, status)
	if err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			pw.alertMemMu.Lock()
			if cur, ok := pw.alertMem[id]; ok && cur.status == status {
				cur.ts = backdated
				pw.alertMem[id] = cur
			}
			pw.alertMemMu.Unlock()
		}
	}
}

// recoveryRetryDelay is how long to wait before re-offering a recovery
// alert whose first delivery failed. It mirrors
// alertRetryAfter (the error direction re-alerts ~1m later), so both
// directions get their second chance on the same cadence. A var so tests
// can shorten it.
var recoveryRetryDelay = time.Minute

// retryJitter spreads a mass-retry herd: N dropped alerts scheduled at the
// same instant must not re-fire in lockstep a minute later (a second
// thundering herd). Upward-only [base, 1.5×base] — 60..90s at the
// production 1m base. The floor stays at base: the FIFO budget invariant
// (TestInFifoRetryBudgetUnderRecoveryRetryDelay) checks the worst in-band
// job against recoveryRetryDelay, so a sub-base jitter would re-open the
// permanent-drop window it closes.
func retryJitter(base time.Duration) time.Duration {
	if base < 2*time.Millisecond {
		return base
	}
	return base + time.Duration(rand.Int63n(int64(base)/2))
}

// scheduleRecoveryRetry re-offers a recovery / partial-recovery alert
// (error -> up, error -> warning) whose first delivery failed — dropped on
// a full per-sensor FIFO during provider degradation, or every provider
// down. The error direction self-heals through scheduleAlertRetry + the
// re-alert tick; recovery has NO such path: setAlertState has already
// stamped "up" and maybeRealert only runs on sustained-error ticks, so a
// dropped recovery is permanently lost — the chat's last word for a sensor
// that is UP stays "error" without this.
//
// Contract:
//   - Called from inside a launchAlert goroutine (the caller holds an
//     alertWG count), so this Add is never the counter-0 Add-concurrent-
//     with-Wait case — same discipline as armStormFlushLocked.
//   - The delay is watched on stopCtx, so StopAlerts aborts a pending
//     retry immediately and DrainAlerts never waits out the full delay.
//   - Guarded at FIRE time by currentStatus: a sensor that flapped back
//     into error during the delay must not receive a stale "recovered"
//     line after its fresh error alert (the per-sensor FIFO orders the
//     queue, not the delayed re-entry); a deleted sensor reads as an
//     error from currentStatus and is skipped the same way.
//   - Exactly one retry. A second failure is logged: the sensor's state
//     rows are correct, only the notification is lost, and an endless
//     retry loop against a dead provider is worse.
//
// History: docs/DECISIONS.md → alert-retry-budget.
func (pw *ProbeWorker) scheduleRecoveryRetry(id, name, target, oldStatus, newStatus string, rttMs float64) {
	// Capture the delay BEFORE spawning: the repo's -race rule forbids
	// reading a package var (tests swap it) inside the goroutine — the
	// retry outlives the test's restore, and the unsynchronized read/write
	// is a data race the detector flags (same discipline as enqueueAlert,
	// which passes alertGateIdle as a parameter). The jitter is drawn here
	// too: a mass recovery schedules N retries at one instant, and they
	// must not re-fire in lockstep (see retryJitter).
	delay := retryJitter(recoveryRetryDelay)
	pw.launchAlert(func() {
		select {
		case <-time.After(delay):
		case <-pw.stopCtx.Done():
			return
		}
		if cur, err := pw.currentStatus(id); err != nil || cur != newStatus {
			return // flapped back (or deleted): the newer transition owns the chat
		}
		if !pw.alertsEnabled() {
			return // maintenance began during the delay: stay silenced
		}
		if !pw.sendAlert(id, name, target, oldStatus, newStatus, rttMs) {
			log.Printf("alert: recovery retry for sensor %s failed again; notification dropped (state rows are correct)", id)
		}
	})
}

// scheduleStormRetry re-offers one entry of a storm summary that failed on
// ALL providers — a brief WAN outage takes out the targets and the egress
// together, and the batch would otherwise be discarded: on a realert_min ==
// 0 install no re-alert tick comes, so the coalesced sensors (#11..#N)
// never alert. Mirrors scheduleRecoveryRetry: one jittered re-offer
// through the normal path (sendAlert → stormAdmit) — if the providers are
// still down the entry re-coalesces into the next window's summary, which
// carries its own retry; guarded at fire time by currentStatus (a sensor
// that moved on owns the chat); exactly one retry, a second failure is
// logged. Works in BOTH directions: a dropped recovery storm summary has
// no re-alert path either.
// History: docs/DECISIONS.md → storm-summary-total-failure-retry.
func (pw *ProbeWorker) scheduleStormRetry(id, name, target, oldState, state string, rttMs float64) {
	delay := retryJitter(recoveryRetryDelay)
	pw.launchAlert(func() {
		select {
		case <-time.After(delay):
		case <-pw.stopCtx.Done():
			return
		}
		if cur, err := pw.currentStatus(id); err != nil || cur != state {
			return
		}
		if !pw.alertsEnabled() {
			return
		}
		if !pw.sendAlert(id, name, target, oldState, state, rttMs) {
			log.Printf("alert: storm retry for sensor %s failed again; notification dropped (state rows are correct)", id)
		}
	})
}

// realertMin returns the re-alert interval in minutes from the SNAPSHOT.
// 0 means alert once only (no re-alerts). Default 30. Lock-free: a DB
// hiccup can no longer read realert_min as "" and reset the interval to the
// 30-min default mid-storm.
func (pw *ProbeWorker) realertMin() int {
	return pw.alertSettings().realertMin
}

// ResetAlertStates stamps every tracked sensor's alert_state to now, so
// sensors already in a bad state do not immediately re-alert right after
// maintenance mode is turned off. The in-memory copies are stamped with the
// same instant (write-through): maintenance pauses sensors, so no probe tick
// refreshes alertMem while paused — a stale pre-maintenance mem.ts would
// survive to the first post-maintenance tick and re-alert immediately. A DB
// error is logged but the memory stamp is KEPT: the in-run behavior (no
// immediate re-alert after maintenance ends) is the point of this function;
// a durable-row miss after a restart only re-exposes the pre-reset timing,
// never a wrong state.
// History: docs/DECISIONS.md → reset-alert-states-mem-write-through.
func (pw *ProbeWorker) ResetAlertStates() {
	now := time.Now().UTC()
	if _, err := pw.db.Exec(`UPDATE alert_state SET last_ts = ?`, store.FormatTS(now)); err != nil {
		log.Printf("alert: failed to reset alert_state rows: %v", err)
	}
	pw.alertMemMu.Lock()
	for id, entry := range pw.alertMem {
		entry.ts = now
		pw.alertMem[id] = entry
	}
	pw.alertMemMu.Unlock()
}

// parseTSForRealert reads an alert_state.last_ts back into a time.Time for
// the re-alert interval check. It accepts BOTH formats this column has held:
// the new RFC3339Nano writer output (fractional seconds) and the integer-
// second rows older versions stored. Verified: stdlib time.Parse accepts a
// fractional string under the RFC3339Nano layout and an integer-second string
// under the same layout, so one layout covers both.
func parseTSForRealert(ts string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, ts)
}
