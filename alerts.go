package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"math/rand"
	"net/http"
	neturl "net/url"
	"os"
	"pulsemon/internal/store"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// alertPanicRecovered guards the fire-and-forget alert paths: a panicking
// delivery logs with a stack and sacrifices that ONE delivery, never the
// monitor — and never the goroutine owning shared alert machinery (a dead
// gate consumer fills that sensor's FIFO and blocks alertMu for every
// sensor). History: docs/DECISIONS.md → alert-gate.
func alertPanicRecovered(label string) {
	if r := recover(); r != nil {
		log.Printf("ALERT PANIC recovered (%s): %v\n%s", label, r, debug.Stack())
	}
}

// Alerting: the alert gate, storm coalescing, provider routing and
// delivery, retries, and the card builders for status-change alerts.

// alertGateIdle is how long an idle per-sensor alert consumer waits for
// its next job before exiting and dropping its map entry. A var so tests can shrink it; 10 minutes is far
// beyond any real alert cadence gap for a sensor that is alerting, so a
// live alerting sensor's consumer is effectively permanent — the idle
// exit only reclaims consumers whose sensor is quiet (deleted, or simply
// healthy).
var alertGateIdle = 10 * time.Minute

// enqueueAlert queues job on the sensor's FIFO and reports false if the
// 8-slot buffer is full (never blocks under alertMu — a stuck sensor must
// not stall every other sensor's enqueue). Invariant: map lookup, gate
// creation and the send are one alertMu critical section, so the consumer's
// idle-exit check (also under alertMu) can never see an empty queue while a
// send is in flight. History: docs/DECISIONS.md → alert-gate.
func (pw *ProbeWorker) enqueueAlert(id string, job func()) bool {
	pw.alertMu.Lock()
	defer pw.alertMu.Unlock()
	ch, ok := pw.alertOrderGates[id]
	if !ok {
		ch = make(chan func(), 8)
		pw.alertOrderGates[id] = ch
		// The idle duration is captured HERE, on the caller's goroutine,
		// and passed in: the consumer must not read the package var
		// (tests swap it; a reader outliving the restore is a data race,
		// caught by -race).
		go pw.alertGateConsumer(id, ch, alertGateIdle)
	}
	select {
	case ch <- job:
		return true
	default:
		log.Printf("alert: sensor %s alert queue full (8 pending); dropping alert", id)
		return false
	}
}

// alertGateConsumer drains one sensor's alert FIFO and exits after idleDur
// with no queued jobs, reaping consumers of quiet sensors — the channel is
// never closed (a send on a closed channel panics), so a plain `range ch`
// consumer would leak one goroutine per deleted sensor.
//
// Invariants (docs/DECISIONS.md → alert-gate): the exit check runs under
// alertMu — the same lock enqueueAlert holds across its send — so
// len(ch) == 0 under the lock means no job is queued AND no send is in
// flight; exiting drops nothing. idleDur arrives as a parameter (the
// consumer must NOT read the alertGateIdle package var; tests swap it). A
// Reset that skips draining a fired timer value reads as a spurious
// idle-fire, hence the Stop/drain/Reset lifecycle below.
func (pw *ProbeWorker) alertGateConsumer(id string, ch chan func(), idleDur time.Duration) {
	idle := time.NewTimer(idleDur)
	for {
		select {
		case job := <-ch:
			// Per-job recover: a panicking delivery
			// used to crash the monitor AND take this sensor's alerting
			// down with it (consumer dies → FIFO fills → alertMu blocks
			// for every sensor). Sacrifice the job, keep the loop alive.
			func() {
				defer alertPanicRecovered("alert-gate " + id)
				job()
			}()
			// Drain-then-Reset (the canonical safe pattern): the timer
			// may have fired while job() was running; a Reset without
			// draining the fired value would leave a stale ready in
			// idle.C.
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(idleDur)
		case <-idle.C:
			pw.alertMu.Lock()
			if len(ch) == 0 {
				if pw.alertOrderGates[id] == ch {
					delete(pw.alertOrderGates, id)
				}
				pw.alertMu.Unlock()
				return
			}
			pw.alertMu.Unlock()
			idle.Reset(idleDur)
		}
	}
}

// alertSettings is the typed, point-in-time snapshot of every setting the
// alert hot path reads: the gate (maintenance, routing scope, filter,
// re-alert interval) and the resolved delivery destinations (provider URL +
// Telegram chat_id). Loaded once at worker start, swapped atomically after
// every successful PUT /api/settings commit — the gate and delivery then
// read it lock-free, with ZERO per-probe / per-alert DB queries.
//
// Why a snapshot: GetSetting maps a read error to "", so a transient DB
// lock mid-probe made maintenance_mode read as "0" (alerts ENABLED) and
// alert_scope read as "" (scope "all") — a DB hiccup during maintenance
// fired alerts for every sensor. The snapshot keeps the last GOOD state in
// memory: a hiccup between reloads never touches it, so maintenance stays
// on, routing stays put, and the hot path is lock-free.
// History: docs/DECISIONS.md → alert-settings-snapshot.
type alertSettings struct {
	maintenance bool            // maintenance_mode == "1"
	scope       string          // alert_scope, normalized to "all" when empty
	filter      map[string]bool // alert_filter items (tag names, or sensor ids)
	realertMin  int             // realert_min (0 = alert once only)
	dests       []dest          // resolved active providers (url + chat_id)
}

// defaultAlertSettings is the safe fallback: alerts enabled, every sensor in
// scope, the 30-min re-alert default, no providers. It matches the
// pre-snapshot swallow-to-default behavior and is stored before the first DB
// load so the hot path never derefs a nil snapshot.
func defaultAlertSettings() *alertSettings {
	return &alertSettings{
		maintenance: false,
		scope:       "all",
		filter:      map[string]bool{},
		realertMin:  30,
		dests:       []dest{},
	}
}

// resolveDestinationsFromDB resolves the active, URL-configured providers
// (with the Telegram chat_id) from the DB — the single place that turns
// raw provider settings into delivery destinations, run at snapshot-load
// time so the hot path reads the result lock-free. Every key — Enabled,
// HasURL, URL, chat_id — is evaluated fail-loud from ONE bulk settings
// read (getAllSettings): a real read failure aborts the load (the caller
// keeps the previous snapshot), for EVERY key. Swallowing Enabled/HasURL
// (GetSetting) let a transient lock silently DROP a provider from an
// installed snapshot — alerts for it stopped until the next settings
// save: the exact half-read state the snapshot design forbids.
// History: docs/DECISIONS.md → provider-reads-bulk-fail-loud.
func resolveDestinationsFromDB(db *store.Store) ([]dest, error) {
	m, err := getAllSettings(db)
	if err != nil {
		return nil, err
	}
	return resolveDestsGet(func(k string) (string, error) { return m[k], nil })
}

func resolveDestsGet(get settingGet) ([]dest, error) {
	var dests []dest
	for _, p := range providerList {
		en, err := p.enabledGet(get)
		if err != nil {
			return nil, err
		}
		hu, err := p.hasURLGet(get)
		if err != nil {
			return nil, err
		}
		if !en || !hu {
			continue
		}
		// p.URLField, NOT p.Kind + "_url": SMTP's value lives in
		// "smtp_host", and a "smtp_url" lookup returns "" for every real
		// SMTP config — silently skipping email (see resolveDestinations).
		url, err := get(p.URLField)
		if err != nil {
			return nil, err
		}
		if url == "" && p.EnvFallback != "" {
			url = os.Getenv(p.EnvFallback)
		}
		if url == "" {
			continue
		}
		var chatID string
		if p.Kind == "telegram" {
			// Resolved up front, error-aware: a transient DB lock must
			// fail the load (and keep the previous snapshot), never post
			// an empty chat_id (Telegram 400).
			chatID, err = get("telegram_chat_id")
			if err != nil || chatID == "" {
				return nil, err
			}
		}
		d := dest{p: p, url: url, chatID: chatID}
		if p.Kind == "smtp" {
			// The full mail config resolves here with the URL/chat_id
			// (one bulk read, fail-loud): delivery then performs ZERO
			// settings reads. The old live smtpConfig() did 7 swallow-to-""
			// GetSetting calls per send — a transient lock degraded into
			// "not configured", which the retry loop skips as permanent.
			cfg, err := smtpConfigFromGet(get)
			if err != nil {
				return nil, err
			}
			d.smtp = &cfg
		}
		dests = append(dests, d)
	}
	return dests, nil
}

// loadAlertSettings reads the alert-relevant settings from the DB into a
// fresh snapshot. Every key (core fields AND providers) comes from ONE
// bulk settings read (getAllSettings): a read ERROR aborts the load with
// an error, so the caller keeps the previous snapshot instead of
// installing a half-read one, and the whole snapshot observes a single
// consistent commit of the settings table (the settings PUT commits all
// its keys in one tx; N point reads could straddle it). A MISSING key
// falls back to the same default the old per-read code used (scope
// "all", realert 30, no filter).
func loadAlertSettings(db *store.Store) (*alertSettings, error) {
	m, err := getAllSettings(db)
	if err != nil {
		return nil, err
	}
	get := func(k string) (string, error) { return m[k], nil }
	s := defaultAlertSettings()

	s.maintenance = m["maintenance_mode"] == "1"

	scope := m["alert_scope"]
	if scope == "" {
		scope = "all"
	}
	s.scope = scope

	if f := m["alert_filter"]; f != "" {
		var items []string
		if err := json.Unmarshal([]byte(f), &items); err != nil {
			// A corrupt filter is treated as "no filter": the old
			// shouldAlert returned false on an unmarshal error (no sensor
			// matched), which is the same as an empty set here.
			items = nil
		}
		s.filter = make(map[string]bool, len(items))
		for _, it := range items {
			s.filter[it] = true
		}
	}

	if v := m["realert_min"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 1440 {
			s.realertMin = n
		}
	}

	dests, err := resolveDestsGet(get)
	if err != nil {
		return nil, err
	}
	s.dests = dests
	return s, nil
}

// reloadAlertSettings re-reads the alert settings from the DB and atomically
// swaps the snapshot. Called at worker start (after the default is stored)
// and after every successful PUT /api/settings commit. On a read error it
// KEEPS the previous snapshot (logging a warning) — a hiccup must never
// install a half-read state, which is exactly the bug this snapshot fixes.
// A nil DB (test workers that don't exercise settings) keeps the current
// snapshot too: the default stands until a real DB is present.
func (pw *ProbeWorker) reloadAlertSettings() {
	if pw.reloadObs != nil {
		pw.reloadObs()
	}
	if pw.db == nil {
		return
	}
	s, err := loadAlertSettings(pw.db)
	if err != nil {
		log.Printf("alert: settings snapshot reload failed (keeping last good): %v", err)
		return
	}
	pw.alertCfg.Store(s)
}

// alertSettings returns the current snapshot lock-free. It is never nil:
// NewProbeWorker stores a default snapshot before the first load, and the
// lazy fallback covers tests that construct &ProbeWorker{} directly.
func (pw *ProbeWorker) alertSettings() *alertSettings {
	if s := pw.alertCfg.Load(); s != nil {
		return s
	}
	pw.reloadAlertSettings()
	if s := pw.alertCfg.Load(); s != nil {
		return s
	}
	return defaultAlertSettings()
}

// alertsEnabled reports whether any alert may fire: maintenance mode
// silences everything. It reads the SNAPSHOT, not the DB: a transient DB
// lock between reloads must never read maintenance_mode as "0" and fire
// alerts during maintenance.
func (pw *ProbeWorker) alertsEnabled() bool {
	return !pw.alertSettings().maintenance
}

// alertableTransition reports whether a status CHANGE sends an alert.
// Warning-only movement is dashboard-only by design — up<->warning flapping
// was alert noise: neither entering warning nor warning -> up is worth a
// notification. Everything involving error alerts: into error, error ->
// warning (partial recovery), and error -> up (full recovery). Same-state
// input is false here; sustained-error re-alerts don't go through this
// gate — see alertGates.
func alertableTransition(oldStatus, newStatus string) bool {
	if oldStatus == newStatus {
		return false
	}
	if oldStatus == "error" || newStatus == "error" {
		return true
	}
	return false // up<->warning flapping: dashboard-only
}

// alertGates applies the maintenance gate and the global alert routing rule
// (settings table): "all", "tags" (any of the sensor's tags in filter list),
// or "sensors" (id in filter list).
func (pw *ProbeWorker) alertGates(c sensorConfig) bool {
	if !pw.alertsEnabled() {
		return false
	}
	return pw.shouldAlert(c.id, c.tags)
}

// shouldAlertNow decides whether a status transition alerts: maintenance
// off, routing in scope, and the transition itself is alertable (warning is
// dashboard-only in both directions — see alertableTransition).
func (pw *ProbeWorker) shouldAlertNow(c sensorConfig, oldStatus, newStatus string) bool {
	if !pw.alertGates(c) {
		return false
	}
	return alertableTransition(oldStatus, newStatus)
}

// shouldAlert applies the global alert routing rule from the SNAPSHOT:
// "all", "tags" (any of the sensor's tags in the filter), or "sensors" (id
// in the filter). Lock-free: the snapshot is swapped after each
// PUT /api/settings commit, so a routing change takes effect on the next
// transition with zero staleness AND zero per-decision DB reads — a DB
// hiccup can no longer read alert_scope as "" (scope "all") and alert every
// sensor.
func (pw *ProbeWorker) shouldAlert(id string, tags []string) bool {
	s := pw.alertSettings()
	if s.scope == "all" {
		return true
	}
	switch s.scope {
	case "tags":
		for _, t := range tags {
			if s.filter[t] {
				return true
			}
		}
	case "sensors":
		if s.filter[id] {
			return true
		}
	}
	return false
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

type providerMeta struct {
	Kind        string // settings key prefix: google_chat, discord
	Label       string // display name
	URLField    string // JSON field the settings payload uses
	Placeholder string // input placeholder
	EnvFallback string // env var that supplies a URL when the dashboard one is empty ("") = none
	// The canonical predicates take a settingGet so each provider's
	// enabled/has-URL logic lives in EXACTLY ONE place and can be
	// evaluated fail-loud against any read source: the bulk-map adapter
	// (snapshot load + settings GET) or db.GetSettingErr (TestWebhook).
	// The old bool, GetSetting-swallowing predicates survive only as free
	// functions for the test suite; production reads all go through these.
	enabledGet func(get settingGet) (bool, error)
	hasURLGet  func(get settingGet) (bool, error)
}

// settingGet reads one settings key. Contract: absent key is ("", nil);
// a read FAILURE is ("", err) and must abort the caller's evaluation —
// "unset" and "read failed" must never look the same on the alert paths
// (the fail-loud settings-read contract).
type settingGet = func(key string) (string, error)

// getAllSettings is the bulk-load seam (test seam, mirroring
// getSettingErr): the snapshot load and the settings GET payload evaluate
// every provider key from ONE consistent settings-table read.
var getAllSettings = func(db *store.Store) (map[string]string, error) { return db.GetAllSettings() }

var providerList = []providerMeta{
	{
		Kind: "google_chat", Label: "Google Chat", URLField: "google_chat_url",
		Placeholder: "https://chat.googleapis.com/v1/spaces/…/messages?key=…",
		EnvFallback: "GOOGLE_CHAT_WEBHOOK_URL",
		enabledGet:  chatEnabledGet,
		hasURLGet:   chatHasURLGet,
	},
	{
		Kind: "discord", Label: "Discord", URLField: "discord_url",
		Placeholder: "https://discord.com/api/webhooks/…/…",
		EnvFallback: "",
		enabledGet:  flagEnabledGet("discord"),
		hasURLGet:   flagHasURLGet("discord"),
	},
	{
		Kind: "telegram", Label: "Telegram", URLField: "telegram_url",
		Placeholder: "https://api.telegram.org/bot<TOKEN>/sendMessage",
		EnvFallback: "",
		enabledGet:  flagEnabledGet("telegram"),
		hasURLGet:   telegramHasURLGet,
	},
	{
		Kind: "smtp", Label: "Email (SMTP)", URLField: "smtp_host",
		Placeholder: "smtp.example.com",
		EnvFallback: "",
		enabledGet:  smtpEnabledGet,
		hasURLGet:   smtpHasURLGet,
	},
}

func providerByKey(kind string) (providerMeta, bool) {
	for _, p := range providerList {
		if p.Kind == kind {
			return p, true
		}
	}
	return providerMeta{}, false
}

// chatEnabledGet: google_chat's legacy default. Explicitly enabled ("1")
// wins; explicitly disabled ("0") wins; with no flag, a present URL
// (dashboard or env) keeps it active so an upgrade changes nothing. Fresh
// install: no URL, no flag → off. (The swallow-to-"" twins the test suite
// uses live in provider_predicates_test.go — every
// production read uses these *Get predicates so a settings read failure
// aborts the caller instead of reading as "provider unset"; 2026-11-13
// review, closing the Enabled/HasURL half of the class the 2026-10-30
// chat_id fix opened.)
func chatEnabledGet(get settingGet) (bool, error) {
	v, err := get("google_chat_enabled")
	if err != nil {
		return false, err
	}
	switch v {
	case "1":
		return true, nil
	case "0":
		return false, nil
	}
	return chatHasURLGet(get)
}

// chatHasURLGet: the dashboard URL, falling back to the
// GOOGLE_CHAT_WEBHOOK_URL env (the pre-multi-provider mechanism, kept
// working).
func chatHasURLGet(get settingGet) (bool, error) {
	v, err := get("google_chat_url")
	if err != nil {
		return false, err
	}
	if v != "" {
		return true, nil
	}
	return os.Getenv("GOOGLE_CHAT_WEBHOOK_URL") != "", nil
}

// flagEnabledGet / flagHasURLGet: a generic provider — explicit "1" flag
// and a non-empty URL. No env fallback, no legacy default. Built as
// closures over the provider kind so each entry is self-contained.
func flagEnabledGet(kind string) func(settingGet) (bool, error) {
	return func(get settingGet) (bool, error) {
		v, err := get(kind + "_enabled")
		return v == "1", err
	}
}

func flagHasURLGet(kind string) func(settingGet) (bool, error) {
	return func(get settingGet) (bool, error) {
		v, err := get(kind + "_url")
		return v != "", err
	}
}

// telegramHasURLGet: Telegram needs BOTH the bot endpoint and a chat_id
// to deliver; a URL alone can't reach anyone.
func telegramHasURLGet(get settingGet) (bool, error) {
	u, err := get("telegram_url")
	if err != nil {
		return false, err
	}
	c, err := get("telegram_chat_id")
	if err != nil {
		return false, err
	}
	return u != "" && c != "", nil
}

// providerStatus is the per-provider read the settings API returns to the
// dashboard.
type providerStatus struct {
	Kind    string            `json:"kind"`
	Enabled bool              `json:"enabled"`
	HasURL  bool              `json:"has_url"`
	URL     string            `json:"url"` // masked; empty when none
	Source  string            `json:"source"`
	Extra   map[string]string `json:"extra,omitempty"` // non-secret fields (e.g. telegram chat_id)
}

// providerExtraGet returns a provider's non-secret, non-URL fields for the
// dashboard to pre-fill. chat_id is not a credential — the token lives in
// the masked URL — so it is returned in the clear. Reads go through the
// settingGet contract (see providerMeta): every read is fail-loud, and
// the fixed slice order keeps the read order deterministic.
func providerExtraGet(p providerMeta, get settingGet) (map[string]string, error) {
	if p.Kind == "telegram" {
		cid, err := get("telegram_chat_id")
		if err != nil {
			return nil, err
		}
		if cid != "" {
			return map[string]string{"chat_id": cid}, nil
		}
	}
	if p.Kind == "smtp" {
		extra := map[string]string{}
		for _, kf := range [][2]string{
			{"smtp_port", "port"}, {"smtp_from", "from"}, {"smtp_to", "to"},
			{"smtp_username", "username"}, {"smtp_tls_mode", "tls_mode"},
		} {
			v, err := get(kf[0])
			if err != nil {
				return nil, err
			}
			if v != "" {
				extra[kf[1]] = v
			}
		}
		// The password is never returned in the clear. A stored password is
		// surfaced as a fixed mask ("••••••••") so the UI knows the field is
		// filled; the save path treats the mask as "unchanged" and omits it.
		pw, err := get("smtp_password")
		if err != nil {
			return nil, err
		}
		if pw != "" {
			extra["password"] = "••••••••"
		}
		if len(extra) > 0 {
			return extra, nil
		}
	}
	return nil, nil
}

// providerStatuses builds the per-provider view for the settings API.
// Every key comes from ONE bulk settings read and every read is fail-loud
// settingsPayload() aborts on a transient DB failure
// for its own fields via GetSettingErr — a swallowed provider read here
// used to answer 200 with providers claiming enabled:false/has_url:false,
// a payload the settings PUT can echo back and write.
func (pw *ProbeWorker) providerStatuses() ([]providerStatus, error) {
	m, err := getAllSettings(pw.db)
	if err != nil {
		return nil, err
	}
	get := func(k string) (string, error) { return m[k], nil }
	out := []providerStatus{}
	for _, p := range providerList {
		// p.URLField is the canonical read (SMTP's display "URL" is
		// smtp_host, which the providerList literal already declares).
		url := m[p.URLField]
		source := "none"
		if url != "" {
			source = "dashboard"
		} else if p.EnvFallback != "" && os.Getenv(p.EnvFallback) != "" {
			url = os.Getenv(p.EnvFallback)
			source = "env"
		}
		en, err := p.enabledGet(get)
		if err != nil {
			return nil, err
		}
		hu, err := p.hasURLGet(get)
		if err != nil {
			return nil, err
		}
		extra, err := providerExtraGet(p, get)
		if err != nil {
			return nil, err
		}
		out = append(out, providerStatus{
			Kind:    p.Kind,
			Enabled: en,
			HasURL:  hu,
			URL:     webhookMasked(url),
			Source:  source,
			Extra:   extra,
		})
	}
	return out, nil
}

// sendWebhook delivers one alert to every active provider and reports
// whether it was delivered. The delivery is QUEUED on the sensor's
// alertGate FIFO first: alerts for one sensor run
// strictly in launch order, so an "error" alert whose first attempt fails
// and retries cannot be delivered AFTER the sensor's later "recovered"
// alert — the chat's last word must match the sensor's current state.
// The caller blocks until the delivery finishes (the launchAlert goroutine
// is tracked in alertWG, so DrainAlerts still sees true completion).
func (pw *ProbeWorker) sendWebhook(id, name, target, oldState, state string, rttMs float64, reAlert bool) bool {
	// Storm budget: over-budget transitions are coalesced into a single
	// storm summary instead of delivered individually. A suppressed alert
	// reports "delivered" (true) so the caller schedules no retry — the
	// summary carries it. Re-alerts (oldState == state) NEVER ride the
	// budget: they are the operator's re-alert cadence, not a transition
	// burst, and coalescing them would burn budget meant for new
	// transitions and render bogus "svc: error -> error" lines in a
	// "sensors changed state" summary.
	if !reAlert && !pw.stormAdmit(id, name, target, oldState, state, rttMs) {
		return true
	}
	done := make(chan bool, 1)
	if !pw.enqueueAlert(id, func() {
		// Guarantee a `done` value even if the delivery panics: the
		// consumer's per-job recover swallows the panic (sacrifice the job,
		// keep the loop alive), but a skipped `done <-` would park this
		// caller on `<-done` forever — leaking the goroutine and its
		// alertWG count, so DrainAlerts burns the full backstop at every
		// shutdown. The buffer-1 channel makes the
		// defer exact: the normal send fills it and the defer is a no-op;
		// on panic the defer is the sole writer.
		defer func() {
			select {
			case done <- false:
			default:
			}
		}()
		done <- pw.sendWebhookDeliver(id, name, target, oldState, state, rttMs, reAlert)
	}) {
		// The sensor's FIFO was full (provider degradation): the alert was
		// dropped, not delivered. Report false so the caller schedules its
		// 1-minute-later retry (scheduleAlertRetry) once the queue drains.
		return false
	}
	select {
	case ok := <-done:
		return ok
	case <-pw.stopCtx.Done():
		// Shutdown began before the FIFO reached this job. Abort the wait
		// so this caller (tracked in alertWG via launchAlert) releases its
		// count and DrainAlerts can finish, instead of parking on `<-done`
		// for the full backstop.
		return false
	}
}

// stormEntry is one alert suppressed by the storm budget, pending the
// coalesced summary.
type stormEntry struct {
	id       string
	name     string
	target   string
	oldState string
	state    string
	rttMs    float64
}

// stormBudget / stormWindow bound the global alert rate: at most
// stormBudget individual non-recovery alerts per stormWindow.
// recoveryStormBudget / recoveryStormWindow bound the recovery direction
// symmetrically (see the stormMu field comment in probe.go). Vars so tests
// can shrink them.
var (
	stormBudget         = 10
	stormWindow         = 30 * time.Second
	recoveryStormBudget = 10
	recoveryStormWindow = 30 * time.Second
)

// isRecoveryState reports whether a transition is a recovery: full (up) or
// partial (error -> warning). Both ride the recovery storm budget.
func isRecoveryState(oldState, state string) bool {
	return state == "up" || (oldState == "error" && state == "warning")
}

// stormAdmit reports whether this alert may be delivered individually,
// applying the budget of ITS direction (recovery vs non-recovery). See the
// stormMu field comment for the design.
func (pw *ProbeWorker) stormAdmit(id, name, target, oldState, state string, rttMs float64) bool {
	pw.stormMu.Lock()
	defer pw.stormMu.Unlock()
	return pw.stormAdmitLocked(isRecoveryState(oldState, state), stormEntry{
		id: id, name: name, target: target, oldState: oldState, state: state, rttMs: rttMs,
	})
}

// stormAdmitLocked applies ONE direction's budget. Caller holds stormMu.
func (pw *ProbeWorker) stormAdmitLocked(recovery bool, e stormEntry) bool {
	var (
		windowStart *time.Time
		count       *int
		queue       *[]stormEntry
		budget      int
		window      time.Duration
	)
	if recovery {
		windowStart, count, queue = &pw.recoveryStormWindowStart, &pw.recoveryStormCount, &pw.recoveryStormQueue
		budget, window = recoveryStormBudget, recoveryStormWindow
	} else {
		windowStart, count, queue = &pw.stormWindowStart, &pw.stormCount, &pw.stormQueue
		budget, window = stormBudget, stormWindow
	}
	now := time.Now()
	if now.Sub(*windowStart) >= window {
		*windowStart = now
		*count = 0
	}
	if *count < budget {
		*count++
		return true
	}
	*queue = append(*queue, e)
	pw.armStormFlushLocked(recovery, now)
	return false
}

// armStormFlushLocked schedules the one-shot flush of the coalesced queue
// of ONE direction at the end of its current storm window. Caller holds
// stormMu.
func (pw *ProbeWorker) armStormFlushLocked(recovery bool, now time.Time) {
	var (
		armed       *bool
		windowStart *time.Time
		window      time.Duration
	)
	if recovery {
		armed, windowStart, window = &pw.recoveryStormFlushArmed, &pw.recoveryStormWindowStart, recoveryStormWindow
	} else {
		armed, windowStart, window = &pw.stormFlushArmed, &pw.stormWindowStart, stormWindow
	}
	if *armed {
		return
	}
	*armed = true
	due := time.Until(windowStart.Add(window))
	if due < 0 {
		due = 0
	}
	// Track the flush in alertWG from ARM time: the arming caller is an alert
	// path that already holds a launchAlert count (sendWebhook runs inside
	// launchAlert), so this Add can never be the "Add called concurrently with
	// Wait" case at counter 0. DrainAlerts JOINS a pending flush; the goroutine
	// exits promptly on stopCtx, so shutdown is not delayed (the queued summary
	// drops on shutdown — StopAlerts has aborted the network by then;
	// unchanged, documented).
	// History: docs/DECISIONS.md → alert-gate.
	pw.alertWG.Add(1)
	go func() {
		defer pw.alertWG.Done()
		defer alertPanicRecovered("storm-flush")
		select {
		case <-time.After(due):
			pw.flushStorm(recovery)
		case <-pw.stopCtx.Done():
		}
	}()
}

// flushStorm delivers the coalesced storm summary of ONE direction (when
// its queue is non-empty) and resets that direction's budget for the next
// window.
func (pw *ProbeWorker) flushStorm(recovery bool) {
	pw.stormMu.Lock()
	var (
		q           []stormEntry
		windowStart *time.Time
		count       *int
		armed       *bool
	)
	if recovery {
		q = pw.recoveryStormQueue
		pw.recoveryStormQueue = nil
		windowStart, count, armed = &pw.recoveryStormWindowStart, &pw.recoveryStormCount, &pw.recoveryStormFlushArmed
	} else {
		q = pw.stormQueue
		pw.stormQueue = nil
		windowStart, count, armed = &pw.stormWindowStart, &pw.stormCount, &pw.stormFlushArmed
	}
	*windowStart = time.Time{}
	*count = 0
	*armed = false
	pw.stormMu.Unlock()
	if len(q) == 0 {
		return
	}
	// Maintenance mode silences every alert — the summary included. The
	// individual alerts that filled this queue were each gated at launch,
	// but maintenance can begin AFTER an entry was queued (the flush fires
	// up to stormWindow later), so re-check at flush time: a storm summary
	// must never land in a chat the operator has silenced.
	if !pw.alertsEnabled() {
		return
	}
	// Dedupe by sensor first: a sensor that flapped more than once inside
	// the window (up -> error, then warning -> error) leaves one queue
	// entry per transition. Only the latest transition per sensor is
	// actionable — the older line is stale by definition — so keep the
	// latest entry, in first-seen order for stable summaries.
	latest := make(map[string]stormEntry, len(q))
	order := make([]string, 0, len(q))
	for _, e := range q {
		if _, seen := latest[e.id]; !seen {
			order = append(order, e.id)
		}
		latest[e.id] = e
	}
	// Drop entries whose sensor has MOVED ON since the transition was queued:
	// a summary line for a sensor that recovered (now "up") would contradict
	// the recovery alert it raced, and one that degraded further (entry
	// "warning", now "error") is stale — the newer transition alerted
	// individually. The same filter serves both directions symmetrically: a
	// queued recovery (entry "up") whose sensor flapped back to "error" is
	// dropped for the same reason — the newer transition owns its own budget
	// path and is the operator's last word, not this summary. A vanished
	// sensor (deleted mid-storm, read error) is KEPT — the operator should
	// still see it in the storm that took it down. Status is read via
	// currentStatus (in-memory first): actively-probed sensors make
	// lastStatus the freshest source, and it avoids one SQLite round-trip
	// per queued entry.
	// History: docs/DECISIONS.md → storm-summary-caps-maintenance-gate-and-moved-on-filter.
	still := q[:0]
	for _, id := range order {
		if s, err := pw.currentStatus(id); err == nil && s != latest[id].state {
			continue
		}
		still = append(still, latest[id])
	}
	if len(still) == 0 {
		return
	}
	pw.launchAlert(func() {
		pw.deliverStormSummary(still, recovery)
	})
}

// deliverStormSummary sends the coalesced summary of ONE direction to every
// active provider in parallel (same fan-out contract as sendWebhookDeliver).
// It is a global meta-alert — NOT queued on any sensor's alertGate — so it
// cannot disturb a sensor's per-sensor ordering guarantee (F4).
func (pw *ProbeWorker) deliverStormSummary(entries []stormEntry, recovery bool) {
	// Maintenance can begin between flushStorm's check and this delivery
	// (launchAlert queues the job, it does not run it inline): re-check so
	// a summary never lands in a chat silenced in the gap.
	if !pw.alertsEnabled() {
		return
	}
	// Re-check each entry's status immediately before building the summary:
	// flushStorm's filter ran earlier and this delivery is async (launchAlert)
	// — a sensor that moved on in the gap would be listed under a state it no
	// longer holds, contradicting the individual alert the per-sensor gate
	// ordered ahead of this summary (which bypasses that gate). The re-check
	// narrows the race to the instant before the post. currentStatus is
	// in-memory for an actively-probed sensor, so this is cheap.
	// History: docs/DECISIONS.md → storm-summary-recheck-before-post.
	still := make([]stormEntry, 0, len(entries))
	for _, e := range entries {
		if s, err := pw.currentStatus(e.id); err == nil && s != e.state {
			continue
		}
		still = append(still, e)
	}
	if len(still) == 0 {
		return
	}
	entries = still
	dests, ok := pw.resolveDestinations()
	if !ok {
		log.Printf("alert: storm summary (%d sensors) not delivered — provider list unreadable", len(entries))
		return
	}
	// Render per provider, each under ITS content cap: over the cap the
	// post is a non-retryable HTTP 400 and the WHOLE summary is dropped —
	// the operator gets no outage alert at all. The capped formatters
	// replace the overflow with a "… and N more" footer, so every
	// provider receives a body it will accept (see truncateSummaryLines).
	// SMTP has no practical limit: 0 = uncapped.
	kind := "alert"
	if recovery {
		kind = "recovery"
	}
	mdChat := stormSummaryMarkdown(entries, googleChatMax, recovery)
	mdDiscord := stormSummaryMarkdown(entries, discordContentMax, recovery)
	subject := fmt.Sprintf("pulsemon: %s storm — %d sensors %s", kind, len(entries), stormSummaryCountNoun(recovery))
	body := stormSummaryPlain(entries, 0, recovery)
	var wg sync.WaitGroup
	var delivered atomic.Bool
	for _, d := range dests {
		wg.Add(1)
		go func(d dest) {
			defer wg.Done()
			defer alertPanicRecovered("deliver-" + d.p.Kind)
			var ok bool
			switch d.p.Kind {
			case "google_chat":
				ok = pw.postJSON(d.url, map[string]any{"text": mdChat}) == nil
			case "discord":
				ok = pw.postJSON(d.url, map[string]any{
					"content":          mdDiscord,
					"allowed_mentions": map[string]any{"parse": []string{}},
				}) == nil
			case "telegram":
				// d.chatID was resolved up front in resolveDestinations
				// (see dest) — never a live re-read here.
				ok = pw.postJSON(d.url, map[string]any{
					"chat_id":    d.chatID,
					"text":       stormSummaryHTML(entries, telegramTextMax, recovery),
					"parse_mode": "HTML",
				}) == nil
			case "smtp":
				ok = d.smtp != nil && pw.sendSMTPWith(pw.stopCtx, *d.smtp, subject, body) == nil
			}
			if ok {
				delivered.Store(true)
			}
		}(d)
	}
	wg.Wait()
	if len(dests) > 0 && !delivered.Load() {
		// Every provider failed (a brief WAN outage takes out the targets
		// AND the egress together): re-offer each entry through the normal
		// path instead of discarding the batch. On a realert_min == 0
		// install no re-alert tick ever comes, so the coalesced sensors
		// (#11..#N) would never alert — exactly the visibility the storm
		// path exists to preserve.
		log.Printf("alert: storm summary (%d sensors) failed on all %d providers; re-offering each entry", len(entries), len(dests))
		for _, e := range entries {
			pw.scheduleStormRetry(e.id, e.name, e.target, e.oldState, e.state, e.rttMs)
		}
	}
}

// discordContentMax / telegramTextMax / googleChatMax are the providers'
// message-content limits (the text field, not the whole request): Discord
// 2,000 characters, Telegram sendMessage 4,096, Google Chat 4,096.
// Exceeding them is a non-retryable HTTP 400 — the provider rejects the
// WHOLE message — so an unbounded storm summary (a 50-sensor rack outage
// easily exceeds 2,000) silently dropped the operator's only outage
// alert. The formatters cap their output per provider; the overflow is
// reported as a "… and N more" footer. Vars so a test can shrink them
// without rendering 40-sensor bodies.
var (
	discordContentMax = 2000
	telegramTextMax   = 4096
	googleChatMax     = 4096
)

// truncateSummaryLines renders a storm summary: header, then one line per
// sensor, capped at maxRunes (0 = uncapped). When the next line would push
// the body over the cap, the remaining lines are replaced with a
// "… and N more" footer — the body stays under the provider's limit, so
// the post is accepted and the operator sees the outage (the first N lines
// name the sensors; the header still counts ALL of them). The cap is on
// RUNES, not bytes: the summaries are operator-facing prose and the
// provider limits are character-based.
func truncateSummaryLines(header string, lines []string, maxRunes int) string {
	var b strings.Builder
	b.WriteString(header)
	runes := utf8.RuneCountInString(header)
	shown := 0
	// The worst-case footer (the "\n… and N more" at the FULL line count)
	// is reserved up front: without the reservation a body ending exactly
	// at maxRunes gets the footer appended on top, the "capped" output
	// exceeds the provider's limit, and the provider rejects the WHOLE
	// summary with a non-retryable HTTP 400.
	limit := maxRunes - utf8.RuneCountInString(fmt.Sprintf("\n… and %d more", len(lines)))
	for _, line := range lines {
		lineRunes := utf8.RuneCountInString(line)
		if maxRunes > 0 && runes+1+lineRunes > limit {
			fmt.Fprintf(&b, "\n… and %d more", len(lines)-shown)
			break
		}
		b.WriteString("\n")
		b.WriteString(line)
		runes += 1 + lineRunes
		shown++
	}
	return b.String()
}

// stormSummaryLine renders one entry as a readable transition for the
// non-Markdown summary paths (Telegram HTML, SMTP plain), with the same
// hygiene as the per-sensor cards: credentials stripped (F22). Mention
// tokens are NOT neutralized here: those paths carry the name verbatim, and
// the invisible \u200b discordMentionSafe injects is pointless there and
// corrupts copy-paste in email clients / renders as tofu in non-UTF-8
// readers. The Markdown path (stormSummaryMarkdown)
// builds its own line so it can escape the name without escaping the URL
// target
func stormSummaryLine(e stormEntry) string {
	return fmt.Sprintf("%s: %s → %s (%s)", e.name, e.oldState, e.state, alertTarget(e.target))
}

// stormSummaryCountNoun is the header's verb phrase per direction: a down
// storm is a batch of state changes, a recovery storm a batch of recovered
// sensors (a partial recovery's line shows "error → warning" verbatim).
func stormSummaryCountNoun(recovery bool) string {
	if recovery {
		return "recovered"
	}
	return "changed state"
}

// stormSummaryMarkdown renders the summary for google_chat / discord.
// maxRunes is the destination provider's content cap (googleChatMax /
// discordContentMax); 0 = uncapped (see truncateSummaryLines).
func stormSummaryMarkdown(entries []stormEntry, maxRunes int, recovery bool) string {
	header := stormSummaryHeader("⚠️ *pulsemon: alert storm — %d sensors changed state (coalesced to limit alert noise)*",
		"✅ *pulsemon: recovery storm — %d sensors recovered (coalesced to limit alert noise)*", recovery, len(entries))
	lines := make([]string, len(entries))
	for i, e := range entries {
		// Escape the emphasis chars in the NAME only (free text — a name like
		// db_primary_01 would otherwise render "primary" in italics, and a raw *
		// in the name renders as literal formatting), with mention tokens
		// neutralized. The TARGET is a URL/hostname and stays VERBATIM: mdEscape
		// would inject backslashes into _ and ~ in the path and break the clickable
		// link — but it IS mention-neutralized, exactly like the per-sensor
		// discordCard/discordCardRe: a target path like https://example.com/@every-
		// one would mass-ping the channel on clients that ignore
		// allowed_mentions.parse = []. The emphasis markers come from the format
		// string.
		// History: docs/DECISIONS.md → storm-summary-target-mention-safe.
		lines[i] = "*" + mdEscape(discordMentionSafe(e.name)) + ": " + e.oldState + " → " + e.state + " (" + discordMentionSafe(alertTarget(e.target)) + ")*"
	}
	return truncateSummaryLines(header, lines, maxRunes)
}

// stormSummaryHTML renders the summary for telegram (html-escaped).
// maxRunes is the provider cap (telegramTextMax); 0 = uncapped. The cap is
// measured on the ESCAPED output — that is what Telegram counts.
func stormSummaryHTML(entries []stormEntry, maxRunes int, recovery bool) string {
	header := html.EscapeString(stormSummaryHeader(
		"⚠️ pulsemon: alert storm — %d sensors changed state (coalesced to limit alert noise)",
		"✅ pulsemon: recovery storm — %d sensors recovered (coalesced to limit alert noise)", recovery, len(entries)))
	lines := make([]string, len(entries))
	for i, e := range entries {
		lines[i] = html.EscapeString(stormSummaryLine(e))
	}
	return truncateSummaryLines(header, lines, maxRunes)
}

// stormSummaryPlain renders the summary for SMTP (plain text).
// maxRunes is 0 in production (email has no practical limit).
func stormSummaryPlain(entries []stormEntry, maxRunes int, recovery bool) string {
	header := stormSummaryHeader(
		"pulsemon: alert storm — %d sensors changed state (coalesced to limit alert noise)",
		"pulsemon: recovery storm — %d sensors recovered (coalesced to limit alert noise)", recovery, len(entries))
	lines := make([]string, len(entries))
	for i, e := range entries {
		lines[i] = stormSummaryLine(e)
	}
	return truncateSummaryLines(header, lines, maxRunes)
}

// stormSummaryHeader picks the direction's header format and fills in the
// sensor count (the per-sensor lines follow in the formatters).
func stormSummaryHeader(down, recoveryFmt string, recovery bool, n int) string {
	if recovery {
		return fmt.Sprintf(recoveryFmt, n)
	}
	return fmt.Sprintf(down, n)
}

// dest is one configured provider with its resolved URL (a webhook POST
// target, or the SMTP host for the smtp kind). chatID carries the
// Telegram chat_id, resolved in resolveDestinations with the same
// error-awareness as the URL: the old code re-read it live in the
// delivery goroutine via the swallow-to-"" GetSetting, so a transient
// DB lock at delivery time posted an empty chat_id (Telegram 400) —
// fatal on the storm-summary path, which has no retry.
type dest struct {
	p      providerMeta
	url    string
	chatID string      // telegram only; "" for every other kind
	smtp   *smtpConfig // smtp kind only, resolved at snapshot load; nil elsewhere
}

// getSettingErr is the settings read resolveDestinations uses for the
// provider URLs and the Telegram chat_id. A var so tests can simulate a
// transient read failure on a specific key (same seam idiom as smtpDial);
// production is a plain DB read.
var getSettingErr = func(db *store.Store, key string) (string, error) { return db.GetSettingErr(key) }

// resolveDestinations returns the active, configured providers with their
// URLs (and, for telegram, the chat_id) from the settings SNAPSHOT. It is
// lock-free: the destinations are resolved at snapshot-load time (worker
// start + every PUT /api/settings commit), so the delivery path performs
// ZERO settings reads. ok is always true — the snapshot is never nil (a
// default is stored before the first load), so there is no "unreadable"
// state to report. The delivery job calls it through the deliverDestinations
// seam so the panic-recovery test can force a job-level panic.
func (pw *ProbeWorker) resolveDestinations() ([]dest, bool) {
	return pw.alertSettings().dests, true
}

// deliverDestinations is the seam the delivery job uses to resolve
// destinations; a var so the panic-recovery test (sendwebhook_panic_test.go)
// can force a JOB-LEVEL panic in sendWebhookDeliver — the m1 done-channel
// guarantee — independent of the per-provider recovers. Production is a
// plain snapshot read.
var deliverDestinations = func(pw *ProbeWorker) ([]dest, bool) { return pw.resolveDestinations() }

// sendWebhookDeliver delivers one alert to every active provider IN
// PARALLEL (a slow endpoint must not delay the others) and reports whether
// it was delivered: true when at least one provider accepted it, or when
// none is configured (there is nothing to retry); false only when every
// configured provider failed after its retries, so the caller can schedule
// another attempt.
func (pw *ProbeWorker) sendWebhookDeliver(id, name, target, oldState, state string, rttMs float64, reAlert bool) bool {
	// Resolve every provider destination from the SNAPSHOT before
	// delivering anything: a transient DB lock can no longer make every
	// provider look unset and the alert silently dropped (the old
	// swallow-to-"" GetSetting). Resolving up front also means no provider
	// has fired yet when we bail.
	dests, ok := deliverDestinations(pw)
	if !ok {
		// The snapshot is never nil in practice, so this is defensive: an
		// empty/unreadable destination list must be reported as NOT
		// delivered so the caller can retry — never "delivered" on an
		// empty provider list.
		log.Printf("alert: provider list unreadable — alert not delivered")
		return false
	}
	var wg sync.WaitGroup
	var delivered atomic.Bool
	for _, d := range dests {
		wg.Add(1)
		go func(d dest) {
			defer wg.Done()
			defer alertPanicRecovered("deliver-" + d.p.Kind)
			if pw.deliverOne(d, name, target, oldState, state, rttMs, reAlert) {
				delivered.Store(true)
			}
		}(d)
	}
	wg.Wait()
	return len(dests) == 0 || delivered.Load()
}

// deliverOne sends one alert to one provider and reports success. The dest
// carries everything resolved up front in resolveDestinations (URL and, for
// telegram, the chat_id) — deliverOne must not re-read settings live: a
// transient DB lock at delivery time would otherwise degrade into a
// half-configured payload
func (pw *ProbeWorker) deliverOne(d dest, name, target, oldState, state string, rttMs float64, reAlert bool) bool {
	p, url := d.p, d.url
	switch p.Kind {
	case "google_chat":
		card := cardFor(oldState, state, name, target, rttMs)
		if reAlert {
			card = cardForRe(state, name, target, rttMs)
		}
		return pw.postJSON(url, map[string]any{"text": card}) == nil
	case "discord":
		card := discordCard(oldState, state, name, target, rttMs)
		if reAlert {
			card = discordCardRe(state, name, target, rttMs)
		}
		// allowed_mentions.parse = []: never let
		// card text trigger role/user mentions — a sensor named
		// "@everyone" would otherwise mass-ping the channel. Pairs with
		// discordMentionSafe, which covers clients that ignore the field.
		return pw.postJSON(url, map[string]any{
			"content":          card,
			"allowed_mentions": map[string]any{"parse": []string{}},
		}) == nil
	case "telegram":
		card := telegramCard(oldState, state, name, target, rttMs)
		if reAlert {
			card = telegramCardRe(state, name, target, rttMs)
		}
		// d.chatID was resolved up front in resolveDestinations (see
		// dest): a live re-read here would map a transient DB lock to ""
		// and Telegram would 400 the message.
		return pw.postJSON(url, map[string]any{
			"chat_id":    d.chatID,
			"text":       card,
			"parse_mode": "HTML",
		}) == nil
	case "smtp":
		// SMTP is not a webhook POST — it dials the mail server. The url
		// variable is the host here (URLField: smtp_host); delivery is a
		// plain-text email via sendSMTP.
		subject := smtpSubject(oldState, state)
		body := smtpBody(oldState, state, name, target, rttMs)
		if reAlert {
			subject = smtpSubject(state, state) + " (re-alert)"
			body = smtpBodyRe(state, name, target, rttMs)
		}
		if d.smtp == nil {
			log.Printf("smtp alert to %s: dest carries no resolved config", url)
			return false
		}
		err := pw.retryAlert(func() (bool, time.Duration, error) {
			err := pw.sendSMTPWith(pw.stopCtx, *d.smtp, subject, body)
			// A configuration gap (no host/sender/recipient) cannot succeed
			// on retry. SMTP has no Retry-After: 0 keeps the fixed
			// alertRetryDelays.
			return err != nil && !errors.Is(err, errSMTPNotConfigured), 0, err
		})
		if err != nil {
			log.Printf("smtp alert to %s: %v", url, err)
			return false
		}
		return true
	}
	return false
}

// TestWebhook sends a test message to ONE provider and reports whether it
// accepted it. kind is required (the dashboard tests the provider whose URL
// is being verified). ctx bounds the POST (the handler passes r.Context(),
// so an abandoned dashboard request aborts the delivery at its next read
// instead of holding the client's 10s timeout).
func (pw *ProbeWorker) TestWebhook(ctx context.Context, kind string) (bool, string) {
	p, ok := providerByKey(kind)
	if !ok {
		return false, "unknown provider"
	}
	// Error-aware settings read (getSettingErr — the same seam
	// resolveDestinations uses): the test button is where an operator
	// verifies their config, so a transient DB lock must surface as a
	// database error, not masquerade as "no <provider> webhook URL
	// configured" (the swallow-to-"" GetSetting maps a lock to an empty
	// URL). p.URLField, not p.Kind+"_url": SMTP's value lives in
	// smtp_host (url is unused for SMTP — the smtp branch below uses
	// p.hasURLGet gate + sendSMTP).
	url, err := getSettingErr(pw.db, p.URLField)
	if err != nil {
		return false, "database error reading provider settings"
	}
	if url == "" && p.EnvFallback != "" {
		url = os.Getenv(p.EnvFallback)
	}
	var smtpCfg smtpConfig
	if p.Kind == "smtp" {
		// SMTP has no URL field: ONE bulk read resolves the gate
		// (smtpHasURL: host+sender+recipient) and the send config
		// together, fail-loud through the getAllSettings seam — a
		// transient lock must surface as a database error, never
		// masquerade as "no SMTP host and recipient configured" (the
		// swallow-to-"" contract) and never half-read across the gate
		// and a second per-key read.
		m, err := getAllSettings(pw.db)
		if err != nil {
			return false, "database error reading provider settings"
		}
		get := func(k string) (string, error) { return m[k], nil }
		gate, err := p.hasURLGet(get)
		if err != nil {
			return false, "database error reading provider settings"
		}
		if !gate {
			return false, "no SMTP host and recipient configured"
		}
		smtpCfg, err = smtpConfigFromGet(get)
		if err != nil {
			return false, "database error reading provider settings"
		}
	} else if url == "" {
		return false, "no " + p.Label + " webhook URL configured"
	}
	// map[string]any, not map[string]string: the discord payload nests
	// allowed_mentions — the test-alert body must be
	// structurally identical to the production delivery payloads
	// (deliverOne / deliverStormSummary), so the test button verifies the
	// exact shape the real alerts send.
	var body map[string]any
	if p.Kind == "discord" {
		body = map[string]any{
			"content":          "✅ **pulsemon: test alert**\nSensor: settings · Target: webhook-verify · State: **test** — your Discord webhook works.",
			"allowed_mentions": map[string]any{"parse": []string{}},
		}
	} else if p.Kind == "telegram" {
		// chat_id resolved error-aware (same reason as the URL above): a
		// transient DB lock must not post an empty chat_id to Telegram
		// (HTTP 400).
		chatID, err := getSettingErr(pw.db, "telegram_chat_id")
		if err != nil {
			return false, "database error reading provider settings"
		}
		body = map[string]any{
			"chat_id":    chatID,
			"text":       "✅ <b>pulsemon: test alert</b>\n<b>Sensor:</b> settings · <b>Target:</b> webhook-verify · <b>State:</b> <b>test</b> — your Telegram bot works.",
			"parse_mode": "HTML",
		}
	} else if p.Kind == "smtp" {
		// SMTP test: send a real email (no JSON body). Returns after the
		// protocol round-trip, not the shared http.Client path below.
		subject := "✅ pulsemon: test alert"
		bodyTxt := "✅ pulsemon: test alert\nSensor: settings\nTarget: webhook-verify\nState: test — your SMTP relay works."
		if err := pw.sendSMTPWith(ctx, smtpCfg, subject, bodyTxt); err != nil {
			return false, err.Error()
		}
		return true, "test email sent via " + p.Label + " (SMTP 250 OK)"
	} else {
		body = map[string]any{"text": "✅ *pulsemon: test alert*\n*Sensor*: settings\n*Target*: webhook-verify\n*State*: **test** — this message confirms your " + p.Label + " webhook works."}
	}
	// Single transport seam with postJSON (doWebhookPost): the shared
	// hardened client, the capped drain, and the URL redaction live there.
	// TestWebhook is a cold, operator-initiated path — no retry.
	code, _, err := pw.doWebhookPost(ctx, url, mustJSON(body))
	if err != nil {
		return false, err.Error()
	}
	if code >= 300 && code < 400 {
		return false, "endpoint redirected (refused to follow — possible misconfiguration)"
	}
	if code >= 300 {
		return false, fmt.Sprintf("endpoint returned HTTP %d", code)
	}
	return true, "test alert sent via " + p.Label + " (HTTP " + http.StatusText(code) + ")"
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// launchAlert runs an alert delivery in a tracked goroutine. It is NOT
// counted in wg (probe loops): a hung webhook must not stall Run's return,
// which main bounds to 10s and treats as a failure. alertWG + DrainAlerts
// give the delivery a bounded second chance after Run returns. Per-sensor
// delivery ORDERING lives in sendWebhook (which knows the sensor id) —
// see alertGate.
func (pw *ProbeWorker) launchAlert(fn func()) {
	pw.alertWG.Add(1)
	go func() {
		defer pw.alertWG.Done()
		defer alertPanicRecovered("launch-alert")
		fn()
	}()
}

// DrainAlerts waits for in-flight alert deliveries to finish, bounded by
// timeout. It is called from main AFTER Run returns and BEFORE db.Close, so
// an alert fired on the final probe tick is not killed mid-delivery.
// main calls StopAlerts first, so a delivery stuck in a network blip is
// aborted at its next read (stopCtx) instead of holding this drain for the
// client's full 10s timeout — the timeout here is a backstop only.
//
// The waiter goroutine below is intentionally untracked: sync.WaitGroup has
// no cancellable Wait, so it lingers past a timeout until alertWG drains —
// bounded and harmless (after StopAlerts cancels stopCtx, in-flight
// deliveries abort at their next read and alertWG hits zero promptly; in
// production the process exits right after this returns).
func (pw *ProbeWorker) DrainAlerts(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		pw.alertWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		log.Println("WARNING: alert drain timed out; in-flight webhook deliveries may be aborted")
	}
}

// StopAlerts cancels stopCtx, aborting any in-flight webhook POST at its
// next read. main calls it on shutdown, BEFORE DrainAlerts: without this,
// a POST stuck in a network blip would keep its connection open until the
// client's 10s timeout and hold process exit that long.
func (pw *ProbeWorker) StopAlerts() {
	pw.stopCancel()
}

// sendAlert dispatches a state-transition alert to every active provider.
func (pw *ProbeWorker) sendAlert(id, name, target, oldState, state string, rttMs float64) bool {
	return pw.sendWebhook(id, name, target, oldState, state, rttMs, false)
}

// sendRealert notifies that a sensor has stayed in the same non-up state.
// oldState == state (the re-alert is not a transition; the card just says
// "still <state>").
func (pw *ProbeWorker) sendRealert(id, name, target, state string, rttMs float64) bool {
	return pw.sendWebhook(id, name, target, state, state, rttMs, true)
}

// recoveryTitle picks the alert headline for the new status: a full
// recovery reads "recovered", an error -> warning improvement reads
// "partial recovery".
func recoveryTitle(oldState, state string) string {
	if state == "up" {
		return "recovered"
	}
	if state == "warning" && oldState == "error" {
		return "partial recovery"
	}
	return state
}

// statusIcon maps a sensor state to the alert-card emoji, matching the
// dashboard's icon language (check-circle / warning / x-circle / pause-circle).
func statusIcon(state string) string { return statusIcons[state] }

var statusIcons = map[string]string{"up": "✅", "warning": "⚠️", "error": "❌", "paused": "⏸️"}

// alertTarget renders a sensor's target for third-party alert payloads,
// stripping any userinfo AND the query/fragment from the RAW string: a
// target like https://admin:***@nas.lan/health must not go verbatim into
// the Discord/Telegram/Chat/SMTP card (the password would be readable in
// the channel), and a ?token=… is a credential carrier too. Raw-string,
// not net/url: a malformed target (legacy or hand-edited rows) fails
// Parse, and a "return verbatim" fallback would ship the credentials — the
// exact leak this function exists to prevent; and u.String() would
// percent-encode the path. No authority (bare IP/hostname) → nothing to
// strip. The authority ends at the first '/', '?' or '#' (a raw '?'/'#'
// cannot sit inside userinfo — RFC 3986), and userinfo ends at the LAST
// '@' in the authority (net/url permits a raw '@'; cutting at the first
// '@' left a password fragment in the card).
// History: docs/DECISIONS.md → alert-target-last-at, alert-target
// parse-failure redaction, target-query-redaction.
func alertTarget(target string) string {
	prefix := authorityStart(target)
	if prefix < 0 {
		return target
	}
	rest := target[prefix:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}

	// Cut the userinfo (to and including the LAST '@' in the authority)
	// and the query/fragment (from the first '?'/'#' of the remainder —
	// after the userinfo cut the remainder starts at host[:port], which
	// cannot contain '?'/'#', so the first one is the true start).
	out := rest
	if at := strings.LastIndexByte(rest[:end], '@'); at >= 0 {
		out = rest[at+1:]
	}
	if q := strings.IndexAny(out, "?#"); q >= 0 {
		out = out[:q]
	}
	return target[:prefix] + out
}

// authorityStart returns the offset just past "scheme://" (or a leading
// "//" for a scheme-relative URL) — where the authority
// (userinfo@host[:port]) begins — or -1 when the string has no
// authority (bare IP, hostname, path). The scheme check mirrors
// net/url's grammar (a letter, then [A-Za-z0-9+.-]*), so the boundary
// matches what neturl.Parse would have used.
func authorityStart(target string) int {
	if i := strings.Index(target, "://"); i > 0 && validScheme(target[:i]) {
		return i + 3
	}
	if strings.HasPrefix(target, "//") {
		return 2
	}
	return -1
}

// validScheme mirrors net/url's scheme grammar: a letter followed by any
// run of letters, digits, '+', '-', '.'.
func validScheme(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return false
	}
	for j := 1; j < len(s); j++ {
		c := s[j]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// discordMentionSafe neutralizes Discord mention tokens in free text
// a sensor named "@everyone" (or a target path
// containing the token) would fire a mass mention to the whole channel
// when the card posts. A zero-width space inserted right AFTER the @
// breaks the token for Discord's mention parser while keeping the @
// visible in the rendered card (the old code replaced the @ entirely,
// so "@everyone" rendered as "‌everyone" with no @).
// Belt-and-braces with the payload's allowed_mentions.parse = []:
// this covers clients/imports that ignore allowed_mentions.
func discordMentionSafe(s string) string {
	s = strings.ReplaceAll(s, "@everyone", "@\u200beveryone")
	s = strings.ReplaceAll(s, "@here", "@\u200bhere")
	return s
}

// mdEscape backslash-escapes the Markdown metacharacters that
// validSensorName permits: the emphasis characters * _ ~ ` (a sensor named
// db_primary_01 would otherwise render with "primary" italicized) and the
// link brackets [ ] (a sensor named "[click here](https://evil.example)" is
// legal input and would otherwise render as a masked hyperlink in the
// Discord/Google Chat cards and storm summary). The parens are deliberately
// unescaped: with the brackets neutralized no link syntax can form, so
// escaping them would be noise.
//
// Applied to SENSOR NAMES ONLY, never to targets: a target is a URL/hostname
// whose path may legally contain _ and ~, and backslash-escaping those
// injects visible backslashes into the URL and breaks the clickable link.
//
// Applied ONLY to the Markdown (google_chat/discord) builders — the
// Telegram (HTML) and SMTP (plain) paths carry the data verbatim.
// History: docs/DECISIONS.md → storm-summary-target-mention-safe.
func mdEscape(s string) string {
	return mdReplacer.Replace(s)
}

// mdReplacer is the single-pass table behind mdEscape: strings.Replacer
// applies all six mappings in one scan (no per-character intermediate
// allocations the old ReplaceAll loop made). Each replacement output carries
// a backslash, which is not itself a source character, so the single pass
// cannot re-escape its own output.
var mdReplacer = strings.NewReplacer(
	"*", "\\*",
	"_", "\\_",
	"~", "\\~",
	"`", "\\`",
	"[", "\\[",
	"]", "\\]",
)

func cardFor(oldState, state, name, target string, rttMs float64) string {
	target = alertTarget(target)
	// Escape the name (free text) only; the target is a URL/hostname and stays
	// verbatim so it renders and auto-links cleanly
	name = mdEscape(name)
	icon := statusIcon(state)
	if icon == "" {
		icon = "✅"
	}
	title := recoveryTitle(oldState, state)
	card := fmt.Sprintf("%s *pulsemon: %s*\n*Sensor*: %s\n*Target*: %s\n*State*: **%s**",
		icon, title, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n*Ping*: %d ms", int(rttMs+0.5))
	}
	return card
}

func cardForRe(state, name, target string, rttMs float64) string {
	target = alertTarget(target)
	name = mdEscape(name)
	icon := statusIcon(state)
	if icon == "" {
		icon = "✅"
	}
	card := fmt.Sprintf("%s *pulsemon: still %s (re-alert)*\n*Sensor*: %s\n*Target*: %s\n*State*: **%s** — no change, re-notifying",
		icon, state, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n*Ping*: %d ms", int(rttMs+0.5))
	}
	return card
}

// Discord uses Markdown (**bold**, no *italic* emphasis); the card is plain
// content. Same information, Discord-flavored. name/target are sanitized
// first: credentials stripped (F22) and mention tokens neutralized (F23).
func discordCard(oldState, state, name, target string, rttMs float64) string {
	// Name: mention-neutralized + emphasis-escaped (free text). Target:
	// mention-neutralized + credentials stripped, but VERBATIM (no mdEscape)
	// so the URL renders and auto-links cleanly
	name = mdEscape(discordMentionSafe(name))
	target = discordMentionSafe(alertTarget(target))
	icon := statusIcon(state)
	if icon == "" {
		icon = "✅"
	}
	title := recoveryTitle(oldState, state)
	card := fmt.Sprintf("%s **pulsemon: %s**\n**Sensor:** %s\n**Target:** %s\n**State:** %s", icon, title, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n**Ping:** %d ms", int(rttMs+0.5))
	}
	return card
}

func discordCardRe(state, name, target string, rttMs float64) string {
	name = mdEscape(discordMentionSafe(name))
	target = discordMentionSafe(alertTarget(target))
	icon := statusIcon(state)
	if icon == "" {
		icon = "✅"
	}
	card := fmt.Sprintf("%s **pulsemon: still %s (re-alert)**\n**Sensor:** %s\n**Target:** %s\n**State:** %s — no change, re-notifying", icon, state, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n**Ping:** %d ms", int(rttMs+0.5))
	}
	return card
}

// alertRetryDelays are the pauses between delivery attempts: 3 attempts
// total (now, +2s, +10s). A var so tests can shrink or clear it.
//
// Alert-retry-budget invariant (docs/DECISIONS.md → alert-retry-budget):
// these sleeps and the maxAlertRetryAfter cap run INSIDE the sensor's
// 8-slot alert-FIFO consumer, so the worst-case single job (3 webhook
// attempts × 10s client timeout + the two in-band sleeps) must stay under
// recoveryRetryDelay (60s) — above it, a degraded provider's sustained
// re-alert arrivals outrun FIFO completions, the queue saturates, and a
// dropped recovery's re-finds a full queue a minute later: the second drop
// loses the notification permanently. Pinned by
// TestInFifoRetryBudgetUnderRecoveryRetryDelay.
var alertRetryDelays = []time.Duration{2 * time.Second, 10 * time.Second}

// redactErr strips the request URL out of a net/http error. url.Error.Error()
// embeds the full URL, and every webhook URL here carries its credential
// (Telegram bot token, Discord/Chat key), so logging or returning the raw error
// would leak the secret to journald and to the browser.
func redactErr(err error) error {
	var ue *neturl.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// maxAlertRetryAfter caps a provider's Retry-After so one hostile or buggy
// header can't park a delivery goroutine (and DrainAlerts) for hours. The
// cap is deliberately SHORT: in-band retries run on the sensor's alert-FIFO
// consumer, so every second slept here lengthens the drain of EVERY later
// alert queued for that sensor (the worst job must stay under
// recoveryRetryDelay — see alertRetryDelays). When a provider asks for a
// longer backoff than the in-band cap allows, the job fails fast and the
// OUTER retry (scheduleAlertRetry / scheduleRecoveryRetry, ~1 min) re-
// offers it on a delay that respects the provider's window better than a
// second in-FIFO sleep that also congests eight queued alerts.
// History: docs/DECISIONS.md → alert-retry-budget.
const maxAlertRetryAfter = 10 * time.Second

// retryAlert runs try until it succeeds, reports a non-retryable failure, or
// the delays are exhausted. It stops sleeping the moment shutdown begins.
// try may return a server-requested retryAfter (a 429's Retry-After): the
// pause is then max(alertRetryDelays[i], retryAfter) — a rate-limited
// provider was otherwise re-hit on our fixed 2s/10s schedule regardless of
// what it asked for.
func (pw *ProbeWorker) retryAlert(try func() (retryable bool, retryAfter time.Duration, err error)) error {
	for i := 0; ; i++ {
		retryable, retryAfter, err := try()
		if err == nil || !retryable || i >= len(alertRetryDelays) {
			return err
		}
		delay := alertRetryDelays[i]
		if retryAfter > maxAlertRetryAfter {
			retryAfter = maxAlertRetryAfter
		}
		if retryAfter > delay {
			delay = retryAfter
		}
		select {
		case <-time.After(delay):
		case <-pw.stopCtx.Done():
			return err
		}
	}
}

// doWebhookPost performs ONE webhook POST with the shared hardened client
// (10s timeout, no redirects, SSRF-guarded dial — webhookClientFor) and
// returns the response status + headers. It is the single transport seam for
// both webhook writers: postJSON (alert delivery, retried) and TestWebhook
// (the settings test button, single-shot). The caller passes a pre-marshaled
// body (postJSON marshals once and reuses it across retries) and owns the
// status classification — the two callers classify differently (retry policy
// vs UI detail string). The returned error never contains the URL (it
// carries the provider credential).
func (pw *ProbeWorker) doWebhookPost(ctx context.Context, url string, body []byte) (int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, redactErr(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookClientFor(req.URL).Do(req)
	if err != nil {
		return 0, nil, redactErr(err)
	}
	defer resp.Body.Close()
	// Drain (capped) before close so the transport can reuse the
	// TLS connection for the next request to this endpoint:
	// closing an unread body marks the conn non-reusable, so every
	// alert paid a fresh handshake even to the same endpoint.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, nil
}

// postJSON delivers a JSON payload to a webhook with the shared hardened
// client (10s timeout, no redirects), retrying transient failures (network
// errors, 429, 5xx) per alertRetryDelays. The POST is bound to pw.stopCtx so
// that on shutdown a delivery stuck in a network blip - or sleeping between
// retries - is aborted promptly instead of holding DrainAlerts. The returned
// error never contains the URL (it carries the provider credential). The
// payload is map[string]any (not map[string]string) because the
// Discord provider needs a nested object — allowed_mentions
// which a string-valued map can't express.
func (pw *ProbeWorker) postJSON(url string, payload map[string]any) error {
	body, _ := json.Marshal(payload)
	err := pw.retryAlert(func() (bool, time.Duration, error) {
		code, header, err := pw.doWebhookPost(pw.stopCtx, url, body)
		if err != nil {
			return pw.stopCtx.Err() == nil, 0, err
		}
		switch {
		case code >= 300 && code < 400:
			return false, 0, errors.New("endpoint redirected (refused to follow — possible misconfiguration)")
		case code == http.StatusTooManyRequests:
			// Honor the provider's Retry-After.
			return true, parseRetryAfter(header.Get("Retry-After"), time.Now()), fmt.Errorf("endpoint returned %d", code)
		case code >= 500:
			return true, 0, fmt.Errorf("endpoint returned %d", code)
		case code >= 300:
			return false, 0, fmt.Errorf("endpoint returned %d", code)
		}
		return false, 0, nil
	})
	if err != nil {
		log.Printf("webhook: send failed: %v", err)
	}
	return err
}

// parseRetryAfter parses a Retry-After header value — integer seconds or an
// HTTP-date (relative to now) — into a duration. Unparseable, empty, or
// past values yield 0 (fall back to the fixed schedule). retryAlert applies
// the maxAlertRetryAfter cap.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		if secs > int(maxAlertRetryAfter/time.Second) {
			return maxAlertRetryAfter
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}
