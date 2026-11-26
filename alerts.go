package main

import (
	"encoding/json"
	"log"
	"pulsemon/internal/store"
	"runtime/debug"
	"strconv"
	"time"
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
// timeout. It is called from main (via shutdownAlerts) AFTER Run returns
// and BEFORE db.Close, so an alert fired on the final probe tick is not
// killed mid-delivery. main uses it twice: a bounded pre-abort drain (so
// fast final-tick deliveries LAND before stopCtx cancels) and a short
// post-abort backstop (StopAlerts ends in-flight deliveries at their next
// read, so a hung endpoint costs the backstop, not its full client
// timeout).
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
// next read. main calls it in shutdownAlerts AFTER the pre-abort drain:
// stopping first would cancel stopCtx under fast final-tick deliveries
// (a recovery, an armed storm summary) that had not landed yet.
func (pw *ProbeWorker) StopAlerts() {
	pw.stopCancel()
}

// shutdownAlerts is main's shutdown sequence for the alert machinery:
// let the final-tick deliveries LAND, then abort the rest. The order is
// load-bearing: the last probe tick fires its alerts (a final-tick
// recovery, an armed storm summary) as fire-and-forget goroutines that
// outlive Run's return, and stopping BEFORE the drain cancelled stopCtx
// under them — an aborted final-tick recovery (error -> up) is
// permanently lost (alert_state already says "up", and no re-alert tick
// comes for a sensor that is up), and the armed storm summary died with
// the process. A bounded pre-drain gives the quick deliveries (a LAN
// relay answers in milliseconds) their round-trip; StopAlerts then
// aborts what is genuinely hung at its next read; the short cleanup drain
// reaps the aborting jobs.
// History: docs/DECISIONS.md → shutdown-alert-drain-first.
var (
	// shutdownPreDrain bounds the pre-abort drain: long enough for a fast
	// final-tick delivery (LAN relay + SMTP round-trip), short enough that
	// a genuinely hung endpoint costs at most this much shutdown time.
	shutdownPreDrain = 3 * time.Second
	// shutdownCleanupDrain is the post-abort backstop: StopAlerts ends
	// every in-flight delivery at its next read, so a hung endpoint costs
	// this, not its full client timeout.
	shutdownCleanupDrain = 2 * time.Second
)

func shutdownAlerts(pw *ProbeWorker) {
	pw.DrainAlerts(shutdownPreDrain)
	pw.StopAlerts()
	pw.DrainAlerts(shutdownCleanupDrain)
	log.Println("Alert deliveries drained")
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
