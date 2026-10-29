package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// alertPanicRecovered guards the fire-and-forget alert paths (review
// 2026-10-24): before this, NO alert goroutine had a recover — a panic in
// one malformed payload crashed the entire monitor, and a panic inside a
// gate consumer killed that sensor's alerting PERMANENTLY (the FIFO's 8
// slots eventually fill and block alertMu for every sensor). A guarded
// panic logs with a stack and sacrifices the one delivery, not monitoring.
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

// enqueueAlert queues job on the sensor's alert FIFO, creating the gate
// and its consumer on first use. It reports false (and drops the job) when
// the sensor's 8-slot buffer is full, instead of blocking.
//
// The map read, the gate creation, and the send are ONE critical section
// under alertMu: the consumer's idle-exit check runs under the same lock,
// so it can never observe an empty queue and exit while a send is in
// flight — that window would orphan the job in the buffer with no reader
// (a silently dropped alert). The send is a NON-BLOCKING select, not a
// blocking one: holding alertMu across a blocking send (the old behavior)
// meant a full buffer parked the caller under the GLOBAL lock, stalling
// every other sensor's enqueue AND every idle consumer's exit check behind
// one stuck sensor for up to ~5 minutes (8 pending jobs × ~42s of
// webhook/SMTP I/O each) during provider degradation. Dropping when full
// bounds that stall at zero; the dropped alert is reported to the caller,
// which schedules a 1-minute-later retry once the queue drains. The
// consumer drains WITHOUT holding alertMu (job() is alert delivery —
// webhook/SMTP I/O), and no job takes alertMu, so there is no deadlock.
func (pw *ProbeWorker) enqueueAlert(id string, job func()) bool {
	pw.alertMu.Lock()
	defer pw.alertMu.Unlock()
	ch, ok := pw.alertOrderGates[id]
	if !ok {
		ch = make(chan func(), 8)
		pw.alertOrderGates[id] = ch
		// The idle duration is captured HERE, on the caller's goroutine,
		// and passed in: the consumer must not read the package var
		// itself. A test shrinks alertGateIdle and restores it in
		// t.Cleanup, and a consumer spawned near test end can be
		// unscheduled past that restore — the consumer reading the var
		// concurrently with the restore is a data race (caught by -race).
		// In production the var is never mutated, so the capture is
		// invisible there.
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

// alertGateConsumer drains one sensor's alert FIFO and exits after
// alertGateIdle with no queued jobs. Idle exit reaps consumers of quiet
// sensors (deleted, or simply healthy) — the channel is never closed
// (an in-flight send on a closed channel panics), so a plain
// `range ch` consumer would leak one goroutine per deleted sensor.
//
// Invariants (docs/DECISIONS.md → alert-gate): the exit check runs under
// alertMu — the same lock enqueueAlert holds across its send — so
// len(ch) == 0 under the lock means no job is queued AND no send is in
// flight; exiting drops nothing. The idle timer is local to THIS
// goroutine and idleDur arrives as a parameter — the consumer must NOT
// read the alertGateIdle package var (tests swap it; a reader outliving
// the restore is a data race, caught by -race). The Stop/drain/Reset
// below is the complete canonical pattern: a Reset without draining a
// fired value leaves a stale ready in idle.C read as a spurious
// idle-fire, and the only exit (the <-idle.C branch) is entered only
// after the timer fired AND its value was read, so no fired-but-unread
// timer is left behind and a defer idle.Stop() would be a no-op.
func (pw *ProbeWorker) alertGateConsumer(id string, ch chan func(), idleDur time.Duration) {
	idle := time.NewTimer(idleDur)
	for {
		select {
		case job := <-ch:
			// Per-job recover (review 2026-10-24): a panicking delivery
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

// alertsEnabled reports whether any alert may fire: maintenance mode
// silences everything.
func (pw *ProbeWorker) alertsEnabled() bool {
	return pw.db.GetSetting("maintenance_mode") != "1"
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

// shouldAlert applies the global alert routing rule (settings table):
// "all", "tags" (any of the sensor's tags in filter list), or "sensors"
// (id in filter list).
func (pw *ProbeWorker) shouldAlert(id string, tags []string) bool {
	scope := pw.db.GetSetting("alert_scope")
	if scope == "" {
		scope = "all"
	}
	if scope == "all" {
		return true
	}
	var items []string
	if f := pw.db.GetSetting("alert_filter"); f != "" {
		if err := json.Unmarshal([]byte(f), &items); err != nil {
			return false
		}
	}
	switch scope {
	case "tags":
		for _, t := range tags {
			for _, f := range items {
				if t == f {
					return true
				}
			}
		}
	case "sensors":
		for _, s := range items {
			if s == id {
				return true
			}
		}
	}
	return false
}

// maybeRealert re-notifies while a sensor stays in the same non-up state,
// at most once per re-alert interval (default 30 min).
func (pw *ProbeWorker) maybeRealert(c sensorConfig, status string, rttMs float64) {
	now := time.Now().UTC()
	var lastStatus, lastTs string
	err := pw.db.QueryRow("SELECT status, last_ts FROM alert_state WHERE sensor_id = ?", c.id).Scan(&lastStatus, &lastTs)
	if err != nil {
		pw.setAlertState(c.id, status, now)
		return
	}
	if lastStatus != status {
		pw.setAlertState(c.id, status, now)
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
		pw.setAlertState(c.id, status, now)
		return
	}
	if now.Sub(t) < time.Duration(pw.realertMin())*time.Minute {
		return
	}
	pw.setAlertState(c.id, status, now)
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

func (pw *ProbeWorker) setAlertState(id, status string, ts time.Time) {
	_, _ = pw.db.Exec(`INSERT INTO alert_state (sensor_id, status, last_ts) VALUES (?, ?, ?)
		ON CONFLICT(sensor_id) DO UPDATE SET status = excluded.status, last_ts = excluded.last_ts`,
		id, status, fmtTS(ts))
}

// alertRetryAfter is how soon a re-alert is retried after every provider
// failed (instead of waiting out the full re-alert interval). A var for tests.
var alertRetryAfter = time.Minute

// scheduleAlertRetry backdates alert_state.last_ts so the sustained-error
// re-alert path (maybeRealert) fires again in about alertRetryAfter. It is a
// no-op for "alert once only" (realert_min = 0), and only touches the row if it
// is still tracking the same status (a sensor that recovered meanwhile keeps
// its newer state).
func (pw *ProbeWorker) scheduleAlertRetry(id, status string) {
	m := pw.realertMin()
	if m == 0 {
		return
	}
	back := time.Duration(m)*time.Minute - alertRetryAfter
	if back < 0 {
		back = 0
	}
	_, _ = pw.db.Exec(`UPDATE alert_state SET last_ts = ? WHERE sensor_id = ? AND status = ?`,
		fmtTS(time.Now().UTC().Add(-back)), id, status)
}

// realertMin returns the re-alert interval in minutes. 0 means alert
// once only (no re-alerts). Default 30.
func (pw *ProbeWorker) realertMin() int {
	if v := pw.db.GetSetting("realert_min"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 1440 {
			return n
		}
	}
	return 30
}

// ResetAlertStates stamps every tracked sensor's alert_state to now, so
// sensors already in a bad state do not immediately re-alert right after
// maintenance mode is turned off.
func (pw *ProbeWorker) ResetAlertStates() {
	_, _ = pw.db.Exec(`UPDATE alert_state SET last_ts = ?`, tsNow())
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
	Enabled     func(db *DB) bool
	HasURL      func(db *DB) bool
}

var providerList = []providerMeta{
	{
		Kind: "google_chat", Label: "Google Chat", URLField: "google_chat_url",
		Placeholder: "https://chat.googleapis.com/v1/spaces/…/messages?key=…",
		EnvFallback: "GOOGLE_CHAT_WEBHOOK_URL",
		Enabled:     chatEnabled,
		HasURL:      chatHasURL,
	},
	{
		Kind: "discord", Label: "Discord", URLField: "discord_url",
		Placeholder: "https://discord.com/api/webhooks/…/…",
		EnvFallback: "",
		Enabled:     flagEnabled("discord"),
		HasURL:      flagHasURL("discord"),
	},
	{
		Kind: "telegram", Label: "Telegram", URLField: "telegram_url",
		Placeholder: "https://api.telegram.org/bot<TOKEN>/sendMessage",
		EnvFallback: "",
		Enabled:     flagEnabled("telegram"),
		HasURL:      telegramHasURL,
	},
	{
		Kind: "smtp", Label: "Email (SMTP)", URLField: "smtp_host",
		Placeholder: "smtp.example.com",
		EnvFallback: "",
		Enabled:     smtpEnabled,
		HasURL:      smtpHasURL,
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

// chatEnabled: google_chat's legacy default. Explicitly enabled ("1") wins;
// explicitly disabled ("0") wins; with no flag, a present URL (dashboard or
// env) keeps it active so an upgrade changes nothing. Fresh install: no URL,
// no flag → off.
func chatEnabled(db *DB) bool {
	switch db.GetSetting("google_chat_enabled") {
	case "1":
		return true
	case "0":
		return false
	}
	return chatHasURL(db)
}

// chatHasURL: the dashboard URL, falling back to the GOOGLE_CHAT_WEBHOOK_URL
// env (the pre-multi-provider mechanism, kept working).
func chatHasURL(db *DB) bool {
	if db.GetSetting("google_chat_url") != "" {
		return true
	}
	return os.Getenv("GOOGLE_CHAT_WEBHOOK_URL") != ""
}

// flagEnabled / flagHasURL: a generic provider — explicit "1" flag and a
// non-empty URL. No env fallback, no legacy default. Built as closures over
// the provider kind so each entry is self-contained.
func flagEnabled(kind string) func(db *DB) bool {
	return func(db *DB) bool { return db.GetSetting(kind+"_enabled") == "1" }
}

func flagHasURL(kind string) func(db *DB) bool {
	return func(db *DB) bool { return db.GetSetting(kind+"_url") != "" }
}

// telegramHasURL: Telegram needs BOTH the bot endpoint and a chat_id to
// deliver; a URL alone can't reach anyone.
func telegramHasURL(db *DB) bool {
	return db.GetSetting("telegram_url") != "" && db.GetSetting("telegram_chat_id") != ""
}

// activeProviders returns the enabled, URL-configured providers. The
// second return value reports whether the DB read itself succeeded
// GetSetting maps a read error to "", so a
// failing DB is indistinguishable from "no providers configured" without
// the liveness ping. On a read failure the LAST KNOWN-GOOD list is served
// from the cache; if nothing was ever loaded, it returns (nil, false) and
// the caller must report the alert NOT delivered — never "delivered" when
// nothing was sent.
func (pw *ProbeWorker) activeProviders() ([]providerMeta, bool) {
	if err := pw.db.Ping(); err != nil {
		pw.provMu.Lock()
		cached := pw.lastProviders
		pw.provMu.Unlock()
		if cached != nil {
			return cached, true
		}
		return nil, false
	}
	var out []providerMeta
	for _, p := range providerList {
		if p.Enabled(pw.db) && p.HasURL(pw.db) {
			out = append(out, p)
		}
	}
	pw.provMu.Lock()
	pw.lastProviders = out
	pw.provMu.Unlock()
	return out, true
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

// providerExtra returns a provider's non-secret, non-URL fields for the
// dashboard to pre-fill. chat_id is not a credential — the token lives in
// the masked URL — so it is returned in the clear.
func providerExtra(p providerMeta, db *DB) map[string]string {
	if p.Kind == "telegram" {
		if cid := db.GetSetting("telegram_chat_id"); cid != "" {
			return map[string]string{"chat_id": cid}
		}
	}
	if p.Kind == "smtp" {
		extra := map[string]string{}
		if v := db.GetSetting("smtp_port"); v != "" {
			extra["port"] = v
		}
		if v := db.GetSetting("smtp_from"); v != "" {
			extra["from"] = v
		}
		if v := db.GetSetting("smtp_to"); v != "" {
			extra["to"] = v
		}
		if v := db.GetSetting("smtp_username"); v != "" {
			extra["username"] = v
		}
		if v := db.GetSetting("smtp_tls_mode"); v != "" {
			extra["tls_mode"] = v
		}
		// The password is never returned in the clear. A stored password is
		// surfaced as a fixed mask ("••••••••") so the UI knows the field is
		// filled; the save path treats the mask as "unchanged" and omits it.
		if db.GetSetting("smtp_password") != "" {
			extra["password"] = "••••••••"
		}
		if len(extra) > 0 {
			return extra
		}
	}
	return nil
}

func (pw *ProbeWorker) providerStatuses() []providerStatus {
	out := []providerStatus{}
	for _, p := range providerList {
		url := pw.db.GetSetting(p.Kind + "_url")
		if p.Kind == "smtp" {
			// SMTP stores the mail server under smtp_host (not smtp_url);
			// surface it as the display URL so the UI shows the host.
			url = pw.db.GetSetting("smtp_host")
		}
		source := "none"
		if url != "" {
			source = "dashboard"
		} else if p.EnvFallback != "" && os.Getenv(p.EnvFallback) != "" {
			url = os.Getenv(p.EnvFallback)
			source = "env"
		}
		out = append(out, providerStatus{
			Kind:    p.Kind,
			Enabled: p.Enabled(pw.db),
			HasURL:  p.HasURL(pw.db),
			URL:     webhookMasked(url),
			Source:  source,
			Extra:   providerExtra(p, pw.db),
		})
	}
	return out
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
	// Storm budget: over-budget non-recovery alerts
	// are coalesced into a single storm summary instead of delivered
	// individually. A suppressed alert reports "delivered" (true) so the
	// caller schedules no retry — the summary carries it.
	if !pw.stormAdmit(id, name, target, oldState, state, rttMs) {
		return true
	}
	done := make(chan bool, 1)
	if !pw.enqueueAlert(id, func() {
		// Guarantee a `done` value even if the delivery panics: the
		// consumer's per-job recover swallows the panic (sacrifice the job,
		// keep the loop alive), but a skipped `done <-` would park this
		// caller on `<-done` forever — leaking the goroutine and its
		// alertWG count, so DrainAlerts burns the full backstop at every
		// shutdown (2026-10-24 review m1). The buffer-1 channel makes the
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
// stormBudget individual non-recovery alerts per stormWindow. Vars so
// tests can shrink them.
var (
	stormBudget = 10
	stormWindow = 30 * time.Second
)

// stormAdmit reports whether this alert may be delivered individually.
// See the stormMu field comment for the design.
func (pw *ProbeWorker) stormAdmit(id, name, target, oldState, state string, rttMs float64) bool {
	// A partial recovery (error -> warning) is a recovery: recoveryTitle
	// already renders it as a "partial recovery" card, so coalescing it
	// into a storm summary would delay good news and burn budget meant for
	// down alerts.
	if state == "up" || (oldState == "error" && state == "warning") {
		return true
	}
	pw.stormMu.Lock()
	defer pw.stormMu.Unlock()
	now := time.Now()
	if now.Sub(pw.stormWindowStart) >= stormWindow {
		pw.stormWindowStart = now
		pw.stormCount = 0
	}
	if pw.stormCount < stormBudget {
		pw.stormCount++
		return true
	}
	pw.stormQueue = append(pw.stormQueue, stormEntry{
		id: id, name: name, target: target, oldState: oldState, state: state, rttMs: rttMs,
	})
	pw.armStormFlushLocked(now)
	return false
}

// armStormFlushLocked schedules the one-shot flush of the coalesced queue
// at the end of the current storm window. Caller holds stormMu.
func (pw *ProbeWorker) armStormFlushLocked(now time.Time) {
	if pw.stormFlushArmed {
		return
	}
	pw.stormFlushArmed = true
	due := time.Until(pw.stormWindowStart.Add(stormWindow))
	if due < 0 {
		due = 0
	}
	// Track the flush in alertWG from ARM time (review 2026-10-24): the
	// arming caller is an alert path that already holds a launchAlert
	// count (sendWebhook runs inside launchAlert), so this Add can never
	// be the "Add called concurrently with Wait" case at counter 0 — an
	// untracked flush whose launchAlert Add landed after DrainAlerts'
	// Wait began was the sole instance and threw a fatal on shutdown.
	// DrainAlerts now JOINS a pending flush; the goroutine exits promptly
	// on stopCtx, so shutdown is not delayed (the queued summary still
	// drops on shutdown — StopAlerts has already aborted the network by
	// then, so there is nothing to deliver; unchanged, documented).
	pw.alertWG.Add(1)
	go func() {
		defer pw.alertWG.Done()
		defer alertPanicRecovered("storm-flush")
		select {
		case <-time.After(due):
			pw.flushStorm()
		case <-pw.stopCtx.Done():
		}
	}()
}

// flushStorm delivers the coalesced storm summary (when the queue is
// non-empty) and resets the budget for the next window.
func (pw *ProbeWorker) flushStorm() {
	pw.stormMu.Lock()
	q := pw.stormQueue
	pw.stormQueue = nil
	pw.stormFlushArmed = false
	pw.stormWindowStart = time.Time{}
	pw.stormCount = 0
	pw.stormMu.Unlock()
	if len(q) == 0 {
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
	// Drop entries that recovered before the flush: a summary line for a
	// sensor that is back up would contradict the recovery alert it raced.
	// A vanished sensor (deleted mid-storm) is kept — the operator should
	// still see it in the storm that took it down. Read the status via
	// currentStatus (in-memory first): during a storm the sensors are
	// actively probed, so lastStatus is the freshest source and reading it
	// avoids one SQLite round-trip per queued entry (2026-10-24 review).
	still := q[:0]
	for _, id := range order {
		if s, err := pw.currentStatus(id); err == nil && s == "up" {
			continue
		}
		still = append(still, latest[id])
	}
	if len(still) == 0 {
		return
	}
	pw.launchAlert(func() {
		pw.deliverStormSummary(still)
	})
}

// deliverStormSummary sends the coalesced summary to every active provider
// in parallel (same fan-out contract as sendWebhookDeliver). It is a
// global meta-alert — NOT queued on any sensor's alertGate — so it cannot
// disturb a sensor's per-sensor ordering guarantee (F4).
func (pw *ProbeWorker) deliverStormSummary(entries []stormEntry) {
	dests, ok := pw.resolveDestinations()
	if !ok {
		log.Printf("alert: storm summary (%d sensors) not delivered — provider list unreadable", len(entries))
		return
	}
	md := stormSummaryMarkdown(entries)
	subject := fmt.Sprintf("pulsemon: alert storm — %d sensors changed state", len(entries))
	body := stormSummaryPlain(entries)
	var wg sync.WaitGroup
	var delivered atomic.Bool
	for _, d := range dests {
		wg.Add(1)
		go func(p providerMeta, url string) {
			defer wg.Done()
			defer alertPanicRecovered("deliver-" + p.Kind)
			var ok bool
			switch p.Kind {
			case "google_chat":
				ok = pw.postJSON(url, map[string]interface{}{"text": md}) == nil
			case "discord":
				ok = pw.postJSON(url, map[string]interface{}{
					"content":          md,
					"allowed_mentions": map[string]interface{}{"parse": []string{}},
				}) == nil
			case "telegram":
				ok = pw.postJSON(url, map[string]interface{}{
					"chat_id":    pw.db.GetSetting("telegram_chat_id"),
					"text":       stormSummaryHTML(entries),
					"parse_mode": "HTML",
				}) == nil
			case "smtp":
				ok = pw.sendSMTP(pw.stopCtx, subject, body) == nil
			}
			if ok {
				delivered.Store(true)
			}
		}(d.p, d.url)
	}
	wg.Wait()
	if len(dests) > 0 && !delivered.Load() {
		log.Printf("alert: storm summary (%d sensors) failed on all %d providers", len(entries), len(dests))
	}
}

// stormSummaryLine renders one entry as a readable transition for the
// non-Markdown summary paths (Telegram HTML, SMTP plain), with the same
// hygiene as the per-sensor cards: credentials stripped (F22). Mention
// tokens are NOT neutralized here: those paths carry the name verbatim, and
// the invisible \u200b discordMentionSafe injects is pointless there and
// corrupts copy-paste in email clients / renders as tofu in non-UTF-8
// readers (2026-10-24 review). The Markdown path (stormSummaryMarkdown)
// builds its own line so it can escape the name without escaping the URL
// target (2026-10-28 review n4).
func stormSummaryLine(e stormEntry) string {
	return fmt.Sprintf("%s: %s → %s (%s)", e.name, e.oldState, e.state, alertTarget(e.target))
}

// stormSummaryMarkdown renders the summary for google_chat / discord.
func stormSummaryMarkdown(entries []stormEntry) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("⚠️ *pulsemon: alert storm — %d sensors changed state (coalesced to limit alert noise)*\n", len(entries)))
	for _, e := range entries {
		// Escape the emphasis chars in the NAME only (free text — a name like
		// db_primary_01 would otherwise render "primary" in italics, and a
		// raw * in the name renders as literal formatting), with mention
		// tokens neutralized (2026-10-24 review n2 + markdown). The TARGET is
		// a URL/hostname and stays VERBATIM: mdEscape would inject backslashes
		// into _ and ~ in the path and break the clickable link (2026-10-28
		// review n4). The emphasis markers come from the format string.
		b.WriteString("*" + mdEscape(discordMentionSafe(e.name)) + ": " + e.oldState + " → " + e.state + " (" + alertTarget(e.target) + ")*\n")
	}
	return b.String()
}

// stormSummaryHTML renders the summary for telegram (html-escaped).
func stormSummaryHTML(entries []stormEntry) string {
	var b strings.Builder
	b.WriteString(html.EscapeString(fmt.Sprintf("⚠️ pulsemon: alert storm — %d sensors changed state (coalesced to limit alert noise)\n", len(entries))))
	for _, e := range entries {
		b.WriteString(html.EscapeString(stormSummaryLine(e)) + "\n")
	}
	return b.String()
}

// stormSummaryPlain renders the summary for SMTP (plain text).
func stormSummaryPlain(entries []stormEntry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "pulsemon: alert storm — %d sensors changed state (coalesced to limit alert noise)\n", len(entries))
	for _, e := range entries {
		b.WriteString(stormSummaryLine(e) + "\n")
	}
	return b.String()
}

// dest is one configured provider with its resolved URL (a webhook POST
// target, or the SMTP host for the smtp kind).
type dest struct {
	p   providerMeta
	url string
}

// resolveDestinations returns the active, configured providers with their
// URLs. ok=false means the provider list is unreadable (DB error with no
// last-known-good cache) — the caller must treat the send as FAILED, not
// delivered.
func (pw *ProbeWorker) resolveDestinations() ([]dest, bool) {
	providers, readOK := pw.activeProviders()
	if !readOK {
		return nil, false
	}
	var dests []dest
	for _, p := range providers {
		// p.URLField, NOT p.Kind + "_url": SMTP's value lives in
		// "smtp_host" (see providerList), and a "smtp_url" lookup
		// returns "" for every real SMTP config — silently skipping
		// email in both the per-sensor delivery and the storm summary,
		// with sendWebhookDeliver reporting "delivered" (no dests) for
		// an alert nothing was sent in.
		url, err := pw.db.GetSettingErr(p.URLField)
		if err != nil {
			return nil, false
		}
		if url == "" && p.EnvFallback != "" {
			url = os.Getenv(p.EnvFallback)
		}
		if url == "" {
			continue
		}
		dests = append(dests, dest{p, url})
	}
	return dests, true
}

// sendWebhookDeliver delivers one alert to every active provider IN
// PARALLEL (a slow endpoint must not delay the others) and reports whether
// it was delivered: true when at least one provider accepted it, or when
// none is configured (there is nothing to retry); false only when every
// configured provider failed after its retries, so the caller can schedule
// another attempt.
func (pw *ProbeWorker) sendWebhookDeliver(id, name, target, oldState, state string, rttMs float64, reAlert bool) bool {
	// Resolve every provider URL BEFORE delivering anything. GetSetting
	// maps a DB error to "" — indistinguishable from "not configured" — so
	// a transient read failure made every provider look unset and the alert
	// was reported delivered (attempted == 0) and silently dropped. A real
	// DB error now fails the send; resolving up front
	// means no provider has fired yet when we bail.
	dests, ok := pw.resolveDestinations()
	if !ok {
		// DB unreadable and no last-known-good list: the alert CANNOT be
		// delivered, and it must be reported as such so the caller can
		// retry — never "delivered" on an empty (error-induced) provider
		// list.
		log.Printf("alert: provider list unreadable (no cache) — alert not delivered")
		return false
	}
	var wg sync.WaitGroup
	var delivered atomic.Bool
	for _, d := range dests {
		wg.Add(1)
		go func(p providerMeta, url string) {
			defer wg.Done()
			defer alertPanicRecovered("deliver-" + p.Kind)
			if pw.deliverOne(p, url, name, target, oldState, state, rttMs, reAlert) {
				delivered.Store(true)
			}
		}(d.p, d.url)
	}
	wg.Wait()
	return len(dests) == 0 || delivered.Load()
}

// deliverOne sends one alert to one provider and reports success.
func (pw *ProbeWorker) deliverOne(p providerMeta, url, name, target, oldState, state string, rttMs float64, reAlert bool) bool {
	switch p.Kind {
	case "google_chat":
		card := cardFor(oldState, state, name, target, rttMs)
		if reAlert {
			card = cardForRe(state, name, target, rttMs)
		}
		return pw.postJSON(url, map[string]interface{}{"text": card}) == nil
	case "discord":
		card := discordCard(oldState, state, name, target, rttMs)
		if reAlert {
			card = discordCardRe(state, name, target, rttMs)
		}
		// allowed_mentions.parse = []: never let
		// card text trigger role/user mentions — a sensor named
		// "@everyone" would otherwise mass-ping the channel. Pairs with
		// discordMentionSafe, which covers clients that ignore the field.
		return pw.postJSON(url, map[string]interface{}{
			"content":          card,
			"allowed_mentions": map[string]interface{}{"parse": []string{}},
		}) == nil
	case "telegram":
		card := telegramCard(oldState, state, name, target, rttMs)
		if reAlert {
			card = telegramCardRe(state, name, target, rttMs)
		}
		return pw.postJSON(url, map[string]interface{}{
			"chat_id":    pw.db.GetSetting("telegram_chat_id"),
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
		err := pw.retryAlert(func() (bool, time.Duration, error) {
			err := pw.sendSMTP(pw.stopCtx, subject, body)
			// "smtp: no host/sender/recipient configured" cannot succeed on retry.
			// SMTP has no Retry-After: 0 keeps the fixed alertRetryDelays.
			return err != nil && !strings.HasPrefix(err.Error(), "smtp: no "), 0, err
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
	url := pw.db.GetSetting(p.Kind + "_url")
	if url == "" && p.EnvFallback != "" {
		url = os.Getenv(p.EnvFallback)
	}
	if p.Kind == "smtp" {
		// SMTP has no URL field; the host+recipient gate is smtpHasURL.
		if !smtpHasURL(pw.db) {
			return false, "no SMTP host and recipient configured"
		}
	} else if url == "" {
		return false, "no " + p.Label + " webhook URL configured"
	}
	var body map[string]string
	if p.Kind == "discord" {
		body = map[string]string{"content": "✅ **pulsemon: test alert**\nSensor: settings · Target: webhook-verify · State: **test** — your Discord webhook works."}
	} else if p.Kind == "telegram" {
		body = map[string]string{
			"chat_id":    pw.db.GetSetting("telegram_chat_id"),
			"text":       "✅ <b>pulsemon: test alert</b>\n<b>Sensor:</b> settings\n<b>Target:</b> webhook-verify\n<b>State:</b> <b>test</b> — your Telegram bot works.",
			"parse_mode": "HTML",
		}
	} else if p.Kind == "smtp" {
		// SMTP test: send a real email (no JSON body). Returns after the
		// protocol round-trip, not the shared http.Client path below.
		subject := "✅ pulsemon: test alert"
		bodyTxt := "✅ pulsemon: test alert\nSensor: settings\nTarget: webhook-verify\nState: test — your SMTP relay works."
		if err := pw.sendSMTP(ctx, subject, bodyTxt); err != nil {
			return false, err.Error()
		}
		return true, "test email sent via " + p.Label + " (SMTP 250 OK)"
	} else {
		body = map[string]string{"text": "✅ *pulsemon: test alert*\n*Sensor*: settings\n*Target*: webhook-verify\n*State*: **test** — this message confirms your " + p.Label + " webhook works."}
	}
	// Errors from net/http embed the full request URL, which carries the
	// provider token: strip it before it reaches the browser or the log.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(mustJSON(body)))
	if err != nil {
		return false, redactErr(err).Error()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookClientFor(req.URL).Do(req)
	if err != nil {
		return false, redactErr(err).Error()
	}
	defer resp.Body.Close()
	// Drain (capped) before close so the shared client's per-host pool can
	// reuse the TLS connection for the next request to this endpoint —
	// closing an unread body marks the conn non-reusable (same idiom as
	// postJSON). TestWebhook is a cold, operator-initiated path, so this is
	// a minor efficiency/consistency win, not a hot-path fix.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return false, "endpoint redirected (refused to follow — possible misconfiguration)"
	}
	if resp.StatusCode >= 300 {
		return false, fmt.Sprintf("endpoint returned HTTP %d", resp.StatusCode)
	}
	return true, "test alert sent via " + p.Label + " (HTTP " + http.StatusText(resp.StatusCode) + ")"
}

func mustJSON(v interface{}) []byte {
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
// an alert fired on the final probe tick is not killed mid-delivery. main
// calls StopAlerts first, so any delivery stuck in a network blip is
// aborted at its next read (stopCtx) instead of holding this drain for the
// client's full 10s timeout — the timeout here is a backstop only.
//
// The waiter goroutine below is intentionally untracked: sync.WaitGroup has
// no cancellable Wait, so it lingers past a timeout until alertWG drains.
// That is bounded and harmless — after StopAlerts cancels stopCtx (and with
// the non-blocking enqueue, no enqueue blocks forever), in-flight deliveries
// abort at their next read and alertWG hits zero promptly. In production the
// process exits right after this returns, so a lingering waiter is moot; in
// tests it is a short-lived bounded goroutine (Go tests do not fail on it).
// There is no clean way to avoid it without redesigning the delivery
// tracking (2026-10-24 review finding #9).
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
// stripping any userinfo: an HTTP target like
// https://admin:hunter2@nas.lan/health used to go VERBATIM into the
// Discord/Telegram/Chat/SMTP card — the password readable by everyone who
// can see the channel. u.User = nil drops the credentials. A string that
// doesn't parse as a URL (an IP, a hostname) is returned unchanged —
// there is nothing to strip.
func alertTarget(target string) string {
	u, err := neturl.Parse(target)
	if err != nil || u.Scheme == "" || u.User == nil {
		return target
	}
	// Strip ONLY the userinfo, from the RAW string. u.String() would
	// percent-encode the path/query — a target like /<b>bold</b> would come
	// back as /%3Cb%3Ebold%3C/b%3E, and the card's HTML escaping would then
	// show literal %3C… to the reader instead of the escaped markup the
	// target really is (telegram_test.go pins both halves: & -> &amp; and
	// <b> -> &lt;b&gt;, with the card's own tags intact).
	// userinfo is the run between "scheme://" and the first '@' that
	// precedes any path/query/fragment separator.
	if i := strings.Index(target, "://"); i >= 0 {
		rest := target[i+3:]
		at := strings.IndexByte(rest, '@')
		firstSep := strings.IndexAny(rest, "/?#")
		if at >= 0 && (firstSep < 0 || at < firstSep) {
			return target[:i+3] + rest[at+1:]
		}
	}
	return target
}

// discordMentionSafe neutralizes Discord mention tokens in free text
// a sensor named "@everyone" (or a target path
// containing the token) would fire a mass mention to the whole channel
// when the card posts. A zero-width space inserted right AFTER the @
// breaks the token for Discord's mention parser while keeping the @
// visible in the rendered card (the old code replaced the @ entirely,
// so "@everyone" rendered as "‌everyone" with no @ — 2026-10-28 review
// n4). Belt-and-braces with the payload's allowed_mentions.parse = []:
// this covers clients/imports that ignore allowed_mentions.
func discordMentionSafe(s string) string {
	s = strings.ReplaceAll(s, "@everyone", "@\u200beveryone")
	s = strings.ReplaceAll(s, "@here", "@\u200bhere")
	return s
}

// mdEscape backslash-escapes the Markdown emphasis characters — * _ ~ ` — so
// Discord and Google Chat render them verbatim instead of as
// bold/italic/strikethrough/code (2026-10-24 review: a sensor named
// db_primary_01 would otherwise render with "primary" italicized).
//
// Applied to SENSOR NAMES ONLY, never to targets: a target is a URL/hostname
// whose path may legally contain _ and ~, and backslash-escaping those
// injects visible backslashes into the URL and breaks the clickable link
// (2026-10-28 review n4). The URL host carries no emphasis chars, and the
// intra-path _ / ~ do not trigger emphasis inside an auto-linked URL token
// on either platform, so a verbatim target is both safe and clickable.
//
// Applied ONLY to the Markdown (google_chat/discord) builders — the Telegram
// (HTML) and SMTP (plain) paths carry the data verbatim.
func mdEscape(s string) string {
	for _, c := range []string{"*", "_", "~", "`"} {
		s = strings.ReplaceAll(s, c, "\\"+c)
	}
	return s
}

func cardFor(oldState, state, name, target string, rttMs float64) string {
	target = alertTarget(target)
	// Escape the name (free text) only; the target is a URL/hostname and stays
	// verbatim so it renders and auto-links cleanly (2026-10-28 review n4).
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
	// so the URL renders and auto-links cleanly (2026-10-28 review n4).
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

// alertRetryDelays are the pauses between delivery attempts: 3 attempts total
// (now, +2s, +10s). A var so tests can shrink or clear it.
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
// header can't park a delivery goroutine (and DrainAlerts) for hours.
const maxAlertRetryAfter = 60 * time.Second

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

// postJSON delivers a JSON payload to a webhook with the shared hardened
// client (10s timeout, no redirects), retrying transient failures (network
// errors, 429, 5xx) per alertRetryDelays. The POST is bound to pw.stopCtx so
// that on shutdown a delivery stuck in a network blip - or sleeping between
// retries - is aborted promptly instead of holding DrainAlerts. The returned
// error never contains the URL (it carries the provider credential). The
// payload is map[string]interface{} (not map[string]string) because the
// Discord provider needs a nested object — allowed_mentions
// which a string-valued map can't express.
func (pw *ProbeWorker) postJSON(url string, payload map[string]interface{}) error {
	body, _ := json.Marshal(payload)
	err := pw.retryAlert(func() (bool, time.Duration, error) {
		req, err := http.NewRequestWithContext(pw.stopCtx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return false, 0, redactErr(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := webhookClientFor(req.URL).Do(req)
		if err != nil {
			return pw.stopCtx.Err() == nil, 0, redactErr(err)
		}
		defer resp.Body.Close()
		// Drain (capped) before close so the transport can reuse the
		// TLS connection for the next alert:
		// closing an unread body marks the conn non-reusable, so every
		// alert paid a fresh handshake even to the same endpoint.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		switch code := resp.StatusCode; {
		case code >= 300 && code < 400:
			return false, 0, errors.New("endpoint redirected (refused to follow — possible misconfiguration)")
		case code == http.StatusTooManyRequests:
			// Honor the provider's Retry-After.
			return true, parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()), fmt.Errorf("endpoint returned %d", code)
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
