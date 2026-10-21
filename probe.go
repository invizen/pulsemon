package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type ProbeState struct {
	id       string
	isPaused bool
	// kick wakes the sensor's probe loop early (2026-10-19 review F28):
	// SetPaused(false) sends on it so a resume probes on the loop's next
	// wake instead of waiting out the timer it was holding while paused
	// (up to a full interval, e.g. 60s). Buffered-1 so the send never
	// blocks; a nil channel (test-constructed states) simply never fires.
	kick chan struct{}
	// lastStatus is the most recently derived status for this sensor
	// (maintained by doProbe). It drives the fast-recovery rule: a sensor
	// recovering from ERROR flips back to up on a single good probe, even
	// though a flapping (loss/up/loss/up) sensor that was in WARNING does
	// not. deriveStatus reads it; doProbe writes it after each probe.
	lastStatus string
	// fastRetry is true while the sensor's status is ERROR: the probe loop
	// re-checks it on the shortened cadence (errorRetryInterval, 30s) until
	// a probe brings it back to up, then reverts to the configured interval.
	// Maintained by doProbe, read by sensorLoop under pw.mu.
	fastRetry bool
	// lastHTTPStatus is the most recent HTTP status code for an HTTP sensor
	// (nil for ICMP, or when no response has ever arrived). doProbe updates
	// it after each probe; the API reads it via LastHTTPStatus. It is NOT
	// part of the stats cache (SensorStats is type-agnostic and shared by
	// the differential test).
	lastHTTPStatus *int
	// lastCertExpiry is the server cert's NotAfter from the most recent
	// probe (HTTPS only; nil for plain HTTP or no handshake). Informational:
	// the card shows an expiry note when it is near, but it never feeds
	// status. Kept alongside lastHTTPStatus for the same reason.
	lastCertExpiry *time.Time
}

// probeEntry is one probe in the in-memory stats series: its UTC epoch second
// and its RTT in ms (nil = packet lost). The series is what makes the
// dashboard read path (GetStats) an O(1) map lookup instead of 4 SQLite
// queries per sensor — the whole point of v0.1.18.
type probeEntry struct {
	ts  int64 // UTC epoch seconds (matches CAST(strftime('%s', ts)))
	rtt *float64
	// manual marks a "Pulse Now" row: it stays in the series (sparkline
	// honesty) but is excluded from status derivation (recentFromCache
	// skips it) — see the probes.manual column.
	manual bool
}

// probeSeries is an append-only, oldest-first log of probeEntry with a
// logical `start` offset. Appending is amortized O(1); entries older than the
// 24h retention are evicted by advancing `start`, and the backing array is
// compacted only occasionally (when `start` grows large) so the common
// append path never pays an O(n) memmove.
type probeSeries struct {
	data  []probeEntry
	start int // index (into data) of the oldest live entry
}

func (ps *probeSeries) len() int { return len(ps.data) - ps.start }

// append adds a new (newest) entry and evicts entries the dashboard can never
// need. The retention is the UNION of the two windows the stats read:
//   - the 60-probe stats window keeps the LAST 60 probes even if a sensor's
//     long interval pushes them past 24h (a 1h-interval sensor's 60 probes
//     span 60h) — this is what `ORDER BY ts DESC LIMIT 60` reads;
//   - the 24h time window keeps everything within retentionSeconds for the
//     uptime/sparkline/hour fields — what `ts >= now-24h` reads.
//
// An entry is evicted only when it is BOTH beyond the last 60 AND older than
// the 24h cutoff, so the series always holds exactly the union the DB path
// returns (never fewer), and memory is bounded for fast-interval sensors.
func (ps *probeSeries) append(e probeEntry) {
	if ps.start > 0 && (ps.start >= 4096 || ps.start*2 >= len(ps.data)) {
		// Reclaim front space so future appends reuse the backing array
		// instead of reallocating every time (the classic "resliced slice
		// grows unbounded" trap).
		n := copy(ps.data, ps.data[ps.start:])
		for i := n; i < len(ps.data); i++ {
			ps.data[i] = probeEntry{} // drop *float64 refs so they can GC
		}
		ps.data = ps.data[:n]
		ps.start = 0
	}
	ps.data = append(ps.data, e)
	keep := ps.len() - 60 // everything beyond the last 60 is a candidate
	if keep < 0 {
		keep = 0
	}
	cutoff := e.ts - retentionSeconds
	for ps.start < keep && ps.data[ps.start].ts < cutoff {
		ps.data[ps.start] = probeEntry{} // release the *float64
		ps.start++
	}
}

// snapshot copies the live entries (oldest-first) into a fresh slice so a
// reader can compute stats off the shared lock without the series mutating
// mid-read.
func (ps *probeSeries) snapshot() []probeEntry {
	n := ps.len()
	out := make([]probeEntry, n)
	copy(out, ps.data[ps.start:])
	return out
}

type sensorConfig struct {
	id     string
	name   string
	target string
	// probeType is the probe transport: "icmp" (default) or "http". It
	// decides which probe probeTarget dispatches to; everything downstream
	// (status derivation, loss/jitter, sparkline, alerts) is type-agnostic.
	probeType string
	tags      []string
	intervalS int
	timeoutMS int
	lossWarn  int
	downAfter int
	// probeBroken is set by doProbe on its per-probe copy of the config when
	// THIS probe could not be attempted because the ICMP engine itself is
	// unusable (see PingResult.Broken). deriveStatus reads it so a dead probe
	// path never reads "up". It is deliberately per-probe, not a process-wide
	// counter: one sensor's per-target send error must not degrade the others.
	probeBroken bool
}

type ProbeWorker struct {
	sensors map[string]*ProbeState
	mu      sync.Mutex
	loops   map[string]context.CancelFunc
	db      *DB

	// spawnedIDs records every id this worker has ever spawned a loop for,
	// so syncSensors can tell a FIRST spawn (process start, brand-new
	// sensor) from a RESPAWN (loop dropped by the vanished pass after a
	// >5s pause, by maintenance-mode end, or by Restart after a config
	// edit). A respawn's first tick is capped at respawnFirstTickCap
	// instead of the full staggered phase: the operator explicitly
	// resumed/edited the sensor and wants data now, not up to a whole
	// interval later (2026-10-20 external review — before the cap, an
	// hourly sensor resumed after a >5s pause, or after ANY maintenance
	// mode ended, waited up to an hour for its first probe, because
	// SetPaused's F28 kick is a no-op once the sync pass has dropped the
	// paused loop). Ids are UUIDs, never reused, so the map only grows
	// with distinct sensors ever monitored (negligible); Remove deletes
	// its entry anyway.
	spawnedIDs map[string]bool

	// syncReq requests an immediate syncSensors pass (buffered 1, so the
	// non-blocking send from Restart never stalls; a second request while a
	// pass is in flight is coalesced into the next select iteration and
	// fires a follow-up pass). Restart pings it so a config edit respawns
	// the loop promptly instead of waiting out the 5s tick (2026-10-19
	// external review #2). Only the Run goroutine consumes it — syncSensors
	// stays single-goroutine, so no new locking is needed.
	syncReq chan struct{}

	// wg tracks every spawned sensorLoop so Run can't return (and thus the
	// process's db.Close() can't run) while a loop is still mid-probe. Without
	// this, cancelling the context makes Run return the instant it sees
	// ctx.Done() while N sensor loops are still alive — one of them may be
	// inside doProbe, between its INSERT and its status UPDATE. See
	// shutdown_probe_test.go for the regression this guards.
	wg sync.WaitGroup

	// alertWG tracks in-flight alert deliveries (sendAlert/sendRealert,
	// launched fire-and-forget so a slow webhook never blocks the probe
	// tick). They are NOT in wg: a hung endpoint would otherwise stall
	// Run's return up to the 10s client timeout, which main's 10s worker
	// budget would read as a failure. main drains these separately via
	// DrainAlerts after Run returns — without that, an alert fired on the
	// final probe tick dies mid-TLS-negotiation the instant db.Close() runs
	// (sendWebhook's first act is a settings read).
	alertWG sync.WaitGroup

	// stopCtx bounds in-flight webhook POSTs (postJSON). It is cancelled
	// by StopAlerts on shutdown: a POST stuck in a network blip then
	// aborts at the next read instead of stalling DrainAlerts for the
	// client's full 10s timeout. It is deliberately a SEPARATE context
	// from Run's — Run's cancel happens first so no NEW alerts start,
	// while the in-flight ones get their own bounded second chance.
	stopCtx    context.Context
	stopCancel context.CancelFunc

	// stats cache: the in-memory source of truth for the dashboard's
	// per-sensor stats (v0.1.18). Written by doProbe (one append per probe)
	// and by the startup warm-up; read by GetStats, which the API serves
	// instead of running 4 SQLite queries per sensor per poll.
	statsMu    sync.RWMutex
	statsCache map[string]*probeSeries

	// lastPulse records when each sensor last had a manual "Pulse Now",
	// enforcing a per-sensor cooldown so an unthrottled stream of pulses
	// can't starve the probe queue. Guarded by mu; cleaned up in Remove.
	lastPulse map[string]time.Time

	// alertOrderGates serializes each sensor's alert deliveries in LAUNCH ORDER
	// (2026-10-19 review F4): an "error" alert whose webhook attempt fails
	// and retries must not be delivered AFTER the sensor's later
	// "recovered" alert — a chat whose last word is "error" on a recovered
	// sensor is worse than a late alert. One lazily-started consumer
	// goroutine per sensor drains a small FIFO; jobs run strictly in queue
	// order. Guarded by alertMu. Remove drops a deleted sensor's map entry;
	// its idle consumer (blocked on the unclosed channel) is left behind —
	// one per deleted sensor, negligible at homelab sensor counts, and
	// closing the channel would panic a sender still queued on it.
	alertMu         sync.Mutex
	alertOrderGates map[string]chan func()

	// lastProviders: the last successfully loaded active-provider list
	// (2026-10-19 review N3). GetSetting maps a DB read error to "", so a
	// failing DB looks exactly like "no providers configured" — and
	// sendWebhook's len(dests)==0 branch then reports a DROPPED alert as
	// delivered. activeProviders pings the DB first; on a read failure it
	// serves this cache. Guarded by provMu.
	provMu        sync.Mutex
	lastProviders []providerMeta

	// Storm budget (2026-10-19 review M8): a global cap on individual
	// non-recovery alerts per window. When the budget is exhausted (an
	// upstream router dies and 23 sensors error within seconds), the
	// excess alerts are NOT delivered individually — they are queued and
	// emitted as ONE coalesced "storm summary" alert when the window
	// elapses, instead of N parallel bursts that trip provider 429s and
	// the retry schedule into a storm of their own. Recoveries
	// (state == "up") are ALWAYS admitted: the operator must hear a
	// recovery even mid-storm, and a storm of recoveries is far less
	// noisy than a storm of failures. Guarded by stormMu.
	stormMu          sync.Mutex
	stormWindowStart time.Time
	stormCount       int
	stormQueue       []stormEntry
	stormFlushArmed  bool
}

// retentionSeconds is how long of a probe history the in-memory series keeps.
// It must be >= the longest window the dashboard reads (24h uptime), so the
// cache never goes stale relative to a DB read. Mirrors purgeOld's 24h.
const retentionSeconds int64 = 24 * 3600

func NewProbeWorker(db *DB) *ProbeWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProbeWorker{
		sensors:         make(map[string]*ProbeState),
		loops:           make(map[string]context.CancelFunc),
		spawnedIDs:      make(map[string]bool),
		db:              db,
		syncReq:         make(chan struct{}, 1),
		statsCache:      make(map[string]*probeSeries),
		lastPulse:       make(map[string]time.Time),
		alertOrderGates: make(map[string]chan func()),
		stopCtx:         ctx,
		stopCancel:      cancel,
	}
}

// alertGate returns the FIFO job channel that serializes one sensor's
// alert deliveries, starting its consumer goroutine on first use
// (2026-10-19 review F4 — see the alertOrderGates field comment). The queue is
// small on purpose: alert cadence is bounded by the probe interval and
// realert_min, so a deep queue would only mean a wedged provider is
// stacking undeliverable alerts.
func (pw *ProbeWorker) alertGate(id string) chan func() {
	pw.alertMu.Lock()
	defer pw.alertMu.Unlock()
	ch, ok := pw.alertOrderGates[id]
	if !ok {
		ch = make(chan func(), 8)
		pw.alertOrderGates[id] = ch
		go func() {
			for job := range ch {
				job()
			}
		}()
	}
	return ch
}

// Run reconciles the probe set from the DB every 5s, plus hourly retention.
// It does NOT return until every spawned sensorLoop has also exited — a
// cancelled ctx makes this loop exit, but the per-sensor loops it spawned
// must be waited on first (wg.Wait), so the caller can treat Run's return as
// "no probe is in flight" and safely close the database.
func (pw *ProbeWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	retention := time.NewTicker(1 * time.Hour)
	defer retention.Stop()

	// Warm the shared ICMP socket now so a socket-level failure is visible
	// in healthz immediately instead of after the first probe tick.
	if _, err := getSharedConn(); err != nil {
		log.Printf("ProbeWorker: ICMP socket init: %v", err)
	}
	// Populate the stats cache from the DB so the first dashboard poll after a
	// restart serves populated cards (RTT, sparkline, 24h uptime) instead of
	// blanking them for up to an interval while probes re-accumulate. It MUST
	// run before syncSensors spawns the loops: warmStats replaces each
	// sensor's cached series wholesale, so running it after probing started
	// wiped any probe recorded during the warm window (2026-10-19 review m6).
	pw.warmStats()
	pw.syncSensors(ctx) // immediate first pass
	for {
		select {
		case <-ctx.Done():
			// Wait for every in-flight probe to finish before returning, so
			// the caller can close the DB without aborting a write. Each
			// loop's context derives from ctx (cancelled above), so each one
			// exits at its next select; wg.Wait bounds that to the slowest
			// in-flight ping + one DB round-trip.
			pw.wg.Wait()
			return
		case <-ticker.C:
			pw.syncSensors(ctx)
		case <-pw.syncReq:
			// A Restart requested an immediate re-sync (config edit):
			// run the pass now instead of waiting for the 5s tick. If a
			// pass was already in flight when the request arrived, the
			// buffered request fires this case again right after it —
			// the follow-up pass reads the post-commit row, so a stale
			// in-flight pass can never leave the install on old config.
			pw.syncSensors(ctx)
		case <-retention.C:
			pw.purgeOld()
		}
	}
}

func (pw *ProbeWorker) syncSensors(ctx context.Context) {
	rows, err := pw.db.Query(`SELECT id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, state
		FROM sensors WHERE state = 'active'`)
	if err != nil {
		log.Printf("ProbeWorker: failed to query sensors: %v", err)
		return
	}
	defer rows.Close() // top-level: closed on every return path, not just the happy one
	type activeCfg struct {
		sensorConfig
		state string
	}
	var configs []activeCfg
	// partial is true when the read could not be completed (a row failed to
	// scan, or the cursor errored mid-iteration). The sensor set is then
	// incomplete, so the "stop loops for vanished sensors" pass below must be
	// skipped: otherwise a healthy sensor whose row merely failed to read this
	// time would have its loop cancelled and its ProbeState deleted.
	partial := false
	for rows.Next() {
		var c activeCfg
		if err := rows.Scan(&c.id, &c.name, &c.target, &c.probeType, &c.intervalS, &c.timeoutMS, &c.lossWarn, &c.downAfter, &c.state); err != nil {
			log.Printf("ProbeWorker: skipping unreadable sensor row: %v", err)
			partial = true
			continue
		}
		if c.probeType == "" {
			c.probeType = "icmp" // legacy rows pre-migration
		}
		configs = append(configs, c)
	}
	if err := rows.Err(); err != nil {
		log.Printf("ProbeWorker: sensor query ended early: %v", err)
		partial = true
	}

	// ONE batched tag query after the loop — never a per-sensor query inside
	// rows.Next(): the outer iteration holds a pooled connection, and nested
	// per-row queries starve the pool (deadlock risk under concurrency).
	ids := make([]string, len(configs))
	for i := range configs {
		ids[i] = configs[i].id
	}
	tagMap := pw.db.SensorTagsFor(ids)
	for i := range configs {
		configs[i].tags = tagMap[configs[i].id]
	}

	pw.mu.Lock()
	defer pw.mu.Unlock()

	// Fresh state read UNDER the lock (2026-10-19 review F28): the config
	// read above ran before pw.mu and can be arbitrarily stale by apply
	// time — an operator pause landing in that gap would be clobbered by
	// the stale 'active' row (the loop would keep probing a DB-paused
	// sensor). Re-read the state column for exactly this id set, batched,
	// so the pause sync applies the freshest state the DB has. A missing
	// id (row deleted in the gap) stays on the pre-lock value; the
	// vanished-sensor pass below handles it on the next pass.
	freshState := pw.freshStates(ids)

	seen := make(map[string]bool, len(configs))
	for _, c := range configs {
		seen[c.id] = true
		state := c.state
		if s, ok := freshState[c.id]; ok {
			state = s
		}
		ps, ok := pw.sensors[c.id]
		if !ok {
			ps = &ProbeState{id: c.id, isPaused: state == "paused", kick: make(chan struct{}, 1)}
			pw.sensors[c.id] = ps
		} else {
			ps.isPaused = state == "paused" // keep pause in sync with DB (fresh read, F28)
		}
		if _, ok := pw.loops[c.id]; !ok {
			// Re-read the row UNDER the lock (2026-10-19 external review #2,
			// closes the M1b TOCTOU): configs was read from the DB above,
			// before pw.mu — a PATCH+Restart landing in that gap would
			// otherwise respawn here with the pre-read cfg, and the next
			// sync won't respawn (loop exists), so the sensor would run the
			// stale config until process restart. The under-lock re-read
			// returns the freshest committed row, so a spawned loop always
			// carries config that is current at spawn time. A row deleted
			// in the gap is skipped — the vanished-sensor pass owns deleted
			// ids. A read ERROR falls back to the pre-read cfg (probe with
			// slightly stale config rather than drop the loop); the next
			// pass retries.
			cfg, found, err := pw.freshConfig(c.id)
			if err != nil {
				log.Printf("ProbeWorker: fresh config read for %s failed: %v (using pre-read cfg)", c.id, err)
				cfg = c.sensorConfig
			}
			if !found {
				continue
			}
			// First spawn vs RESPAWN (see the spawnedIDs field): a
			// respawned loop — resume after a >5s pause, maintenance-mode
			// end, config-edit Restart — caps its first tick at
			// respawnFirstTickCap so the sensor is not dark for up to a
			// whole interval (2026-10-20 external review).
			if pw.spawnedIDs == nil { // bare test workers
				pw.spawnedIDs = make(map[string]bool)
			}
			resumed := pw.spawnedIDs[c.id]
			pw.spawnedIDs[c.id] = true
			lctx, lcancel := context.WithCancel(ctx)
			pw.loops[c.id] = lcancel
			pw.wg.Add(1)
			go func() {
				defer pw.wg.Done()
				pw.sensorLoop(lctx, cfg, resumed)
			}()
		}
	}

	// Stop loops for sensors that vanished or were deleted (only when we saw
	// the complete set - see partial above).
	for id, cancel := range pw.loops {
		if !partial && !seen[id] {
			cancel()
			delete(pw.loops, id)
			delete(pw.sensors, id)
		}
	}
}

// freshStates re-reads the state column for exactly the given sensor ids,
// batched in inQueryChunk (2026-10-19 review F28). syncSensors calls it
// under pw.mu: the pre-lock config read can be arbitrarily stale by apply
// time (an operator pause landing in the read→apply gap would otherwise be
// clobbered by the stale row), so the pause sync uses this fresh read. A
// missing id (row deleted in the gap) is simply absent from the map.
func (pw *ProbeWorker) freshStates(ids []string) map[string]string {
	out := make(map[string]string, len(ids))
	for i := 0; i < len(ids); i += inQueryChunk {
		end := i + inQueryChunk
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[i:end]
		q := make([]string, len(chunk))
		args := make([]any, len(chunk))
		for j, id := range chunk {
			q[j] = "?"
			args[j] = id
		}
		rows, err := pw.db.Query(`SELECT id, state FROM sensors WHERE id IN (`+strings.Join(q, ",")+`)`, args...)
		if err != nil {
			log.Printf("ProbeWorker: fresh state read failed: %v", err)
			continue
		}
		for rows.Next() {
			var id, state string
			if rows.Scan(&id, &state) == nil {
				out[id] = state
			}
		}
		rows.Close()
	}
	return out
}

// freshConfig re-reads one sensor's spawn config from the DB (2026-10-19
// external review #2): syncSensors calls it UNDER pw.mu in the respawn
// branch, where the pre-lock configs slice can be arbitrarily stale (a
// PATCH+Restart lands in the read→apply gap). Returns the row's CURRENT
// values plus its tags; found=false when the row was deleted in the gap
// (the caller skips the spawn — the vanished-sensor pass owns deleted
// ids). Mirrors syncSensors' pre-lock SELECT column set exactly.
func (pw *ProbeWorker) freshConfig(id string) (sensorConfig, bool, error) {
	var c sensorConfig
	err := pw.db.QueryRow(`SELECT id, name, target, type, interval_s, timeout_ms, loss_warn, down_after
		FROM sensors WHERE id = ?`, id).
		Scan(&c.id, &c.name, &c.target, &c.probeType, &c.intervalS, &c.timeoutMS, &c.lossWarn, &c.downAfter)
	if err == sql.ErrNoRows {
		return c, false, nil
	}
	if err != nil {
		return c, false, err
	}
	if c.probeType == "" {
		c.probeType = "icmp" // legacy rows pre-migration
	}
	c.tags = pw.db.SensorTagsFor([]string{id})[id]
	return c, true, nil
}

// SetPaused flips the in-memory pause flag immediately (API PATCH fast path).
// A resume (paused=false) also KICKS the sensor's loop (2026-10-19 review
// F28): the loop's timer was holding a full interval while the sensor was
// paused, so without the kick the first probe after a resume would be up to
// a whole interval late (60s on a 60s sensor). The kick makes the loop
// re-evaluate and probe on its next wake.
//
// Scope: the kick only reaches a LIVE loop. The sync pass drops paused
// sensors within ~5s (the vanished pass deletes loop + state), so a resume
// after a longer pause finds no entry here and the kick is a no-op — the
// sensor is then RESPAWNED by the next syncSensors pass, and the respawn
// path caps the first tick at respawnFirstTickCap (1s) so the resume delay
// is bounded the same way (2026-10-20 external review: before that cap,
// an hourly sensor resumed after a >5s pause — or after ANY maintenance
// mode ended — waited up to an hour for its first probe).
func (pw *ProbeWorker) SetPaused(id string, paused bool) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	ps, ok := pw.sensors[id]
	if !ok {
		return
	}
	ps.isPaused = paused
	if !paused && ps.kick != nil {
		// Non-blocking: the buffer absorbs one pending kick; a second
		// resume while the first is still queued is a no-op (the loop is
		// already woken).
		select {
		case ps.kick <- struct{}{}:
		default:
		}
	}
}

// Restart respawns a sensor's probe loop so config changes take effect
// without a process restart: target/interval/timeout are read by the loop
// and loss_warn/down_after by deriveStatus, all from the spawn-time config
// copy captured in syncSensors.
//
// Deliberate: cancel + delete + SIGNAL. The respawn is the NEXT syncSensors
// pass — now requested IMMEDIATELY via the syncReq channel (Run's select
// runs it on the next iteration) instead of waiting out the 5s tick
// (2026-10-19 external review #2). The <=5s + staggered-phase gap the old
// passive design left is closed (and the respawn's first tick is capped at
// respawnFirstTickCap, so a config edit is not dark for up to a full
// interval — 2026-10-20 external review); the DB is still the source of
// truth and deriveStatus re-derives state from probe history on the next
// probe. This
// is the documented M2 design (see api_restart_test.go), with the
// immediate-sync extension.
//
// Security/concurrency-review note (deliberate, do NOT "fix" by re-spawning
// in Restart): there is NO duplicate-loop race and NO map race. pw.loops is
// guarded by pw.mu at every access (syncSensors, Restart, Remove,
// ActiveCount); syncSensors runs on a SINGLE goroutine (only Run's first
// pass + its ticker call it - API handlers call Restart/Remove, never
// syncSensors); and an old sensorLoop's cleanup on ctx.Done() just returns
// and never touches pw.loops, so the "old loop cleaning up while the new
// one spawns" case has nothing to race on. A duplicate entry cannot form:
// the spawn is guarded by `if _, ok := pw.loops[id]; !ok` under the same
// lock that deletes it. The only real overlap (an old loop mid-doProbe when
// a new one spawns) writes ONE shared *ProbeState at pw.sensors[id] under
// the mutex (doProbe) - two goroutines, one object, locked. Correct.
//
// CRITICAL invariant a naive "re-spawn in Restart" fix breaks: every loop
// is a CHILD of Run's ctx (see syncSensors: WithCancel(ctx)). Run's
// shutdown path does `case <-ctx.Done(): pw.wg.Wait()` and RELIES on every
// loop being a child of that ctx so it exits at its next select. Spawning
// with context.WithCancel(context.Background()) (as a proposed review fix
// did) SEVERS that: the Background-parented loop is never cancelled by
// ctx.Done(), so Run's wg.Wait() HANGS FOREVER for any sensor that was ever
// restarted - the process can no longer shut down or close the DB. If the
// <=5s respawn gap is ever worth closing, the safe form is: re-read config
// from the DB, delete pw.sensors[id] first, and spawn under the EXISTING
// Run ctx (never Background) - keeping the mutex discipline and the
// shutdown invariant intact.
func (pw *ProbeWorker) Restart(id string) {
	pw.mu.Lock()
	if cancel, ok := pw.loops[id]; ok {
		cancel()
		delete(pw.loops, id)
	}
	delete(pw.sensors, id)
	pw.mu.Unlock()
	// Request an IMMEDIATE sync pass: Run's select runs it on the next
	// iteration and respawns the loop with the post-commit config, so a
	// config edit no longer waits out the 5s tick (2026-10-19 external
	// review #2). The spawn re-reads the row under pw.mu (see the
	// syncSensors respawn branch), so even a sync pass that started before
	// this commit can't respawn a stale config. Non-blocking: a request
	// already queued is enough — the follow-up pass will see this change.
	select {
	case pw.syncReq <- struct{}{}:
	default:
	}
}

// Remove drops a deleted sensor's loop and state.
func (pw *ProbeWorker) Remove(id string) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if cancel, ok := pw.loops[id]; ok {
		cancel()
		delete(pw.loops, id)
	}
	delete(pw.sensors, id)
	delete(pw.spawnedIDs, id) // nil-map delete is a safe no-op
	delete(pw.lastPulse, id)
	// Drop the cached stats series too, or a deleted sensor's 24h history
	// stays pinned in memory for the process lifetime (2026-10-19 review
	// m1). Lock order: pw.mu (held) then pw.statsMu — see ResetStatsFor.
	pw.statsMu.Lock()
	delete(pw.statsCache, id)
	pw.statsMu.Unlock()
	// Same for the per-sensor alert gate (2026-10-19 review F4): drop the
	// map entry so the channel isn't pinned by the map. The idle consumer
	// goroutine (blocked on the unclosed channel) is left behind — see the
	// alertOrderGates field comment for why the channel is not closed.
	pw.alertMu.Lock()
	delete(pw.alertOrderGates, id)
	pw.alertMu.Unlock()
}

// ActiveCount is the number of sensor loops currently tracked (healthz).
func (pw *ProbeWorker) ActiveCount() int {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	return len(pw.loops)
}

// ---------- in-memory stats cache (v0.1.18) ----------
//
// The dashboard polls GET /api/sensors every 5s. Pre-v0.1.18 each poll ran
// 4 SQLite queries PER sensor (60-probe window, 1h loss/avg, 24h uptime, 1h
// sparkline) — 2 + 4N round-trips per poll, contending with the probe write
// transactions. The cache moves that load out of the read path: doProbe
// appends each result to a per-sensor in-memory series, and GetStats computes
// the same SensorStats from that series in a single map lookup + in-memory
// scan. The DB stays the durable source of truth (probe INSERT is unchanged);
// the cache is a read model, rebuilt from the DB at startup.

// warmStats loads every active sensor's 24h probe history into the cache so a
// fresh process (deploy/restart) serves populated cards immediately instead of
// blanking them until each sensor re-accumulates a window. Runs once, before
// probing starts (Run calls it before the first syncSensors — 2026-10-19
// review m6).
func (pw *ProbeWorker) warmStats() {
	ids, err := pw.db.Query("SELECT id FROM sensors WHERE state = 'active'")
	if err != nil {
		log.Printf("stats warm: failed to list sensors: %v", err)
		return
	}
	defer ids.Close()
	var idList []string
	for ids.Next() {
		var id string
		if ids.Scan(&id) == nil {
			idList = append(idList, id)
		}
	}
	if err := ids.Err(); err != nil {
		log.Printf("stats warm: sensor list ended early: %v", err)
	}

	// One batched fetch for all sensors (never a per-sensor query in a loop —
	// same pool-starvation rule as SensorTagsFor), oldest-first, so each
	// series is built in append order. The load is the UNION of the two
	// windows the stats read: the last 60 probes PER sensor (a slow-interval
	// sensor's window can span >24h) plus the full 24h retention — matching
	// exactly what the live series will hold, so a fresh process serves the
	// same window the DB path would have.
	//
	// Branch 1 (last 60 per sensor, ROW_NUMBER) must be UNRESTRICTED by the
	// 24h cutoff: the "last 60" window is the 60 most recent probes
	// OVERALL, and for a sensor whose recent probes are fewer than 60 it
	// reaches back past the cutoff. The 24h branch then overlaps it, so the
	// two branches are combined with a deduping UNION — a UNION ALL would
	// emit the overlapping recent rows twice and grow the series past 60
	// (warmstats_union_test.go pins this). The dedupe cost is a one-time
	// startup expense; the alternative (a disjoint split) is inexpressible,
	// because how far back the last-60 window reaches depends on each
	// sensor's own row counts (2026-10-19 review F29 — the UNION ALL "fix"
	// was reverted for breaking this contract).
	// The query has two IN-clauses (last-60 part + 24h part), so the id list
	// appears twice, followed by the 24h cutoff. It runs in inQueryChunk
	// batches (see db.go): 2*inQueryChunk+1 params per chunk stays far under
	// the driver's 32,766 host-parameter limit, so a very large fleet can't
	// fail the warm-up with "too many SQL variables". Partitioning by sensor
	// id keeps each sensor's rows in exactly one chunk, so per-sensor order is
	// preserved. The closure defers the cursor close per chunk — top-level
	// defer, not a bare close below a loop — so no pooled connection is held
	// across chunks.
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	type acc struct {
		series *probeSeries
	}
	byID := make(map[string]*acc, len(idList))
	var built int
	fetchChunk := func(chunk []string) {
		q := make([]string, len(chunk))
		for i := range q {
			q[i] = "?"
		}
		args := make([]any, 0, len(chunk)*2+1)
		for _, id := range chunk {
			args = append(args, id)
		}
		for _, id := range chunk {
			args = append(args, id)
		}
		args = append(args, fmtTS(cutoff))
		rows, err := pw.db.Query(
			`SELECT sensor_id, ts, rtt_ms FROM (
				SELECT sensor_id, ts, rtt_ms,
				       ROW_NUMBER() OVER (PARTITION BY sensor_id ORDER BY ts DESC) AS rn
				FROM probes WHERE sensor_id IN (`+strings.Join(q, ",")+`)
			) WHERE rn <= 60
			UNION
			SELECT sensor_id, ts, rtt_ms FROM probes
			WHERE sensor_id IN (`+strings.Join(q, ",")+`) AND ts >= ?
			ORDER BY sensor_id, ts`, args...)
		if err != nil {
			log.Printf("stats warm: chunk fetch failed: %v", err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var sid string
			var ts time.Time
			var rtt *float64
			if err := rows.Scan(&sid, &ts, &rtt); err != nil {
				continue
			}
			a, ok := byID[sid]
			if !ok {
				a = &acc{series: &probeSeries{}}
				byID[sid] = a
			}
			a.series.append(probeEntry{ts: ts.UTC().Unix(), rtt: rtt})
			built++
		}
		if err := rows.Err(); err != nil {
			log.Printf("stats warm: chunk read ended early: %v", err)
		}
	}
	for i := 0; i < len(idList); i += inQueryChunk {
		end := i + inQueryChunk
		if end > len(idList) {
			end = len(idList)
		}
		fetchChunk(idList[i:end])
	}
	pw.statsMu.Lock()
	for sid, a := range byID {
		pw.statsCache[sid] = a.series
	}
	pw.statsMu.Unlock()
	log.Printf("stats warm: loaded %d probes for %d sensors", built, len(byID))
}

// recordProbe appends a fresh probe result to the cache. Called from doProbe
// right after the DB insert succeeds, so cache and DB stay in lockstep. The
// map is created lazily so a ProbeWorker built by a test without
// NewProbeWorker (which leaves statsCache nil) can't panic.
//
// The write lock is held across the whole read-create-append so the series is
// never observed or mutated in a half-built state. This is what keeps
// recordProbe's append and statsFor's snapshot mutually exclusive: an
// RWMutex's write lock excludes its read locks, so a dashboard read can't
// snapshot mid-append even though probeSeries carries no lock of its own.
func (pw *ProbeWorker) recordProbe(id string, e probeEntry) {
	pw.statsMu.Lock()
	defer pw.statsMu.Unlock()
	if pw.statsCache == nil {
		pw.statsCache = make(map[string]*probeSeries)
	}
	s, ok := pw.statsCache[id]
	if !ok {
		// Sensor isn't in the cache yet (added after warm-up). Create it.
		s = &probeSeries{}
		pw.statsCache[id] = s
	}
	s.append(e)
}

// statsFor computes a sensor's SensorStats from the in-memory series,
// anchored at nowUnix. GetStats calls it with time.Now().Unix(); tests call
// it directly with a fixed now so the time-window fields (1h, 24h, sparkline)
// compare deterministically against the DB reference.
func (pw *ProbeWorker) statsFor(id string, nowUnix int64) *SensorStats {
	// Compute under the read lock directly over the live slice: appends take
	// the write lock, so the series cannot mutate mid-read, and
	// computeSensorStats only reads (the *float64 values it keeps are
	// immutable). This avoids copying up to 24h of entries (1.4 MB for a
	// 1s sensor) per sensor per dashboard poll.
	pw.statsMu.RLock()
	defer pw.statsMu.RUnlock()
	s, ok := pw.statsCache[id]
	if !ok || s.len() == 0 {
		return nil
	}
	return computeSensorStats(s.data[s.start:], nowUnix)
}

// GetStats computes a sensor's SensorStats from the in-memory series,
// anchored to the wall clock. Returns nil when the sensor has no data
// (matches the DB path, which returns nil for a zero-probe window).
// Pure read — no DB.
func (pw *ProbeWorker) GetStats(id string) *SensorStats {
	return pw.statsFor(id, time.Now().Unix())
}

// ResetStatsFor empties one sensor's cached series AND its in-memory
// ProbeState (used by the clear-history endpoint so neither the cache nor
// the loop state outlives the DB rows it mirrors). Without the ProbeState
// reset, a cleared failing HTTP sensor keeps serving its stale
// lastHTTPStatus (the card shows "up" with an "HTTP 503" badge) and its
// fastRetry cadence until the next probe tick overwrites them. isPaused is
// deliberately untouched — pause is operator state, not history.
// Lock order: pw.mu (ProbeState) then pw.statsMu (cache); the only other
// path taking both (Remove) uses the same order, so it can't invert.
func (pw *ProbeWorker) ResetStatsFor(id string) {
	pw.mu.Lock()
	if ps, ok := pw.sensors[id]; ok {
		ps.lastStatus = ""
		ps.fastRetry = false
		ps.lastHTTPStatus = nil
		ps.lastCertExpiry = nil
	}
	pw.mu.Unlock()
	pw.statsMu.Lock()
	delete(pw.statsCache, id)
	pw.statsMu.Unlock()
}

// ResetStatsAll empties every sensor's cached series and ProbeState
// (clear-all-history). Same field set and lock order as ResetStatsFor.
func (pw *ProbeWorker) ResetStatsAll() {
	pw.mu.Lock()
	for _, ps := range pw.sensors {
		ps.lastStatus = ""
		ps.fastRetry = false
		ps.lastHTTPStatus = nil
		ps.lastCertExpiry = nil
	}
	pw.mu.Unlock()
	pw.statsMu.Lock()
	pw.statsCache = make(map[string]*probeSeries)
	pw.statsMu.Unlock()
}

// computeSensorStats turns a sensor's probe history (oldest-first) into the
// dashboard's SensorStats. This is the single source of truth for the stats
// math — the in-memory read path (GetStats) and the differential test both go
// through it, and it mirrors the field semantics of the pre-v0.1.18 SQL
// queries exactly:
//
//   - the 60-probe window (total/loss/rtt min/avg/max/recent) is the LAST 60
//     probes regardless of age, matching `ORDER BY ts DESC LIMIT 60`;
//   - the past-hour (hour_loss_pct, hour_rtt_avg, sparkline) and 24h uptime
//     fields use time windows relative to nowUnix, matching the SQL
//     `ts >= datetime('now', '-1 hour' / '-1 day')` filters.
//
// nowUnix (epoch seconds) is the "current time" the time windows anchor to.
// GetStats passes time.Now().Unix(); the differential test passes a fixed
// value to both the SQL and in-memory paths so they compare deterministically
// (no flake from a minute-boundary crossing mid-test). A nil rtt is a lost
// probe (matches SQL `rtt_ms IS NULL`).
func computeSensorStats(entries []probeEntry, nowUnix int64) *SensorStats {
	if len(entries) == 0 {
		return nil
	}
	var st SensorStats
	var min, max, sum float64
	have := false

	// 60-probe window: the last 60 probes (oldest-first slice), then scanned
	// newest-first to match the original ROW_NUMBER() ordering.
	window := entries
	if len(window) > 60 {
		window = window[len(window)-60:]
	}
	st.Total = len(window)
	for i := len(window) - 1; i >= 0; i-- {
		rtt := window[i].rtt
		if st.RTTLast == nil && rtt != nil { // first non-lost from the newest
			v := *rtt
			st.RTTLast = &v
		}
		if len(st.Recent) < 30 {
			st.Recent = append(st.Recent, rtt)
		}
		if rtt == nil {
			st.LostCount++
			continue
		}
		v := *rtt
		if !have {
			min, max, have = v, v, true
		} else {
			if v < min {
				min = v
			}
			if v > max {
				max = v
			}
		}
		sum += v
	}
	if st.Total > 0 {
		st.LossPct = float64(st.LostCount) / float64(st.Total) * 100
	}
	if have {
		mn, mx, avg := min, max, sum/float64(st.Total-st.LostCount)
		st.RTTMin, st.RTTMax, st.RTTAvg = &mn, &mx, &avg
	}

	// Past-hour loss % + avg RTT.
	h1, l1 := 0, 0
	var h1sum float64
	for _, e := range entries {
		if e.ts >= nowUnix-3600 {
			h1++
			if e.rtt == nil {
				l1++
			} else {
				h1sum += *e.rtt
			}
		}
	}
	if h1 > 0 {
		st.HourLossPct = float64(l1) / float64(h1) * 100
		if h1-l1 > 0 {
			avg := h1sum / float64(h1-l1)
			st.HourRTTAvg = &avg
		}
	}

	// Status-window loss: the SAME window deriveStatus uses, so the inspector
	// can show the number the badge actually came from. Fewer than
	// statusWindow probes (a new sensor) just means a shorter window.
	// deriveStatus reads warning at/above this loss%, up below it (steady
	// state on the newest 2, or a single blip); only the fast-recovery
	// shortcut from error bypasses the % entirely.
	st.StatusWindowSize = statusWindow
	sw := entries
	if len(sw) > statusWindow {
		sw = sw[len(sw)-statusWindow:]
	}
	for _, e := range sw {
		if e.rtt == nil {
			st.StatusLostCount++
		}
	}
	if len(sw) > 0 {
		st.StatusLossPct = float64(st.StatusLostCount) / float64(len(sw)) * 100
	}

	// 24h uptime.
	d24, l24 := 0, 0
	for _, e := range entries {
		if e.ts >= nowUnix-86400 {
			d24++
			if e.rtt == nil {
				l24++
			}
		}
	}
	if d24 > 0 {
		st.Uptime24h = float64(d24-l24) / float64(d24) * 100
	}

	// Past-1-hour sparkline: 60 fixed one-minute buckets, oldest -> newest.
	// Bucket = min RTT in that minute; nil = probes existed, all lost; the -2
	// sentinel marks a minute with no probes (a sensor newer than 1h).
	nd := -2.0
	st.Hour = make([]*float64, 60)
	for i := range st.Hour {
		st.Hour[i] = &nd
	}
	type bmin struct {
		minRTT float64
		hasRTT bool
		hasAny bool
	}
	buckets := make([]bmin, 60)
	nowMin := nowUnix / 60 * 60
	for _, e := range entries {
		if e.ts < nowUnix-3600 || e.ts > nowUnix {
			continue
		}
		// Floor the probe to its minute FIRST (matching SQL's
		// strftime('%s',ts)/60*60), then offset from the now-minute. Skipping
		// the floor would put a probe 30s before a minute boundary into the
		// following minute's bucket.
		bucket := e.ts / 60 * 60
		pos := 59 - int((nowMin-bucket)/60)
		if pos < 0 || pos > 59 {
			continue
		}
		b := &buckets[pos]
		b.hasAny = true
		if e.rtt != nil {
			v := *e.rtt
			if !b.hasRTT || v < b.minRTT {
				b.minRTT = v
				b.hasRTT = true
			}
		}
	}
	for i := range buckets {
		if buckets[i].hasRTT {
			v := buckets[i].minRTT
			st.Hour[i] = &v // at least one reply this minute
		} else if buckets[i].hasAny {
			st.Hour[i] = nil // probes existed, all lost
		}
	}

	if st.Total == 0 {
		return nil
	}
	return &st
}

func (pw *ProbeWorker) sensorLoop(ctx context.Context, c sensorConfig, resumed bool) {
	interval := time.Duration(c.intervalS) * time.Second
	if interval <= 0 {
		interval = time.Minute // a zeroed row must not divide by zero or spin
	}

	// Stagger the first tick by a deterministic per-sensor phase (hash of the
	// id, 0 .. interval). Without this, every sensor added at the same time —
	// or every sensor sharing an interval — fires on the same wall-clock second,
	// producing a write thundering-herd against SQLite. Spreading the phases
	// turns N simultaneous writes into N writes spread across the interval.
	//
	// RESPAWN exception (resumed, set by syncSensors via spawnedIDs): the
	// operator just resumed this sensor (pause >5s, maintenance-mode end)
	// or edited its config (Restart), so a full phase here would leave it
	// dark for up to a whole interval — an hour on an hourly sensor, with
	// no data, no status, and no alerts in between. Cap the first tick at
	// respawnFirstTickCap; see that constant for the anti-herd tradeoff.
	phase := staggerPhase(c.id, interval)
	if resumed && phase > respawnFirstTickCap {
		phase = respawnFirstTickCap
	}

	// Timer (not ticker) so the next-tick delay can adapt: a sensor in
	// ERROR is re-checked on the fast-retry cadence (errorRetryInterval,
	// capped at the configured interval so it is never FASTER than normal —
	// a 15s-interval sensor keeps its 15s during error, a 60s sensor
	// re-checks every 30s) until a probe brings it back to up, then reverts
	// to the configured interval. The 10s floor makes a ping-storm
	// impossible: even if every sensor errors at once, total load is at
	// most 2x the normal load, and each sensor keeps its staggered phase
	// (no re-synchronization into a burst).
	timer := time.NewTimer(phase)
	defer timer.Stop()
	var nextDelay time.Duration

	for {
		// Grab the kick channel under the lock so a state swap (Restart/
		// Remove replacing pw.sensors[id]) can't leave us selecting on a
		// stale channel. A nil kick (test-constructed state) is a case
		// that never fires.
		pw.mu.Lock()
		kick := struct{ ch chan struct{} }{}
		if ps, ok := pw.sensors[c.id]; ok {
			kick.ch = ps.kick
		}
		pw.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-kick.ch:
			// Resume fast path (2026-10-19 review F28): SetPaused(false)
			// woke us — fall through and probe on this wake instead of
			// waiting out the timer we were holding while paused.
		}
		pw.mu.Lock()
		ps, ok := pw.sensors[c.id]
		if !ok {
			pw.mu.Unlock()
			return
		}
		paused := ps.isPaused
		fast := ps.fastRetry
		pw.mu.Unlock()

		if paused {
			// Paused: hold the full interval (no packets, no rows, no
			// alerts) — a paused sensor is not being watched.
			nextDelay = interval
		} else if fast {
			nextDelay = errorRetryInterval
			if nextDelay > interval {
				nextDelay = interval // never faster than the user's pace
			}
			if nextDelay < 10*time.Second {
				nextDelay = 10 * time.Second // floor: no ping-storm loops
			}
		} else {
			nextDelay = interval
		}
		timer.Reset(nextDelay)

		if !paused {
			pw.safeProbe(ctx, c)
		}
	}
}

// fnvHash is a 64-bit FNV-1a over the byte slice — cheap, deterministic, and
// only used to derive a stable stagger phase per sensor id.
func fnvHash(b []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return h.Sum64()
}

// staggerPhase is the deterministic first-tick delay for a sensor, in
// [250ms, interval+250ms). The modulo MUST be done in uint64 BEFORE converting
// to a Duration: converting the raw hash first makes ~half of all ids negative
// (>= 2^63), which fires the timer immediately and defeats the stagger.
func staggerPhase(id string, interval time.Duration) time.Duration {
	if interval <= 0 {
		interval = time.Minute
	}
	phase := time.Duration(fnvHash([]byte(id)) % uint64(interval))
	if phase < 250*time.Millisecond {
		phase += 250 * time.Millisecond // never probe in the first instant
	}
	return phase
}

// respawnFirstTickCap caps the first-tick delay of a RESPAWNED loop (a
// first spawn after the previous loop was dropped — resume after a >5s
// pause, maintenance-mode end, config-edit Restart; see spawnedIDs). A
// full stagger here would leave a resumed sensor dark for up to a whole
// interval (an hour on an hourly sensor). Capping at 1s keeps the
// anti-herd property in the one case that matters — a maintenance-mode
// end with N sensors respawning together lands N probes across ~1s, not
// the same wall-clock instant — while bounding the resume/edit delay
// (2026-10-20 external review).
const respawnFirstTickCap = time.Second

// safeProbe runs one probe and contains a panic: one bad probe must not take
// the whole monitor (every other sensor) down with it.
func (pw *ProbeWorker) safeProbe(ctx context.Context, c sensorConfig) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ProbeWorker: probe for sensor %s panicked: %v\n%s", c.id, r, debug.Stack())
		}
	}()
	pw.doProbe(ctx, c)
}

// pingNowTimeout bounds the "Pulse Now" manual probe. It is a fixed 1s,
// independent of the sensor's configured timeout: a manual pulse is a quick
// diagnostic, not a scheduled probe, so it shouldn't wait out a long
// configured timeout. It is a var (like the other bounded call sites) so a
// test can shorten it.
var pingNowTimeout = time.Second

// errPulseCoolingDown is returned by PingNow when a manual pulse arrives
// before the per-sensor cooldown elapses; the handler maps it to 429.
var errPulseCoolingDown = errors.New("pulse too soon")

// pulseNowCooldown bounds how often a sensor may be manually pulsed. A
// human's click rate is far below this; an unthrottled loop is not.
const pulseNowCooldown = 2 * time.Second

// PingNow performs one immediate "Pulse Now" probe and RECORDS it: the row
// lands in probes (history + dashboard sparkline) and the in-memory stats
// cache, exactly as a scheduled tick would — but it deliberately does NOT
// derive a status, write a transition event, or fire an alert. A manual
// pulse is a diagnostic: recording it keeps the history honest (the user saw
// a real RTT / loss at that instant), while keeping status and alerts driven
// only by the scheduled probe loop (a single manual probe must not flip a
// healthy sensor to error or fire a recovery webhook).
//
// The "status and alerts are unaffected" half is enforced, not assumed
// (2026-10-20 external review): the row is tagged manual=1, and status
// derivation (recentFromDB / recentFromCache) excludes manual rows. Before
// the tag, a manual pulse's loss row was indistinguishable from a scheduled
// loss, so ONE lost manual pulse + one lost scheduled probe tripped the
// down_after=2 consecutive-loss test — the fixed 1s pulse timeout (a
// sensor whose configured timeout is longer can look lost on a pulse while
// answering fine on schedule) made the spurious loss likelier, not less.
// Works while paused (SPEC §2). Dispatches by sensor type, so an HTTP
// sensor's manual pulse makes an HTTP request (the card's "Pulse Now"
// shows its status code).
func (pw *ProbeWorker) PingNow(ctx context.Context, id string) (probeOutcome, error) {
	var target, probeType string
	if err := pw.db.QueryRow("SELECT target, type FROM sensors WHERE id = ?", id).Scan(&target, &probeType); err != nil {
		return probeOutcome{}, err // sql.ErrNoRows for an unknown sensor
	}
	// Per-sensor cooldown: a manual pulse is a quick diagnostic, and an
	// unthrottled stream of them would starve the probe queue. 2s is well
	// above a human's click rate.
	now := time.Now()
	pw.mu.Lock()
	if last, ok := pw.lastPulse[id]; ok && now.Sub(last) < pulseNowCooldown {
		pw.mu.Unlock()
		return probeOutcome{}, errPulseCoolingDown
	}
	pw.lastPulse[id] = now
	pw.mu.Unlock()
	if probeType == "" {
		probeType = "icmp"
	}

	o := probeTarget(ctx, probeType, target, pingNowTimeout)

	var rttVal interface{}
	if !o.lost {
		rttVal = o.rttMs
	}
	ts := time.Now().UTC()
	if _, err := pw.db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip, http_status, manual) VALUES (?, ?, ?, ?, ?, 1)",
		id, fmtTS(ts), rttVal, o.ip, o.httpCode); err != nil {
		return o, fmt.Errorf("record echo probe: %w", err)
	}
	// Keep the in-memory stats cache in lockstep with the DB row (the same
	// lockstep doProbe maintains), so the dashboard reflects the echo. The
	// entry must carry the SAME post-probe instant as the DB row (ts), not
	// the pre-probe cooldown timestamp (now): probeSeries is oldest-first
	// (a scheduled probe completing mid-pulse would otherwise append before
	// an older entry), and the sparkline floors each entry to its minute —
	// a pulse straddling a minute boundary would bucket differently in the
	// warm cache than in the DB.
	var rttPtr *float64
	if !o.lost {
		v := o.rttMs
		rttPtr = &v
	}
	pw.recordProbe(id, probeEntry{ts: ts.Unix(), rtt: rttPtr, manual: true})
	return o, nil
}

// LastHTTPStatus returns the most recent HTTP status code and cert expiry for
// a sensor, or (nil, nil) for ICMP sensors / sensors never probed this run.
// The card uses it to render "HTTP 503" and the cert-expiry note without a
// DB read per poll.
func (pw *ProbeWorker) LastHTTPStatus(id string) (*int, *time.Time) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if ps, ok := pw.sensors[id]; ok {
		return ps.lastHTTPStatus, ps.lastCertExpiry
	}
	return nil, nil
}

// probeOutcome is the transport-agnostic result of one probe: the round-trip
// time (meaningful only when not lost), whether the probe was lost, the
// resolved IP (diagnostic), and, for HTTP sensors, the status code when a
// response arrived (nil when it didn't). Both ICMP and HTTP probes are
// normalized to this so doProbe, PingNow, and status derivation share one
// code path and don't care which transport produced the result.
type probeOutcome struct {
	rttMs      float64
	lost       bool
	ip         string
	httpCode   *int
	certExpiry *time.Time
	// broken: the probe could not be attempted because the ICMP engine is
	// unusable (never set for HTTP probes or per-target ICMP failures).
	broken bool
}

// probeTarget dispatches one probe to the sensor's transport. A var so a
// test can stub the whole probe without opening a socket or making a request.
// ctx bounds the probe (DNS + transport) so a cancelled probe — shutdown,
// sensor removed, sensor reconfigured — aborts at its next read instead of
// running out its full (up to 30s) timeout.
var probeTarget = func(ctx context.Context, probeType, target string, timeout time.Duration) probeOutcome {
	if probeType == "http" {
		r := probeHTTP(ctx, target, timeout)
		o := probeOutcome{lost: r.Lost, ip: r.IP, httpCode: r.Status, certExpiry: r.CertExpiry}
		if !r.Lost {
			o.rttMs = r.Elapsed.Seconds() * 1000
		}
		return o
	}
	// icmp (default)
	res := pingHost(ctx, target, timeout)
	o := probeOutcome{lost: res.Lost, ip: res.ResolvedIP, broken: res.Broken}
	if !res.Lost {
		o.rttMs = res.RTT.Seconds() * 1000
	}
	return o
}

func (pw *ProbeWorker) doProbe(ctx context.Context, c sensorConfig) {
	o := probeTarget(ctx, c.probeType, c.target, time.Duration(c.timeoutMS)*time.Millisecond)
	// If the probe was cancelled in flight (stop, sensor removed or
	// reconfigured), drop the result: writing it would record a probe for a
	// sensor that no longer exists (FK violation) or for a config that was
	// already changed. The loop is exiting (or about to be replaced), so the
	// row is simply skipped.
	if ctx.Err() != nil {
		return
	}
	c.probeBroken = o.broken // per-probe, on this call's own copy of the config

	var rttVal interface{}
	var rttMs float64
	if !o.lost {
		rttVal = o.rttMs
		rttMs = o.rttMs
	}

	now := time.Now().UTC()
	if _, err := pw.db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip, http_status) VALUES (?, ?, ?, ?, ?)", c.id, fmtTS(now), rttVal, o.ip, o.httpCode); err != nil {
		log.Printf("ProbeWorker: failed to insert probe for %s: %v", c.id, err)
		return
	}
	// Keep the in-memory stats cache in lockstep with the DB row so the
	// dashboard read path stays O(1) (no per-poll SQLite queries).
	var rttPtr *float64
	if !o.lost {
		v := rttMs
		rttPtr = &v
	}
	pw.recordProbe(c.id, probeEntry{ts: now.Unix(), rtt: rttPtr})

	// The previous status feeds deriveStatus's fast-recovery rule (a sensor
	// recovering from ERROR flips to up on one good probe). Memory is
	// authoritative once the sensor has ticked in this process; the DB (which
	// survives restarts) is read only on the first tick or after a history clear.
	oldStatus, err := pw.currentStatus(c.id)
	if err != nil {
		return
	}

	newStatus := pw.deriveStatus(c, oldStatus)

	// Keep the fast-retry flag and, for HTTP sensors, the status code + cert
	// expiry in lockstep so sensorLoop picks the next-tick cadence and the card
	// shows "HTTP 503" / "cert expires in 3d" without a DB read per poll.
	pw.mu.Lock()
	if ps, ok := pw.sensors[c.id]; ok {
		ps.fastRetry = newStatus == "error"
		if c.probeType == "http" {
			ps.lastHTTPStatus = o.httpCode
			ps.lastCertExpiry = o.certExpiry
		}
	}
	pw.mu.Unlock()

	if newStatus == oldStatus {
		pw.rememberStatus(c.id, newStatus)
		// No transition: a sustained ERROR may be due for a re-alert.
		// Warning is never re-alerted (loss flapping is dashboard noise).
		if newStatus == "error" {
			pw.maybeRealert(c, newStatus, rttMs)
		}
		return
	}

	if _, err := pw.db.Exec("UPDATE sensors SET status = ? WHERE id = ?", newStatus, c.id); err != nil {
		// lastStatus is NOT advanced, so the next tick sees the same
		// transition and retries the write instead of believing it is done.
		log.Printf("ProbeWorker: failed to update status for %s: %v", c.id, err)
		return
	}
	pw.rememberStatus(c.id, newStatus) // only once the new status is durable

	note := fmt.Sprintf("%s -> %s", oldStatus, newStatus)
	if newStatus == "up" {
		note = "recovered" // first transition back to up after warning/error
	}
	if _, err := pw.db.Exec("INSERT INTO events (sensor_id, ts, from_status, to_status, note) VALUES (?, ?, ?, ?, ?)",
		c.id, tsNow(), oldStatus, newStatus, note); err != nil {
		log.Printf("ProbeWorker: failed to record event for %s: %v", c.id, err)
	}

	pw.setAlertState(c.id, newStatus, time.Now().UTC())
	// Warning-only flapping is dashboard-only; everything involving error
	// alerts (into error, partial recovery error -> warning, full recovery
	// error -> up).
	if pw.shouldAlertNow(c, oldStatus, newStatus) {
		pw.launchAlert(func() {
			// Every provider failed after retries: for an error alert, make the
			// re-alert path try again soon instead of waiting a full interval.
			if !pw.sendAlert(c.id, c.name, c.target, oldStatus, newStatus, rttMs) && newStatus == "error" {
				pw.scheduleAlertRetry(c.id, newStatus)
			}
		})
	}
}

// currentStatus returns the sensor's last known derived status: the in-memory
// value when the sensor has already been derived in this process, else the
// durable one from the sensors table.
func (pw *ProbeWorker) currentStatus(id string) (string, error) {
	pw.mu.Lock()
	if ps, ok := pw.sensors[id]; ok && ps.lastStatus != "" {
		s := ps.lastStatus
		pw.mu.Unlock()
		return s, nil
	}
	pw.mu.Unlock()
	var s string
	if err := pw.db.QueryRow("SELECT status FROM sensors WHERE id = ?", id).Scan(&s); err != nil {
		return "", err
	}
	return s, nil
}

// rememberStatus records the durable status in memory (no-op if the sensor was
// removed or restarted meanwhile).
func (pw *ProbeWorker) rememberStatus(id, status string) {
	pw.mu.Lock()
	if ps, ok := pw.sensors[id]; ok {
		ps.lastStatus = status
	}
	pw.mu.Unlock()
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

// errorRetryInterval is the probe cadence for a sensor while its status is
// ERROR: re-check every 30s until a probe brings it back to up, then revert
// to the sensor's configured interval. It is capped at the configured
// interval (a sensor polling faster than 30s already re-checks at least as
// often) and floored at 10s, so the fast path is never faster than the
// normal one and a total-outage scenario is bounded to ~2x normal load.
const errorRetryInterval = 30 * time.Second

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
//	            (and not error); loss_warn == 0 (disabled, API-unreachable)
//	            warns on any loss in the window
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
		if r == nil {
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
	// (loss_warn == 0 keeps the pre-gate steady-state behavior — the
	// defensive zeroed-row path, unreachable via the API.)
	upRule := false
	if recent[0] != nil {
		switch {
		case lastStatus == "error" || len(recent) == 1:
			upRule = true
		case recent[1] != nil && (c.lossWarn == 0 || lossPct < float64(c.lossWarn)):
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
		if r == nil {
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
	// sparkline bar still show the blip.
	if c.lossWarn > 0 {
		if lossPct >= float64(c.lossWarn) {
			return "warning"
		}
		// Below the threshold: the window is statistically healthy, so the
		// sensor reads up (a single recent loss among sub-threshold stats
		// is a blip, not degradation).
		return "up"
	}

	// loss_warn == 0 (threshold disabled): any loss in the window that
	// isn't an error degrades the sensor. Unreachable via the API — it
	// validates 1-100 — kept so a zeroed row degrades loudly rather than
	// reading up while dropping packets.
	return "warning"
}

// recentFromCache returns up to limit most-recent RTTs (index 0 = newest,
// nil = lost) from the in-memory series. ok is false when the series holds
// fewer than limit entries, in which case the DB may know more history.
func (pw *ProbeWorker) recentFromCache(id string, limit int) ([]*float64, bool) {
	pw.statsMu.RLock()
	defer pw.statsMu.RUnlock()
	s, ok := pw.statsCache[id]
	if !ok || s.len() < limit {
		return nil, false
	}
	out := make([]*float64, 0, limit)
	for i := len(s.data) - 1; i >= s.start && len(out) < limit; i-- {
		// Manual "Pulse Now" rows are excluded from status derivation
		// (probes.manual): they stay in the series for the sparkline,
		// but never count toward loss % or the consecutive-loss test
		// (2026-10-20 external review — see the PingNow doc).
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
func (pw *ProbeWorker) recentFromDB(id string, limit int) ([]*float64, error) {
	rows, err := pw.db.Query("SELECT rtt_ms FROM probes WHERE sensor_id = ? AND manual = 0 ORDER BY ts DESC LIMIT ?", id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() // top-level: closed on every return path (the pool is capped; a leak would hang)
	var recent []*float64
	for rows.Next() {
		var rtt *float64
		if err := rows.Scan(&rtt); err != nil {
			return nil, err
		}
		recent = append(recent, rtt)
	}
	return recent, rows.Err()
}

// purgeOld enforces 24-hour retention on probes/events (SPEC §3). 24h is the
// longest window the dashboard reads, so nothing on screen needs older data.
//
// ts is compared as a string. That is exact because every writer uses the
// fixed-width fmtTS layout (lexicographic order == chronological order). Rows
// written by older versions used a variable-width layout; for those the
// comparison can be off by under one second right at the cutoff, which only
// ever over- or under-retains a single boundary row once and ages out within a
// day - harmless for a 24h window.
func (pw *ProbeWorker) purgeOld() {
	cutoff := fmtTS(time.Now().Add(-24 * time.Hour))
	for _, table := range []string{"probes", "events"} {
		res, err := pw.db.Exec("DELETE FROM "+table+" WHERE ts < ?", cutoff)
		if err != nil {
			log.Printf("retention: failed to purge %s: %v", table, err)
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("retention: purged %d rows from %s", n, table)
		}
	}
}

// ---------- alert destinations (multi-provider) ----------
//
// Each provider (google_chat, discord) has its own URL setting and an
// explicit enable flag. Alerts fan out to EVERY active provider. The
// registry is the single source of truth for "which providers exist", so a
// future provider (Slack, ntfy, …) is one entry in this slice plus a card
// builder — the send path, migration, and UI all derive from it.
//
// google_chat is the legacy provider: before this it was THE webhook. Its
// enable flag defaults to ON when a URL is present (dashboard or the
// GOOGLE_CHAT_WEBHOOK_URL env) so existing installs keep alerting with zero
// config; a fresh install has no URL and no flag, so it stays off.

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

// activeProviders returns every provider currently receiving alerts.
// activeProviders returns the enabled, URL-configured providers. The
// second return value reports whether the DB read itself succeeded
// (2026-10-19 review N3): GetSetting maps a read error to "", so a
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
// alertGate FIFO first (2026-10-19 review F4): alerts for one sensor run
// strictly in launch order, so an "error" alert whose first attempt fails
// and retries cannot be delivered AFTER the sensor's later "recovered"
// alert — the chat's last word must match the sensor's current state.
// The caller blocks until the delivery finishes (the launchAlert goroutine
// is tracked in alertWG, so DrainAlerts still sees true completion).
func (pw *ProbeWorker) sendWebhook(id, name, target, oldState, state string, rttMs float64, reAlert bool) bool {
	// Storm budget (2026-10-19 review M8): over-budget non-recovery alerts
	// are coalesced into a single storm summary instead of delivered
	// individually. A suppressed alert reports "delivered" (true) so the
	// caller schedules no retry — the summary carries it.
	if !pw.stormAdmit(id, name, target, oldState, state, rttMs) {
		return true
	}
	done := make(chan bool, 1)
	pw.alertGate(id) <- func() {
		done <- pw.sendWebhookDeliver(id, name, target, oldState, state, rttMs, reAlert)
	}
	return <-done
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
	if state == "up" {
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
	go func() {
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
	// Drop entries that recovered before the flush: a summary line for a
	// sensor that is back up would contradict the recovery alert it raced.
	// A vanished sensor (deleted mid-storm) is kept — the operator should
	// still see it in the storm that took it down.
	still := q[:0]
	for _, e := range q {
		if s, err := pw.db.SensorStatus(e.id); err == nil && s == "up" {
			continue
		}
		still = append(still, e)
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

// stormSummaryLine renders one entry as a readable transition, with the
// same hygiene as the per-sensor cards: credentials stripped (F22),
// mention tokens neutralized (F23).
func stormSummaryLine(e stormEntry) string {
	name := discordMentionSafe(e.name)
	target := alertTarget(e.target)
	return fmt.Sprintf("%s: %s → %s (%s)", name, e.oldState, e.state, target)
}

// stormSummaryMarkdown renders the summary for google_chat / discord.
func stormSummaryMarkdown(entries []stormEntry) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("⚠️ *pulsemon: alert storm — %d sensors changed state (coalesced to limit alert noise)*\n", len(entries)))
	for _, e := range entries {
		b.WriteString("*" + stormSummaryLine(e) + "*\n")
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
// delivered (2026-10-19 review N3).
func (pw *ProbeWorker) resolveDestinations() ([]dest, bool) {
	providers, readOK := pw.activeProviders()
	if !readOK {
		return nil, false
	}
	var dests []dest
	for _, p := range providers {
		url, err := pw.db.GetSettingErr(p.Kind + "_url")
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
	// DB error now fails the send (2026-10-19 review m5); resolving up front
	// means no provider has fired yet when we bail.
	dests, ok := pw.resolveDestinations()
	if !ok {
		// DB unreadable and no last-known-good list: the alert CANNOT be
		// delivered, and it must be reported as such so the caller can
		// retry — never "delivered" on an empty (error-induced) provider
		// list (2026-10-19 review N3).
		log.Printf("alert: provider list unreadable (no cache) — alert not delivered")
		return false
	}
	var wg sync.WaitGroup
	var delivered atomic.Bool
	for _, d := range dests {
		wg.Add(1)
		go func(p providerMeta, url string) {
			defer wg.Done()
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
		// allowed_mentions.parse = [] (2026-10-19 review F23): never let
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
	resp, err := webhookClient.Do(req)
	if err != nil {
		return false, redactErr(err).Error()
	}
	defer resp.Body.Close()
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
		fn()
	}()
}

// DrainAlerts waits for in-flight alert deliveries to finish, bounded by
// timeout. It is called from main AFTER Run returns and BEFORE db.Close, so
// an alert fired on the final probe tick is not killed mid-delivery. main
// calls StopAlerts first, so any delivery stuck in a network blip is
// aborted at its next read (stopCtx) instead of holding this drain for the
// client's full 10s timeout — the timeout here is a backstop only.
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
// stripping any userinfo (2026-10-19 review F22): an HTTP target like
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
// (2026-10-19 review F23): a sensor named "@everyone" (or a target path
// containing the token) would fire a mass mention to the whole channel
// when the card posts. A zero-width space after the @ breaks the token
// for Discord's mention parser while staying invisible in the rendered
// card. Belt-and-braces with the payload's allowed_mentions.parse = []:
// this covers clients/imports that ignore allowed_mentions.
func discordMentionSafe(s string) string {
	s = strings.ReplaceAll(s, "@everyone", "\u200beveryone")
	s = strings.ReplaceAll(s, "@here", "\u200bhere")
	return s
}

func cardFor(oldState, state, name, target string, rttMs float64) string {
	target = alertTarget(target)
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
	name, target = discordMentionSafe(name), discordMentionSafe(alertTarget(target))
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
	name, target = discordMentionSafe(name), discordMentionSafe(alertTarget(target))
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
// what it asked for (2026-10-19 review M8).
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
// (2026-10-19 review F23) — which a string-valued map can't express.
func (pw *ProbeWorker) postJSON(url string, payload map[string]interface{}) error {
	body, _ := json.Marshal(payload)
	err := pw.retryAlert(func() (bool, time.Duration, error) {
		req, err := http.NewRequestWithContext(pw.stopCtx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return false, 0, redactErr(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := webhookClient.Do(req)
		if err != nil {
			return pw.stopCtx.Err() == nil, 0, redactErr(err)
		}
		defer resp.Body.Close()
		// Drain (capped) before close so the transport can reuse the
		// TLS connection for the next alert (2026-10-19 review F25):
		// closing an unread body marks the conn non-reusable, so every
		// alert paid a fresh handshake even to the same endpoint.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		switch code := resp.StatusCode; {
		case code >= 300 && code < 400:
			return false, 0, errors.New("endpoint redirected (refused to follow — possible misconfiguration)")
		case code == http.StatusTooManyRequests:
			// Honor the provider's Retry-After (2026-10-19 review M8).
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
// the maxAlertRetryAfter cap (2026-10-19 review M8).
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

// newID generates a unique sensor id.
func newID() string {
	return uuid.NewString()
}

// validTarget accepts only well-formed probe targets (all SQL is parameterized; this is input hygiene).
//
// Hostnames must be dotted labels ending in an alphabetic TLD (one or more
// labels). Bare single-label hostnames (a plain "router", "NAS", "home")
// are deliberately REJECTED: for an ICMP tool a bare label is almost always
// a typo (the user meant "router.local" or the actual IP) and most resolvers
// won't resolve it anyway — so it must fail at save time with a clear error,
// not hang every probe tick. This is intentional, not a bug.
var targetRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// validTarget reports whether t is a usable probe target: a range-checked
// IPv4 address, or a dotted hostname. IPv4 is checked with net.ParseIP so
// out-of-range octets like "999.999.999.999" are rejected up front instead
// of passing validation and then failing DNS every tick.
func validTarget(t string) bool {
	if t == "" {
		return false
	}
	if ip := net.ParseIP(t); ip != nil {
		return ip.To4() != nil // accept IPv4; IPv6 targets are not supported
	}
	return targetRe.MatchString(t)
}
