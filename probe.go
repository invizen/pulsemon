package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"math"
	"net"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"pulsemon/internal/store"
)

type ProbeState struct {
	id       string
	isPaused bool
	// kick wakes the sensor's probe loop early: // SetPaused(false) sends on it so a resume probes on the loop's next
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

func (ps *probeSeries) len() int { return len(ps.data) - ps.start }

// lastTs is the timestamp of the newest appended entry (0 when empty).
// Entries are appended in arrival order; callers use it only as a
// monotonicity guard (warm-stats merge), not as an ordering guarantee.
func (ps *probeSeries) lastTs() int64 {
	if ps.len() == 0 {
		return 0
	}
	return ps.data[len(ps.data)-1].ts
}

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
		// grows unbounded" trap). Entries are value types, so no zeroing
		// is needed to free memory — shifting is all it takes.
		n := copy(ps.data, ps.data[ps.start:])
		ps.data = ps.data[:n]
		ps.in24Start -= ps.start // the window pointer shifts with the array
		ps.start = 0
	}
	ps.data = append(ps.data, e)
	// Eviction boundary: the INDEX of the first entry beyond the last 60
	// (len(data)-60) — NOT len()-60, which is off by `start` and, once
	// start grows, stops evicting entirely: a long-interval sensor's
	// series would then grow unbounded (the start < start+len-60 test
	// fails at half density). Caught by
	// TestSeriesCountersTrackRecount (6000 hourly appends → len 3030
	// instead of 60 on the pre-fix code).
	boundary := len(ps.data) - 60
	if boundary < 0 {
		boundary = 0
	}
	cutoff := e.ts - retentionSeconds
	// 24h window bookkeeping: entries the window has passed drop out of the
	// counters HERE (see the field doc for why the evict loop below must
	// not touch them). Manual rows were never counted, so they never
	// decrement.
	for ps.in24Start < len(ps.data) && ps.data[ps.in24Start].ts < cutoff {
		if !ps.data[ps.in24Start].manual {
			if isLost(ps.data[ps.in24Start].rtt) {
				ps.lost24--
			}
			ps.total24--
		}
		ps.in24Start++
	}
	for ps.start < boundary && ps.data[ps.start].ts < cutoff {
		ps.start++
	}
	// Manual "Pulse Now" rows stay in the series (the inspector window
	// reads them) but never enter the 24h counters: a diagnostic click
	// must not move uptime_24h.
	if !e.manual {
		ps.total24++
		if isLost(e.rtt) {
			ps.lost24++
		}
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
	db      *store.Store

	// spawnedIDs records every id this worker has ever spawned a loop for,
	// so syncSensors can tell a FIRST spawn (process start, brand-new
	// sensor) from a RESPAWN (loop dropped by the vanished pass after a
	// >5s pause, by maintenance-mode end, or by Restart after a config
	// edit). A respawn's first tick is capped at respawnFirstTickCap
	// instead of the full staggered phase: the operator explicitly
	// resumed/edited the sensor and wants data now, not up to a whole
	// interval later (before the cap, an
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
	// the loop promptly instead of waiting out the 5s tick. Only the Run goroutine consumes it — syncSensors
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
	// an "error" alert whose webhook attempt fails
	// and retries must not be delivered AFTER the sensor's later
	// "recovered" alert — a chat whose last word is "error" on a recovered
	// sensor is worse than a late alert. One consumer goroutine per sensor
	// drains a small FIFO; jobs run strictly in queue order. Guarded by
	// alertMu. The channel is NEVER closed: an in-flight sendWebhook may
	// still hold it and send, and a send on a closed channel panics.
	// Instead the consumer exits after alertGateIdle with an empty queue
	// the old "range ch" consumer lived
	// forever, leaking one goroutine per deleted sensor, and Remove's map
	// delete was the only cleanup. Idle exit recycles both a deleted
	// sensor's consumer (Remove drops the entry; the next idle fire finds
	// an empty queue and goes away) and a quiet live sensor's consumer
	// (the next alert re-creates the gate).
	alertMu         sync.Mutex
	alertOrderGates map[string]chan func()

	// lastProviders: the last successfully loaded active-provider list
	// GetSetting maps a DB read error to "", so a
	// failing DB looks exactly like "no providers configured" — and
	// sendWebhook's len(dests)==0 branch then reports a DROPPED alert as
	// delivered. activeProviders pings the DB first; on a read failure it
	// serves this cache. Guarded by provMu.
	provMu        sync.Mutex
	lastProviders []providerMeta

	// Storm budget: a global cap on individual
	// non-recovery alerts per window. When the budget is exhausted (an
	// upstream router dies and 23 sensors error within seconds), the
	// excess alerts are NOT delivered individually — they are queued and
	// emitted as ONE coalesced "storm summary" alert when the window
	// elapses, instead of N parallel bursts that trip provider 429s and
	// the retry schedule into a storm of their own. Recoveries — full
	// (state == "up") AND partial (error -> warning) — are ALWAYS
	// admitted: the operator must hear a recovery even mid-storm, and a
	// storm of recoveries is far less noisy than a storm of failures.
	// Guarded by stormMu.
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

func NewProbeWorker(db *store.Store) *ProbeWorker {
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
	// wiped any probe recorded during the warm window.
	pw.warmStats(ctx)
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
			pw.purgeOld(ctx)
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
	// Close the cursor NOW (nit 2026-10-24): an exhausted-but-open Rows
	// still holds its pooled connection until the top-level defer runs at
	// FUNCTION return — which is after the pw.mu section below. Closing on
	// the happy path releases the connection before the lock window (the
	// defer above remains the error-path safety net; Close is idempotent).
	rows.Close()

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

	// Lock-across-I/O bound (review 2026-10-24): the reads below run under
	// pw.mu deliberately (see the fresh-state comment), and pw.mu is the
	// hot lock sensorLoops touch twice per iteration BEFORE their ctx.Done
	// select. A stalled read here therefore stalls every loop (and healthz
	// ActiveCount) up to the 15s busy_timeout — so NOTHING that can hold
	// the SQLite write lock for seconds may exist: purgeOld batches
	// (purgeBatchSize) and both clear-history handlers batch too. Keep any
	// future bulk write batched or this window reopens.
	pw.mu.Lock()
	defer pw.mu.Unlock()

	// Fresh state read UNDER the lock: the config
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
			// Re-read the row UNDER the lock (closes the M1b TOCTOU): configs was read from the DB above,
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
				// Row vanished between the config read and this
				// under-lock read. We are inside the NO-LOOP branch, and
				// the vanished-sensor stop pass only sweeps ids present
				// in pw.loops — so a ProbeState created earlier in THIS
				// pass (or left by an earlier one) would be orphaned
				// forever (nit 2026-10-24). Remove it; a future re-create
				// of the sensor rebuilds state cleanly on the next pass.
				delete(pw.sensors, c.id)
				continue
			}
			// First spawn vs RESPAWN (see the spawnedIDs field): a
			// respawned loop — resume after a >5s pause, maintenance-mode
			// end, config-edit Restart — caps its first tick at
			// respawnFirstTickCap so the sensor is not dark for up to a
			// whole interval.
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
// batched in store.InQueryChunk. syncSensors calls it
// under pw.mu: the pre-lock config read can be arbitrarily stale by apply
// time (an operator pause landing in the read→apply gap would otherwise be
// clobbered by the stale row), so the pause sync uses this fresh read. A
// missing id (row deleted in the gap) is simply absent from the map.
func (pw *ProbeWorker) freshStates(ids []string) map[string]string {
	out := make(map[string]string, len(ids))
	for i := 0; i < len(ids); i += store.InQueryChunk {
		end := i + store.InQueryChunk
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

// freshConfig re-reads one sensor's spawn config from the DB: syncSensors calls it UNDER pw.mu in the respawn
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
// A resume (paused=false) also KICKS the sensor's loop: the loop's timer was holding a full interval while the sensor was
// paused, so without the kick the first probe after a resume would be up to
// a whole interval late (60s on a 60s sensor). The kick makes the loop
// re-evaluate and probe on its next wake.
//
// Scope: the kick only reaches a LIVE loop. The sync pass drops paused
// sensors within ~5s (the vanished pass deletes loop + state), so a resume
// after a longer pause finds no entry here and the kick is a no-op — the
// sensor is then RESPAWNED by the next syncSensors pass, and the respawn
// path caps the first tick at respawnFirstTickCap (1s) so the resume delay
// is bounded the same way (or after ANY maintenance
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
// without a process restart: cancel + delete + an IMMEDIATE syncSensors
// signal — the respawn is the NEXT sync pass, which re-reads the row
// under pw.mu. The DB is the source of truth; deriveStatus re-derives
// state from probe history on the next probe.
//
// Invariants (docs/DECISIONS.md → restart-respawn): the respawn must
// stay a child of Run's ctx (a Background-parented loop makes Run's
// wg.Wait() hang forever at shutdown), and the cancel/delete/signal
// discipline is what makes duplicate loops impossible — do not
// "simplify" it into a re-spawn inside this function.
func (pw *ProbeWorker) Restart(id string) {
	pw.mu.Lock()
	if cancel, ok := pw.loops[id]; ok {
		cancel()
		delete(pw.loops, id)
	}
	delete(pw.sensors, id)
	pw.mu.Unlock()
	// Request an IMMEDIATE sync pass: Run's select runs it on the next
	// iteration and respawns with the post-commit config, so a config
	// edit no longer waits out the 5s tick. Non-blocking: a request
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
	// stays pinned in memory for the process lifetime. Lock order: pw.mu (held) then pw.statsMu — see ResetStatsFor.
	pw.statsMu.Lock()
	delete(pw.statsCache, id)
	pw.statsMu.Unlock()
	// Same for the per-sensor alert gate: drop the
	// map entry so the channel isn't pinned by the map. The consumer is
	// NOT signalled — it reaps itself on its next idle fire (the queue is
	// empty, so it exits within alertGateIdle); closing the channel here
	// would panic an in-flight sendWebhook sending on it. See the alertOrderGates field comment.
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

func (pw *ProbeWorker) sensorLoop(ctx context.Context, c sensorConfig, resumed bool) {
	interval := time.Duration(c.intervalS) * time.Second
	if interval <= 0 {
		interval = time.Minute // a zeroed row must not divide by zero or spin
	}

	// Stagger the first tick by a deterministic per-sensor phase so
	// sensors added together don't fire on the same wall-clock second
	// (a write thundering-herd against SQLite) — see staggerPhase and
	// docs/DECISIONS.md → stagger.
	//
	// RESPAWN exception (resumed, set by syncSensors via spawnedIDs):
	// cap the first tick at respawnFirstTickCap (see that constant).
	phase := staggerPhase(c.id, interval)
	if resumed && phase > respawnFirstTickCap {
		phase = respawnFirstTickCap
	}

	// Timer (not ticker) so the next-tick delay can adapt: a sensor in
	// ERROR re-checks on the fast-retry cadence (capped at the configured
	// interval — never faster than the user's pace) until a probe brings
	// it back to up, then reverts to the configured interval.
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
			// Resume fast path: SetPaused(false)
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
			nextDelay = min(errorRetryInterval, interval) // never faster than the user's pace
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
// anti-herd property in the one case that matters — N sensors respawning
// together land across ~1s, not the same instant — while bounding the
// resume/edit delay (docs/DECISIONS.md → stagger).
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

// pingNowTimeout is the FALLBACK timeout for a "Pulse Now" probe on a legacy
// row whose timeout_ms is zeroed (the API validates 100-30000, so only
// pre-validation rows reach it). Real sensors run the pulse with their OWN
// configured timeout: the pulse is the same probe the sensor runs on
// schedule, and the old fixed-1s design made slow-but-healthy targets (a
// cold Nextcloud, a Proxmox login) read as losses on a pulse while
// answering fine on schedule (the old
// code documented that tradeoff in its own doc string).
const pingNowTimeout = time.Second

// dbWriteTimeout bounds a single probe-record write (review 2026-10-24):
// SQLite's busy_timeout is 15s — longer than the shutdown drain budget —
// so probe-path writes carry their own smaller cap instead of parking on
// a stalled writer for the full busy_timeout.
const dbWriteTimeout = 8 * time.Second

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
// the row is tagged manual=1, and status
// derivation (recentFromDB / recentFromCache) excludes manual rows. Before
// the tag, a manual pulse's loss row was indistinguishable from a scheduled
// loss, so ONE lost manual pulse + one lost scheduled probe tripped the
// down_after=2 consecutive-loss test.
//
// The same exclusion covers EVERY loss/uptime aggregate: computeSensorStats skips manual entries in the 1h
// loss/avg, the status window, the sparkline, and the 24h counters, and
// the graph endpoint filters manual = 0. Before F5 only status derivation
// skipped them, so a lost manual pulse — likelier than it should be,
// because the pulse used to run a fixed 1s timeout — could make a healthy
// sensor show packet loss on the card and the graph. The pulse now runs
// with the sensor's own timeout_ms (pingNowTimeout only covers a legacy
// zeroed row), so a slow-but-healthy target answers the pulse exactly as
// it answers the schedule.
// Works while paused (SPEC §2). Dispatches by sensor type, so an HTTP
// sensor's manual pulse makes an HTTP request (the card's "Pulse Now"
// shows its status code).
func (pw *ProbeWorker) PingNow(ctx context.Context, id string) (probeOutcome, error) {
	var target, probeType string
	var timeoutMS int
	if err := pw.db.QueryRow("SELECT target, type, timeout_ms FROM sensors WHERE id = ?", id).Scan(&target, &probeType, &timeoutMS); err != nil {
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

	// The sensor's own configured timeout: // the pulse is the same probe the sensor runs on schedule, so a
	// slow-but-healthy target answers it. A legacy zeroed row falls back
	// to pingNowTimeout.
	timeout := time.Duration(timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = pingNowTimeout
	}
	o := probeTarget(ctx, probeType, target, timeout)

	var rttVal interface{}
	if !o.lost {
		rttVal = o.rttMs
	}
	ts := time.Now().UTC()
	// Bounded write (review 2026-10-24): a bare Exec can sit on the
	// 15s busy_timeout — longer than the ~10s shutdown drain budget —
	// and using the REQUEST ctx would wrongly discard a completed probe
	// when the browser closes the tab. A fresh capped context bounds the
	// write without inheriting either problem.
	writeCtx, cancelWrite := context.WithTimeout(context.Background(), dbWriteTimeout)
	defer cancelWrite()
	if _, err := pw.db.ExecContext(writeCtx, "INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip, http_status, manual) VALUES (?, ?, ?, ?, ?, 1)",
		id, store.FormatTS(ts), rttVal, o.ip, o.httpCode); err != nil {
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
	rtt := float32(math.NaN())
	if !o.lost {
		rtt = float32(o.rttMs)
	}
	pw.recordProbe(id, probeEntry{ts: ts.Unix(), rtt: rtt, manual: true})
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
	// timeout_ms<=0 fallback for a legacy zeroed row (review 2026-10-24):
	// the API's create default is 1000ms and PingNow falls back to the
	// same value (pingNowTimeout). Without this, a zeroed row reads 100%
	// loss on EVERY scheduled tick while Pulse Now on the same sensor
	// works — the two probe paths disagreed on one bad row.
	timeout := time.Duration(c.timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = pingNowTimeout
	}
	o := probeTarget(ctx, c.probeType, c.target, timeout)
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
	// Bounded write (review 2026-10-24): the probe ctx is correct here —
	// it is already cancelled-and-checked above (a cancelled probe drops
	// its result), and it lets shutdown interrupt a write parked on the
	// 15s busy_timeout instead of outrunning the drain budget.
	if _, err := pw.db.ExecContext(ctx, "INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip, http_status) VALUES (?, ?, ?, ?, ?)", c.id, store.FormatTS(now), rttVal, o.ip, o.httpCode); err != nil {
		log.Printf("ProbeWorker: failed to insert probe for %s: %v", c.id, err)
		return
	}
	// Keep the in-memory stats cache in lockstep with the DB row so the
	// dashboard read path stays O(1) (no per-poll SQLite queries).
	rtt := float32(math.NaN())
	if !o.lost {
		rtt = float32(rttMs)
	}
	pw.recordProbe(c.id, probeEntry{ts: now.Unix(), rtt: rtt})

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
		c.id, store.Now(), oldStatus, newStatus, note); err != nil {
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

// errorRetryInterval is the probe cadence for a sensor while its status is
// ERROR: re-check every 30s until a probe brings it back to up, then revert
// to the sensor's configured interval. It is capped at the configured
// interval, so the fast path is never faster than the user's pace and a
// total outage adds no load beyond the normal probe rate for sub-30s
// sensors (longer-interval sensors re-check at 30s — the only increase).
const errorRetryInterval = 30 * time.Second

// purgeBatchSize caps the rows deleted per statement in purgeOld. Each batch
// is its own short write transaction, so probe INSERTs can take the write
// lock BETWEEN batches instead of waiting behind the entire purge
// (see the plan note in purgeOld).
const purgeBatchSize = 5000

// purgeOld enforces 24-hour retention on probes/events (SPEC §3). 24h is the
// longest window the dashboard reads, so nothing on screen needs older data.
//
// ts is compared as a string. That is exact because every writer uses the
// fixed-width store.FormatTS layout (lexicographic order == chronological order). Rows
// written by older versions used a variable-width layout; for those the
// comparison can be off by under one second right at the cutoff, which only
// ever over- or under-retains a single boundary row once and ages out within a
// day - harmless for a 24h window.
//
// PLAN: the old body was one
// `DELETE FROM <table> WHERE ts < ?` per table. ts is the SECOND column of
// idx_probes_sensor_ts(sensor_id, ts), so the planner cannot range-seek it
// (SQLite will not skip-scan a non-leading column without ANALYZE stats) and
// the statement full-scanned the whole table — at 100 sensors @ 5s that is
// ~1.7M rows — and deleted ~72k of them in ONE write transaction, with every
// probe INSERT blocked behind it up to the 15s busy_timeout: stalled probes
// and timing jitter right at the top of the hour. The fix deletes per sensor
// (the inner select is an index range scan on the (sensor_id, ts) prefix) in
// bounded batches of purgeBatchSize rows, so the write lock is held only for
// one batch (a few ms) and released between batches. A sensor whose rows are
// all inside the window costs one cheap empty round trip.
// purgeOld deletes rows older than the retention window. ctx (review
// nit 2026-10-24) lets shutdown stop the sweep between batches: the old
// context-free loop could run minutes of DELETEs uninterruptibly on a
// large retention backlog, past the shutdown drain budget.
func (pw *ProbeWorker) purgeOld(ctx context.Context) {
	cutoff := store.FormatTS(time.Now().Add(-24 * time.Hour))
	ids, err := pw.db.SensorIDs()
	if err != nil {
		log.Printf("retention: failed to list sensors: %v", err)
		return
	}
	for _, table := range []string{"probes", "events"} {
		total := int64(0)
		for _, id := range ids {
			for {
				select {
				case <-ctx.Done():
					if total > 0 {
						log.Printf("retention: purge of %s stopped by shutdown after %d rows", table, total)
					}
					return
				default:
				}
				res, err := pw.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE id IN (
					SELECT id FROM `+table+` WHERE sensor_id = ? AND ts < ? LIMIT ?)`, id, cutoff, purgeBatchSize)
				if err != nil {
					log.Printf("retention: failed to purge %s for sensor %s: %v", table, id, err)
					break
				}
				n, _ := res.RowsAffected()
				total += n
				if n < purgeBatchSize {
					break
				}
			}
		}
		if total > 0 {
			log.Printf("retention: purged %d rows from %s", total, table)
		}
	}
}

// validTarget accepts only well-formed probe targets (all SQL is parameterized; this is input hygiene).
//
// A target is one of:
//   - an IPv4 address (range-checked via net.ParseIP), or
//   - a dotted hostname: one or more RFC 1123 labels ending in an
//     alphabetic TLD (targetRe), or
//   - a BARE single-label hostname (validSingleLabel): "nas", "pve",
//     "router". These resolve on most home LANs via the resolver's
//     search domain (resolv.conf "search") — the same names HTTP
//     targets have always used. A label made purely of digits is
//     rejected: net.ParseIP has already taken real IPv4s, so a bare
//     numeric label is a truncated-IP typo, not a hostname.
//
// Save-time validation is FORMAT hygiene, not a resolvability promise:
// a target that doesn't resolve on this box simply probes down with a
// clear DNS error. That is safe because the probe's resolver is
// deadline-bounded (resolveIPAddrWithTimeout) — a hung lookup becomes a
// loss row, never a wedged tick. (The earlier stance rejected
// bare single labels for fear of per-tick DNS hangs; the bounded
// resolver closed that hole, and the rejection was asymmetric with
// validURL, which already let http://nas:8080 through.)
var targetRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// singleLabelRe is one RFC 1123 label with no dot: length 1-63,
// alphanumeric ends, hyphens inside. validSingleLabel additionally
// requires at least one letter.
var singleLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

// letterRe reports whether its argument contains at least one ASCII letter
// (a character CLASS, unlike strings.ContainsAny, whose second argument is
// a set of literal runes — "a-zA-Z" there means a, -, z, A, Z).
var letterRe = regexp.MustCompile(`[a-zA-Z]`)

// validSingleLabel reports whether t is a usable bare hostname: one RFC
// 1123 label containing at least one letter. A purely numeric label is
// rejected: net.ParseIP has already taken real IPv4s, so a bare numeric
// string is a truncated-IP typo, not a hostname. Shared by validTarget
// (ICMP) and validURL (HTTP) so the two validators keep the same stance
// on single labels.
func validSingleLabel(t string) bool {
	return singleLabelRe.MatchString(t) && letterRe.MatchString(t)
}

// validTarget reports whether t is a usable probe target: a range-checked
// IPv4 address, a dotted hostname, or a bare single-label hostname. IPv4
// is checked with net.ParseIP so out-of-range octets like
// "999.999.999.999" are rejected up front instead of passing validation
// and then failing DNS every tick.
func validTarget(t string) bool {
	if t == "" {
		return false
	}
	// Length bound (review 2026-10-24): names cap at 60 and tags at 30,
	// but target had NO cap — a 1 MiB body-cap string was accepted, then
	// echoed on every poll response and into every alert body. 253 is the
	// RFC 1035 max for a fully-qualified domain name (labels are already
	// ≤63 each; targetRe alone did not bound the TOTAL).
	if len(t) > 253 {
		return false
	}
	if ip := net.ParseIP(t); ip != nil {
		return ip.To4() != nil // accept IPv4; IPv6 targets are not supported
	}
	if targetRe.MatchString(t) {
		return true
	}
	return validSingleLabel(t)
}
