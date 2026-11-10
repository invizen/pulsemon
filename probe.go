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
	"sort"
	"sync"
	"sync/atomic"
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

func (ps *probeSeries) len() int { return len(ps.raw) - ps.rawStart }

// lastTs is the timestamp of the newest appended entry (0 when empty).
// Entries are appended in arrival order; callers use it only as a
// monotonicity guard (warm-stats merge), not as an ordering guarantee.
func (ps *probeSeries) lastTs() int64 {
	if ps.len() == 0 {
		return 0
	}
	return ps.raw[len(ps.raw)-1].ts
}

// rawWindowSecs is the time span the raw tier keeps at full resolution: the
// per-probe read path (60-probe inspector, status window, 1h loss/avg,
// sparkline) only ever needs the last hour. The last-60 count rule (below)
// extends the raw tier further back for slow-interval sensors whose 60 probes
// span more than an hour.
const rawWindowSecs = 3600

// append adds a new (newest) entry. It lands in the raw tier; raw entries that
// age out of the raw window — max(1h, last 60) — are folded into per-minute
// buckets (each entry folds exactly once); minute buckets older than the 24h
// retention are evicted, decrementing the 24h counters.
//
// The raw window is the UNION the DB read path returns at per-probe
// resolution:
// - the 60-probe stats window keeps the LAST 60 probes even if a sensor's
// long interval pushes them past an hour (a 1h-interval sensor's 60 probes
// span 60h) — this is what `ORDER BY ts DESC LIMIT 60` reads;
// - the 1h window keeps everything within rawWindowSecs for the loss/avg/
// sparkline fields — what `ts >= now-1h` reads.
//
// An entry is evicted from raw only when it is BOTH beyond the last 60 AND
// older than the 1h cutoff; it then folds into a minute bucket (manual rows
// are dropped — they never enter the buckets or the counters). Memory is thus
// bounded at ~max(1h, 60) raw entries + 1440 minute buckets, not a full 24h of
// raw probes.
func (ps *probeSeries) append(e probeEntry) {
	if ps.rawStart > 0 && (ps.rawStart >= 4096 || ps.rawStart*2 >= len(ps.raw)) {
		// Reclaim front space so future appends reuse the backing array
		// instead of reallocating (the classic "resliced slice grows
		// unbounded" trap). Entries are value types, so no zeroing is needed
		// to free memory — shifting is all it takes.
		n := copy(ps.raw, ps.raw[ps.rawStart:])
		ps.raw = ps.raw[:n]
		if ps.raw24Start > ps.rawStart {
			ps.raw24Start -= ps.rawStart
		} else {
			ps.raw24Start = 0
		}
		ps.rawStart = 0
	}
	ps.raw = append(ps.raw, e)
	// 24h counters: the new entry is always inside its own window.
	if !e.manual {
		ps.total24++
		if isLost(e.rtt) {
			ps.lost24++
		}
	}
	// Fold raw entries that have aged out of the raw window into minute
	// buckets. The boundary is the FIRST index to keep in raw: an entry is
	// kept if it is within the 1h window (index >= timeBoundary) OR in the
	// last 60 (index >= countBoundary), so it is kept iff index >=
	// min(timeBoundary, countBoundary). raw is ts-sorted, so the time
	// boundary is a clean binary search.
	n := len(ps.raw)
	cutoffHour := e.ts - rawWindowSecs
	i := sort.Search(n, func(j int) bool { return ps.raw[j].ts >= cutoffHour })
	if i < ps.rawStart {
		i = ps.rawStart
	}
	c := n - 60
	if c < ps.rawStart {
		c = ps.rawStart
	}
	boundary := i
	if c < boundary {
		boundary = c
	}
	for ps.rawStart < boundary {
		fe := ps.raw[ps.rawStart]
		// Fold only entries still inside the 24h window (index >= raw24Start):
		// an entry already out of the window was decremented when raw24Start
		// passed it, so folding it into a bucket (then evicting the bucket)
		// would double-decrement the counters. Entries out of the window — and
		// manual rows, which never enter the buckets — are simply dropped.
		if !fe.manual && ps.rawStart >= ps.raw24Start {
			ps.foldIntoBucket(fe)
		}
		ps.rawStart++
	}
	// Evict minute buckets older than the 24h window, decrementing counters.
	// A bucket is fully out of the window once its minute start is before the
	// cutoff (at most a one-minute over-eviction, negligible for a 24h window
	// and consistent with the entry-level cutoff the old code used).
	cutoff24 := e.ts - retentionSeconds
	for ps.bucketStart < len(ps.buckets) && ps.buckets[ps.bucketStart].minute < cutoff24 {
		ps.total24 -= int(ps.buckets[ps.bucketStart].total)
		ps.lost24 -= int(ps.buckets[ps.bucketStart].lost)
		ps.bucketStart++
	}
	// Reclaim bucket front space (buckets max out at 1440 live).
	if ps.bucketStart > 0 && (ps.bucketStart >= 256 || ps.bucketStart*2 >= len(ps.buckets)) {
		nb := copy(ps.buckets, ps.buckets[ps.bucketStart:])
		ps.buckets = ps.buckets[:nb]
		ps.bucketStart = 0
	}
	// Advance raw24Start past live raw entries that have aged out of the 24h
	// window. The raw tier keeps the last-60 tail (slow-interval sensors), so
	// it can hold entries older than 24h; they stay in the series (the
	// 60-probe inspector window reads them) but must not count toward
	// uptime_24h. Folded entries (index < rawStart) are dead — the clamp keeps
	// them from being re-counted (a fold is a no-op for the counters: the
	// entry either stays in the window via its bucket or leaves via bucket
	// eviction).
	if ps.raw24Start < ps.rawStart {
		ps.raw24Start = ps.rawStart
	}
	for ps.raw24Start < len(ps.raw) && ps.raw[ps.raw24Start].ts < cutoff24 {
		if !ps.raw[ps.raw24Start].manual {
			if isLost(ps.raw[ps.raw24Start].rtt) {
				ps.lost24--
			}
			ps.total24--
		}
		ps.raw24Start++
	}
}

// foldIntoBucket folds one aged-out raw entry into the per-minute buckets.
// Entries fold in ts order (oldest first), so the new minute is always >= the
// newest bucket's minute: equal folds in place, greater appends a new bucket.
func (ps *probeSeries) foldIntoBucket(e probeEntry) {
	minute := e.ts / 60 * 60
	lost := isLost(e.rtt)
	if n := len(ps.buckets); n > ps.bucketStart && ps.buckets[n-1].minute == minute {
		b := &ps.buckets[n-1]
		b.total++
		if lost {
			b.lost++
		} else {
			b.sumRTT += float64(e.rtt)
			if !b.hasRTT || e.rtt > b.maxRTT {
				b.maxRTT = e.rtt
				b.hasRTT = true
			}
		}
		return
	}
	b := minuteBucket{minute: minute, total: 1}
	if lost {
		b.lost = 1
	} else {
		b.sumRTT = float64(e.rtt)
		b.maxRTT = e.rtt
		b.hasRTT = true
	}
	ps.buckets = append(ps.buckets, b)
}

// snapshot copies the live RAW entries (oldest-first) into a fresh slice so a
// reader can compute stats off the shared lock without the series mutating
// mid-read. The minute buckets are not copied: the per-probe read path
// (computeSensorStats) never needs them, and the graph reads them in place
// under the read lock.
func (ps *probeSeries) snapshot() []probeEntry {
	n := ps.len()
	out := make([]probeEntry, n)
	copy(out, ps.raw[ps.rawStart:])
	return out
}

// graphPoints serves the inspector's 1h/24h graphs from the in-memory series
// (raw entries + minute buckets) instead of a per-request SQL aggregate.
// bucketSecs is the bucket size (60 for 1h, 900 for 24h); rangeSecs is the
// window (3600 for 1h, 86400 for 24h); nowUnix anchors the window. Manual rows
// are excluded (diagnostic clicks, not scheduled samples) — matching the SQL
// graph's `manual = 0`. Returns points oldest-first with T = bucket start
// (epoch seconds), the same shape the SQL path returned.
func (ps *probeSeries) graphPoints(bucketSecs, rangeSecs int, nowUnix int64) []GraphPoint {
	cutoff := nowUnix - int64(rangeSecs)
	bucketSize := int64(bucketSecs)
	type agg struct {
		total  int
		lost   int
		sumRTT float64
		maxRTT float32
		hasRTT bool
	}
	m := make(map[int64]*agg)
	get := func(b int64) *agg {
		a := m[b]
		if a == nil {
			a = &agg{}
			m[b] = a
		}
		return a
	}
	addEntry := func(ts int64, rtt float32, manual bool) {
		if manual || ts < cutoff {
			return
		}
		a := get(ts / bucketSize * bucketSize)
		a.total++
		if isLost(rtt) {
			a.lost++
		} else {
			a.sumRTT += float64(rtt)
			if !a.hasRTT || rtt > a.maxRTT {
				a.maxRTT = rtt
				a.hasRTT = true
			}
		}
	}
	addBucket := func(mb *minuteBucket) {
		if mb.minute < cutoff {
			return
		}
		a := get(mb.minute / bucketSize * bucketSize)
		a.total += int(mb.total)
		a.lost += int(mb.lost)
		a.sumRTT += mb.sumRTT
		if mb.hasRTT && (!a.hasRTT || mb.maxRTT > a.maxRTT) {
			a.maxRTT = mb.maxRTT
			a.hasRTT = true
		}
	}
	// Minute buckets (older than the raw window, within 24h), then the raw
	// tier (the raw window). A raw entry and a bucket never cover the same
	// probe — a probe is in exactly one tier — so there is no double-count.
	for i := ps.bucketStart; i < len(ps.buckets); i++ {
		addBucket(&ps.buckets[i])
	}
	for i := ps.rawStart; i < len(ps.raw); i++ {
		e := &ps.raw[i]
		addEntry(e.ts, e.rtt, e.manual)
	}
	keys := make([]int64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	points := make([]GraphPoint, 0, len(keys))
	for _, k := range keys {
		a := m[k]
		p := GraphPoint{T: k, Total: a.total, Lost: a.lost}
		if a.total > 0 {
			p.LossPct = float64(a.lost) / float64(a.total) * 100
		}
		if a.total-a.lost > 0 {
			avg := a.sumRTT / float64(a.total-a.lost)
			p.Avg = &avg
		}
		if a.hasRTT {
			v := float64(a.maxRTT)
			p.Max = &v
		}
		points = append(points, p)
	}
	return points
}

type sensorConfig struct {
	id     string
	name   string
	target string
	// probeType is the probe transport: "icmp" (default), "http", or
	// "tcp". It
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

	// gens is a per-sensor generation counter that closes the syncSensors
	// read→apply TOCTOU WITHOUT holding pw.mu across a DB read. Restart and
	// SetPaused bump it (under pw.mu); syncSensors captures a fingerprint of
	// the whole map BEFORE its config read, then under the lock compares each
	// sensor's current generation against the fingerprint: a mismatch means a
	// config change landed in the gap, so that sensor is skipped (the bumping
	// op owns the re-sync — Restart signals syncReq, SetPaused already set
	// isPaused) instead of spawning with a stale config. This replaces the
	// old under-lock freshStates/freshConfig re-reads, which stalled every
	// sensorLoop (pw.mu is touched twice per tick) + healthz up to the 15s
	// busy_timeout. Guarded by mu; a nil map (bare
	// test workers) is safe — bumpGen lazily creates it, range/read over a
	// nil map are no-ops.
	gens map[string]int64

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

	// alertCfg is the typed settings snapshot the alert hot path reads
	// lock-free (see alertSettings in alerts.go): the gate (maintenance,
	// routing, re-alert interval) and the resolved delivery destinations.
	// It is stored with a safe default at construction and swapped
	// atomically by reloadAlertSettings — at worker start and after every
	// PUT /api/settings commit. Replaces the old per-read GetSetting calls
	// (and the activeProviders db.Ping fallback): a DB hiccup between
	// reloads no longer reads maintenance as off / scope as all, and the
	// hot path makes zero settings queries.
	alertCfg atomic.Pointer[alertSettings]

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
	pw := &ProbeWorker{
		sensors:         make(map[string]*ProbeState),
		loops:           make(map[string]context.CancelFunc),
		spawnedIDs:      make(map[string]bool),
		gens:            make(map[string]int64),
		db:              db,
		syncReq:         make(chan struct{}, 1),
		statsCache:      make(map[string]*probeSeries),
		lastPulse:       make(map[string]time.Time),
		alertOrderGates: make(map[string]chan func()),
		stopCtx:         ctx,
		stopCancel:      cancel,
	}
	// Store a safe default BEFORE the first DB load so the alert hot path
	// never derefs a nil snapshot, then replace it with the real DB state.
	// If the DB is unreadable at this instant, the default stands (alerts
	// enabled, scope all, 30-min re-alert, no providers) and the next
	// PUT /api/settings commit reloads the real state.
	pw.alertCfg.Store(defaultAlertSettings())
	pw.reloadAlertSettings()
	return pw
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
	// Enforce the 24h retention ONCE at startup: the retention
	// ticker's first fire is 1h after start, so a process that restarts more
	// often than hourly — crash loops, frequent updates — would never purge and
	// the probes/events tables would grow without bound. Running it here (not
	// just on the hourly tick) guarantees a sweep on every boot. It goes BEFORE
	// warmStats so the warm query reads an already-trimmed 24h window instead
	// of a stale backlog. It is idempotent and bounded (per-sensor batches), so
	// the one-time startup cost is a few milliseconds on a healthy DB.
	pw.purgeOld(ctx)
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
	// Capture the per-sensor generation fingerprint BEFORE any DB read.
	// Restart/SetPaused bump pw.gens under pw.mu; a fingerprint taken now lets
	// the under-lock reconcile below detect a config change that landed in the
	// read→apply gap (the stale-read TOCTOU the old under-lock freshStates /
	// freshConfig re-reads closed). This pw.mu section does NO DB I/O — copying
	// a small map is O(seen sensors), negligible — so it can never stall the
	// fleet the way an under-lock SQLite read could.
	pw.mu.Lock()
	genAtRead := make(map[string]int64, len(pw.gens))
	for id, g := range pw.gens {
		genAtRead[id] = g
	}
	pw.mu.Unlock()

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
		configs = append(configs, c)
	}
	if err := rows.Err(); err != nil {
		log.Printf("ProbeWorker: sensor query ended early: %v", err)
		partial = true
	}
	// Close the cursor NOW (nit 2026-10-24): an exhausted-but-open Rows
	// still holds its pooled connection until the top-level defer runs at
	// FUNCTION return. Closing on the happy path releases the connection
	// before the lock window (the defer above remains the error-path safety
	// net; Close is idempotent).
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

	// Reconcile under the lock with NO DB reads: the generation
	// fingerprint above replaces the old under-lock freshStates/freshConfig
	// re-reads. pw.mu is the hot lock every sensorLoop touches twice per tick
	// (plus healthz ActiveCount / LastHTTPStatus), so holding it across a
	// SQLite read stalled the whole fleet up to the 15s busy_timeout. A sensor
	// whose generation changed since genAtRead is skipped — a Restart/SetPaused
	// landed in the gap and owns the re-sync (Restart signals syncReq, which
	// fires a fresh pass with the new config; SetPaused already set isPaused in
	// place). Every other sensor's config + state are current at read time, so
	// the pre-read values are applied as-is — no re-read needed.
	pw.mu.Lock()
	defer pw.mu.Unlock()

	seen := make(map[string]bool, len(configs))
	for _, c := range configs {
		seen[c.id] = true
		if g, ok := pw.gens[c.id]; ok && g != genAtRead[c.id] {
			// Stale read: a config change landed in the read→apply gap. Skip —
			// the bumping op owns the re-sync. Any running loop keeps its
			// current in-memory state; the fresh pass re-reads and respawns if
			// needed (a row deleted in the gap is simply absent from the next
			// pass's configs, so the vanished-sensor pass owns it there).
			continue
		}
		ps, ok := pw.sensors[c.id]
		if !ok {
			ps = &ProbeState{id: c.id, isPaused: c.state == "paused", kick: make(chan struct{}, 1)}
			pw.sensors[c.id] = ps
		} else {
			ps.isPaused = c.state == "paused" // keep pause in sync with DB
		}
		if _, ok := pw.loops[c.id]; !ok {
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
				pw.sensorLoop(lctx, c.sensorConfig, resumed)
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

// bumpGen increments the sensor's generation counter so an in-flight
// syncSensors pass detects a config change that landed in its read→apply gap
// . Called under pw.mu by Restart and SetPaused. It lazily creates
// the map so bare test workers (&ProbeWorker{} with a nil gens) don't panic;
// syncSensors' fingerprint copy and Remove's delete are safe on a nil map too.
func (pw *ProbeWorker) bumpGen(id string) {
	if pw.gens == nil {
		pw.gens = make(map[string]int64)
	}
	pw.gens[id]++
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
	pw.bumpGen(id) // invalidate an in-flight syncSensors pass's stale read
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
	pw.bumpGen(id) // invalidate an in-flight syncSensors pass's stale read
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
	delete(pw.gens, id)       // nil-map delete is a safe no-op
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
		var kick chan struct{}
		if ps, ok := pw.sensors[c.id]; ok {
			kick = ps.kick
		}
		pw.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-kick:
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

// dbWriteTimeout bounds a single probe-record write:
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
// pulse is a diagnostic: recording it keeps the history honest, while
// keeping status and alerts driven only by the scheduled probe loop.
//
// The "status and alerts are unaffected" half is enforced by the manual=1
// tag: status derivation, loss/uptime aggregates, the sparkline, the 24h
// counters, and the graph endpoint all exclude manual rows.
//
// Works while paused (SPEC §2). Dispatches by sensor type, so an HTTP
// sensor's manual pulse makes an HTTP request.
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

	// The sensor's own configured timeout: // the pulse is the same probe the sensor runs on schedule, so a
	// slow-but-healthy target answers it. A legacy zeroed row falls back
	// to pingNowTimeout.
	timeout := time.Duration(timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = pingNowTimeout
	}
	o := probeTarget(ctx, probeType, target, timeout)

	var rttVal any
	if !o.lost {
		rttVal = o.rttMs
	}
	ts := time.Now().UTC()
	// Bounded write: a bare Exec can sit on the
	// 15s busy_timeout — longer than the ~10s shutdown drain budget —
	// and using the REQUEST ctx would wrongly discard a completed probe
	// when the browser closes the tab. A fresh capped context bounds the
	// write without inheriting either problem.
	writeCtx, cancelWrite := context.WithTimeout(context.Background(), dbWriteTimeout)
	defer cancelWrite()
	var dnsErrVal any
	if o.dnsErr != "" {
		dnsErrVal = o.dnsErr
	}
	if _, err := pw.db.ExecContext(writeCtx, "INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip, http_status, dns_error, manual) VALUES (?, ?, ?, ?, ?, ?, 1)",
		id, store.FormatTS(ts), rttVal, o.ip, o.httpCode, dnsErrVal); err != nil {
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
	// dnsErr: the name-resolution failure for a probe lost BEFORE a target
	// IP could be determined (empty for packet losses and HTTP probes).
	// Recorded on the row (probes.dns_error) so a dead local resolver
	// reads as "DNS failure", not "N hosts down" — the homelab resolver is
	// itself monitored, and its death used to flip every hostname sensor
	// to error at once (one root cause, an N-sensor storm).
	dnsErr string
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
	if probeType == "tcp" {
		r := probeTCP(ctx, target, timeout)
		o := probeOutcome{lost: r.Lost, ip: r.IP}
		if r.DNS && r.Err != nil {
			o.dnsErr = r.Err.Error()
		}
		if !r.Lost {
			o.rttMs = r.Elapsed.Seconds() * 1000
		}
		return o
	}
	// icmp (default)
	res := pingHost(ctx, target, timeout)
	o := probeOutcome{lost: res.Lost, ip: res.ResolvedIP, broken: res.Broken}
	if res.DNS {
		if res.Error != nil {
			o.dnsErr = res.Error.Error()
		} else {
			o.dnsErr = "dns resolution failed"
		}
	}
	if !res.Lost {
		o.rttMs = res.RTT.Seconds() * 1000
	}
	return o
}

func (pw *ProbeWorker) doProbe(ctx context.Context, c sensorConfig) {
	// timeout_ms<=0 fallback for a legacy zeroed row:
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

	var rttVal any
	var rttMs float64
	if !o.lost {
		rttVal = o.rttMs
		rttMs = o.rttMs
	}

	now := time.Now().UTC()
	// Bounded write: the probe ctx is correct here —
	// it is already cancelled-and-checked above (a cancelled probe drops
	// its result), and it lets shutdown interrupt a write parked on the
	// 15s busy_timeout instead of outrunning the drain budget.
	var dnsErrVal any
	if o.dnsErr != "" {
		dnsErrVal = o.dnsErr
	}
	if _, err := pw.db.ExecContext(ctx, "INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip, http_status, dns_error) VALUES (?, ?, ?, ?, ?, ?)", c.id, store.FormatTS(now), rttVal, o.ip, o.httpCode, dnsErrVal); err != nil {
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

	// The status write and the event row commit in ONE transaction (finding
	// #7): if the events INSERT failed after the UPDATE succeeded, the
	// transition was lost forever — rememberStatus had already advanced
	// lastStatus, so the next tick saw oldStatus == newStatus and never wrote
	// the event. A single tx makes the two atomic: a failed INSERT rolls back
	// the UPDATE too, lastStatus is not advanced, and the next tick retries
	// the whole transition.
	note := fmt.Sprintf("%s -> %s", oldStatus, newStatus)
	if newStatus == "up" {
		note = "recovered" // first transition back to up after warning/error
	}
	err = pw.db.ImmediateTx(ctx, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx, "UPDATE sensors SET status = ? WHERE id = ?", newStatus, c.id); err != nil {
			return err
		}
		_, err := conn.ExecContext(ctx, "INSERT INTO events (sensor_id, ts, from_status, to_status, note) VALUES (?, ?, ?, ?, ?)",
			c.id, store.Now(), oldStatus, newStatus, note)
		return err
	})
	if err != nil {
		// lastStatus is NOT advanced, so the next tick sees the same
		// transition and retries the write + event instead of believing it is done.
		log.Printf("ProbeWorker: failed to record status transition for %s: %v", c.id, err)
		return
	}
	pw.rememberStatus(c.id, newStatus) // only once the new status + event are durable

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
// - an IPv4 address (range-checked via net.ParseIP), or
// - a dotted hostname: one or more RFC 1123 labels ending in an
// alphabetic TLD (targetRe), or
// - a BARE single-label hostname (validSingleLabel): "nas", "pve",
// "router". These resolve on most home LANs via the resolver's
// search domain (resolv.conf "search") — the same names HTTP
// targets have always used. A label made purely of digits is
// rejected: net.ParseIP has already taken real IPv4s, so a bare
// numeric label is a truncated-IP typo, not a hostname.
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
	// Length bound: names cap at 60 and tags at 30,
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
