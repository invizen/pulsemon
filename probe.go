package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ProbeState struct {
	id       string
	isPaused bool
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
	spikeMult int
	// lastErrCount is the global ICMP-socket error counter as of the last
	// probe; deriveStatus compares against it to detect "probing is broken".
	lastErrCount int64
}

type ProbeWorker struct {
	sensors map[string]*ProbeState
	mu      sync.Mutex
	loops   map[string]context.CancelFunc
	db      *DB

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
}

// retentionSeconds is how long of a probe history the in-memory series keeps.
// It must be >= the longest window the dashboard reads (24h uptime), so the
// cache never goes stale relative to a DB read. Mirrors purgeOld's 24h.
const retentionSeconds int64 = 24 * 3600

func NewProbeWorker(db *DB) *ProbeWorker {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProbeWorker{
		sensors:    make(map[string]*ProbeState),
		loops:      make(map[string]context.CancelFunc),
		db:         db,
		statsCache: make(map[string]*probeSeries),
		stopCtx:    ctx,
		stopCancel: cancel,
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

	pw.syncSensors(ctx) // immediate first pass
	// Warm the shared ICMP socket now so a socket-level failure is visible
	// in healthz immediately instead of after the first probe tick.
	if _, err := getSharedConn(); err != nil {
		log.Printf("ProbeWorker: ICMP socket init: %v", err)
	}
	// Populate the stats cache from the DB so the first dashboard poll after a
	// restart serves populated cards (RTT, sparkline, 24h uptime) instead of
	// blanking them for up to an interval while probes re-accumulate.
	pw.warmStats()
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
		case <-retention.C:
			pw.purgeOld()
		}
	}
}

func (pw *ProbeWorker) syncSensors(ctx context.Context) {
	rows, err := pw.db.Query(`SELECT id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state
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
	for rows.Next() {
		var c activeCfg
		if err := rows.Scan(&c.id, &c.name, &c.target, &c.probeType, &c.intervalS, &c.timeoutMS, &c.lossWarn, &c.downAfter, &c.spikeMult, &c.state); err != nil {
			continue
		}
		if c.probeType == "" {
			c.probeType = "icmp" // legacy rows pre-migration
		}
		if c.spikeMult < 2 {
			c.spikeMult = 5
		}
		configs = append(configs, c)
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

	seen := make(map[string]bool, len(configs))
	for _, c := range configs {
		seen[c.id] = true
		ps, ok := pw.sensors[c.id]
		if !ok {
			ps = &ProbeState{id: c.id, isPaused: c.state == "paused"}
			pw.sensors[c.id] = ps
		} else {
			ps.isPaused = c.state == "paused" // keep pause in sync with DB
		}
		if _, ok := pw.loops[c.id]; !ok {
			lctx, lcancel := context.WithCancel(ctx)
			pw.loops[c.id] = lcancel
			cfg := c.sensorConfig
			pw.wg.Add(1)
			go func() {
				defer pw.wg.Done()
				pw.sensorLoop(lctx, cfg)
			}()
		}
	}

	// Stop loops for sensors that vanished or were deleted.
	for id, cancel := range pw.loops {
		if !seen[id] {
			cancel()
			delete(pw.loops, id)
			delete(pw.sensors, id)
		}
	}
}

// SetPaused flips the in-memory pause flag immediately (API PATCH fast path).
func (pw *ProbeWorker) SetPaused(id string, paused bool) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if ps, ok := pw.sensors[id]; ok {
		ps.isPaused = paused
	}
}

// Restart respawns a sensor's probe loop so config changes take effect
// without a process restart: target/interval/timeout are read by the loop
// and loss_warn/down_after by deriveStatus, all from the spawn-time config
// copy captured in syncSensors.
func (pw *ProbeWorker) Restart(id string) {
	pw.mu.Lock()
	if cancel, ok := pw.loops[id]; ok {
		cancel()
		delete(pw.loops, id)
	}
	delete(pw.sensors, id)
	pw.mu.Unlock()
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
// probing starts.
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

	// One batched fetch for all sensors (never a per-sensor query in a loop —
	// same pool-starvation rule as SensorTagsFor), oldest-first, so each
	// series is built in append order. The load is the UNION of the two
	// windows the stats read: the last 60 probes PER sensor (a slow-interval
	// sensor's window can span >24h) plus the full 24h retention — matching
	// exactly what the live series will hold, so a fresh process serves the
	// same window the DB path would have.
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
		args = append(args, cutoff.Format(time.RFC3339Nano))
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
	pw.statsMu.RLock()
	s, ok := pw.statsCache[id]
	var entries []probeEntry
	if ok {
		entries = s.snapshot()
	}
	pw.statsMu.RUnlock()
	if len(entries) == 0 {
		return nil
	}
	return computeSensorStats(entries, nowUnix)
}

// GetStats computes a sensor's SensorStats from the in-memory series,
// anchored to the wall clock. Returns nil when the sensor has no data
// (matches the DB path, which returns nil for a zero-probe window).
// Pure read — no DB.
func (pw *ProbeWorker) GetStats(id string) *SensorStats {
	return pw.statsFor(id, time.Now().Unix())
}

// ResetStatsFor empties one sensor's cached series (used by the clear-history
// endpoint so the cache doesn't outlive the DB rows it mirrors).
func (pw *ProbeWorker) ResetStatsFor(id string) {
	pw.statsMu.Lock()
	delete(pw.statsCache, id)
	pw.statsMu.Unlock()
}

// ResetStatsAll empties every sensor's cached series (clear-all-history).
func (pw *ProbeWorker) ResetStatsAll() {
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
	// statusWindow probes (a new sensor) just means a shorter window — the
	// same rule deriveStatus applies (up on the newest 2, warning on loss%).
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

func (pw *ProbeWorker) sensorLoop(ctx context.Context, c sensorConfig) {
	interval := time.Duration(c.intervalS) * time.Second

	// Stagger the first tick by a deterministic per-sensor phase (hash of the
	// id, 0 .. interval). Without this, every sensor added at the same time —
	// or every sensor sharing an interval — fires on the same wall-clock second,
	// producing a write thundering-herd against SQLite. Spreading the phases
	// turns N simultaneous writes into N writes spread across the interval.
	phase := time.Duration(fnvHash([]byte(c.id))) % time.Duration(interval)
	if phase < 250*time.Millisecond {
		phase += 250 * time.Millisecond // never probe in the first instant
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
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
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
			pw.doProbe(c)
		}
	}
}

// fnvHash is a 64-bit FNV-1a over the byte slice — cheap, deterministic, and
// only used to derive a stable stagger phase per sensor id.
func fnvHash(b []byte) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	var h uint64 = offset64
	for _, c := range b {
		h ^= uint64(c)
		h *= prime64
	}
	return h
}

// pingNowTimeout bounds the "Pulse Now" manual probe. It is a fixed 1s,
// independent of the sensor's configured timeout: a manual pulse is a quick
// diagnostic, not a scheduled probe, so it shouldn't wait out a long
// configured timeout. It is a var (like the other bounded call sites) so a
// test can shorten it.
var pingNowTimeout = time.Second

// PingNow performs one immediate "Pulse Now" probe and RECORDS it: the row
// lands in probes (history + dashboard sparkline) and the in-memory stats
// cache, exactly as a scheduled tick would — but it deliberately does NOT
// derive a status, write a transition event, or fire an alert. A manual
// pulse is a diagnostic: recording it keeps the history honest (the user saw
// a real RTT / loss at that instant), while keeping status and alerts driven
// only by the scheduled probe loop (a single manual probe must not flip a
// healthy sensor to error or fire a recovery webhook). Works while paused
// (SPEC §2). Dispatches by sensor type, so an HTTP sensor's manual pulse
// makes an HTTP request (the card's "Pulse Now" shows its status code).
func (pw *ProbeWorker) PingNow(id string) (probeOutcome, error) {
	var target, probeType string
	if err := pw.db.QueryRow("SELECT target, type FROM sensors WHERE id = ?", id).Scan(&target, &probeType); err != nil {
		return probeOutcome{}, err // sql.ErrNoRows for an unknown sensor
	}
	if probeType == "" {
		probeType = "icmp"
	}

	o := probeTarget(probeType, target, pingNowTimeout)

	var rttVal interface{}
	if !o.lost {
		rttVal = o.rttMs
	}
	now := time.Now().UTC()
	if _, err := pw.db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip, http_status) VALUES (?, ?, ?, ?, ?)",
		id, now.Format(time.RFC3339Nano), rttVal, o.ip, o.httpCode); err != nil {
		return o, fmt.Errorf("record echo probe: %w", err)
	}
	// Keep the in-memory stats cache in lockstep with the DB row (the same
	// lockstep doProbe maintains), so the dashboard reflects the echo.
	var rttPtr *float64
	if !o.lost {
		v := o.rttMs
		rttPtr = &v
	}
	pw.recordProbe(id, probeEntry{ts: now.Unix(), rtt: rttPtr})
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
}

// probeTarget dispatches one probe to the sensor's transport. A var so a
// test can stub the whole probe without opening a socket or making a request.
var probeTarget = func(probeType, target string, timeout time.Duration) probeOutcome {
	if probeType == "http" {
		r := probeHTTP(target, timeout)
		o := probeOutcome{lost: r.Lost, ip: r.IP, httpCode: r.Status, certExpiry: r.CertExpiry}
		if !r.Lost {
			o.rttMs = r.Elapsed.Seconds() * 1000
		}
		return o
	}
	// icmp (default)
	res := pingHost(target, timeout)
	o := probeOutcome{lost: res.Lost, ip: res.ResolvedIP}
	if !res.Lost {
		o.rttMs = res.RTT.Seconds() * 1000
	}
	return o
}

func (pw *ProbeWorker) doProbe(c sensorConfig) {
	c.lastErrCount = probeErrCount.Load()
	o := probeTarget(c.probeType, c.target, time.Duration(c.timeoutMS)*time.Millisecond)

	var rttVal interface{}
	var rttMs float64
	if !o.lost {
		rttVal = o.rttMs
		rttMs = o.rttMs
	}

	now := time.Now().UTC()
	if _, err := pw.db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip, http_status) VALUES (?, ?, ?, ?, ?)", c.id, now.Format(time.RFC3339Nano), rttVal, o.ip, o.httpCode); err != nil {
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

	// Read the current status BEFORE deriving the new one: deriveStatus's
	// fast-recovery rule needs to know whether the sensor was in ERROR (one
	// good probe then flips it up) vs WARNING (it must have 2 straight good
	// probes). The DB is the source of truth (survives restarts).
	var oldStatus string
	if err := pw.db.QueryRow("SELECT status FROM sensors WHERE id = ?", c.id).Scan(&oldStatus); err != nil {
		return
	}

	newStatus := pw.deriveStatus(c, oldStatus)

	// Keep the in-memory lastStatus + fastRetry flag in lockstep so the
	// sensorLoop can pick the next-tick cadence without a DB read. For HTTP
	// sensors, also remember the status code + cert expiry so the card can
	// show "HTTP 503" / "cert expires in 3d" without a DB read per poll.
	pw.mu.Lock()
	if ps, ok := pw.sensors[c.id]; ok {
		ps.lastStatus = newStatus
		ps.fastRetry = newStatus == "error"
		if c.probeType == "http" {
			ps.lastHTTPStatus = o.httpCode
			ps.lastCertExpiry = o.certExpiry
		}
	}
	pw.mu.Unlock()

	if newStatus == oldStatus {
		// No transition: a sustained ERROR may be due for a re-alert.
		// Warning is never re-alerted (loss flapping is dashboard noise).
		if newStatus == "error" {
			pw.maybeRealert(c, newStatus, rttMs)
		}
		return
	}

	if _, err := pw.db.Exec("UPDATE sensors SET status = ? WHERE id = ?", newStatus, c.id); err != nil {
		log.Printf("ProbeWorker: failed to update status for %s: %v", c.id, err)
		return
	}

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
		pw.launchAlert(func() { pw.sendAlert(c.id, c.name, c.target, oldStatus, newStatus, rttMs) })
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
		pw.launchAlert(func() { pw.sendRealert(c.id, c.name, c.target, status, rttMs) })
	}
}

func (pw *ProbeWorker) setAlertState(id, status string, ts time.Time) {
	_, _ = pw.db.Exec(`INSERT INTO alert_state (sensor_id, status, last_ts) VALUES (?, ?, ?)
		ON CONFLICT(sensor_id) DO UPDATE SET status = excluded.status, last_ts = excluded.last_ts`,
		id, status, ts.Format(time.RFC3339Nano))
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
//	up        — the newest probe succeeded AND the sensor is either
//	            recovering from ERROR (lastStatus == "error" — one good
//	            reply is enough to prove it's back) or the probe before it
//	            also succeeded (steady state / brand-new sensor). A flapping
//	            sensor in WARNING (loss, success, loss, success…) reads
//	            warning, not up — one good probe amid ongoing loss is not
//	            "recovered", and error+1-success would make a flapping link
//	            oscillate up/error every cycle.
//	error     — `down_after` consecutive losses from the newest probe
//	warning   — window loss% (last `statusWindow` probes) >= loss_warn
//	fallback  — warning (a loss is in the recent window but it's not
//	            error and the up rule doesn't hold)
//
// Consequence of the up-first ordering: a sensor back from a long outage
// reads up on its FIRST good probe (fast recovery — it was already
// confirmed down, one reply is sufficient proof of return), while a sensor
// merely losing packets reads warning until it has 2 straight good probes.
//
// The window read is max(statusWindow, down_after) rows so that a sensor
// configured with down_after > statusWindow still has enough history for the
// consecutive-loss test. A probe-level ICMP error (broken socket) forces
// warning so a dead probe path never reads as "up".
func (pw *ProbeWorker) deriveStatus(c sensorConfig, lastStatus string) string {
	// Broken probe path (e.g. ICMP socket cannot be created): probes never
	// land, so we cannot know the real state — flag warning, never up.
	if probeErrCount.Load() > c.lastErrCount {
		return "warning"
	}

	// Fetch enough history for the loss% window AND the consecutive-loss
	// test, newest first.
	limit := statusWindow
	if c.downAfter > limit {
		limit = c.downAfter
	}
	rows, err := pw.db.Query("SELECT rtt_ms FROM probes WHERE sensor_id = ? ORDER BY ts DESC LIMIT ?", c.id, limit)
	if err != nil {
		// Can't read the probe history, so we can't know the real state —
		// report unknown (warning), never "up". Matches the broken-socket path
		// above: a monitoring tool must not fake a recovery it can't confirm.
		// A transient WAL/SQLite hiccup just reads degraded for this one tick
		// and self-clears next tick, and it never fires an alert (warning is
		// dashboard-only — see alertableTransition).
		return "warning"
	}
	defer rows.Close() // top-level: this function has a post-Query return ("warning"),
	// so a bare rows.Close() below the loop would leak the pooled connection
	// on that path — the hang under SetMaxOpenConns(10) the issue describes.
	var recent []*float64 // index 0 = newest; nil = lost, non-nil = rtt
	for rows.Next() {
		var rtt *float64
		if rows.Scan(&rtt) == nil {
			recent = append(recent, rtt)
		}
	}

	if len(recent) == 0 {
		return "up" // no data yet
	}

	// UP (highest precedence): the newest probe succeeded, and the sensor is
	// either recovering from ERROR (fast recovery — one good reply is enough
	// once it was confirmed down) or the previous probe also succeeded (2
	// straight = steady up; with only one probe recorded, a single success
	// is enough — new-sensor grace). Checked before error/warning so
	// recovery is immediate, but a flapping sensor in WARNING (newest
	// success, 2nd-newest loss, lastStatus=warning) does NOT read up.
	if recent[0] != nil && (lastStatus == "error" || len(recent) == 1 || recent[1] != nil) {
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

	// WARNING: loss% over the status window meets loss_warn.
	totalLost := 0
	for _, r := range recent {
		if r == nil {
			totalLost++
		}
	}
	if c.lossWarn > 0 {
		lossPct := float64(totalLost) / float64(len(recent)) * 100
		if lossPct >= float64(c.lossWarn) {
			return "warning"
		}
	}

	// WARNING: a loss is in the recent window but it's not error and not up.
	return "warning"
}

// purgeOld enforces 24-hour retention on probes/events (SPEC §3).
// 24h is the longest window the dashboard reads (24h graph / uptime 24h), so
// nothing on screen ever needs older data. Revisit if historical reporting
// is added later.
//
// The comparison is a string compare, but that is EXACT here because both
// sides use the same format: the stored ts is RFC3339Nano (written by the
// probe loop) and the cutoff is built in the same format, so the
// lexicographic order matches the chronological order for all real instants.
// (The v0.1.18 window bug was different: it compared RFC3339 against
// datetime('now')'s space-separated output — two DIFFERENT formats — which
// is what made the string compare wrong. Same-format string compares are
// safe; mixed-format ones are not.) An epoch compare was considered and
// rejected: strftime('%s') truncates fractional seconds, introducing a
// 1-second boundary error that the same-format string compare does not have.
func (pw *ProbeWorker) purgeOld() {
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339Nano)
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

// activeProviders returns every provider currently receiving alerts.
func (pw *ProbeWorker) activeProviders() []providerMeta {
	var out []providerMeta
	for _, p := range providerList {
		if p.Enabled(pw.db) && p.HasURL(pw.db) {
			out = append(out, p)
		}
	}
	return out
}

// providerStatus is the per-provider read the settings API returns to the
// dashboard.
type providerStatus struct {
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	HasURL  bool   `json:"has_url"`
	URL     string `json:"url"` // masked; empty when none
	Source  string `json:"source"`
}

func (pw *ProbeWorker) providerStatuses() []providerStatus {
	out := []providerStatus{}
	for _, p := range providerList {
		url := pw.db.GetSetting(p.Kind + "_url")
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
			HasURL:  url != "",
			URL:     webhookMasked(url),
			Source:  source,
		})
	}
	return out
}

func (pw *ProbeWorker) sendWebhook(id, name, target, oldState, state string, rttMs float64, reAlert bool) {
	for _, p := range pw.activeProviders() {
		url := pw.db.GetSetting(p.Kind + "_url")
		if url == "" && p.EnvFallback != "" {
			url = os.Getenv(p.EnvFallback)
		}
		if url == "" {
			continue
		}
		switch p.Kind {
		case "google_chat":
			card := cardFor(oldState, state, name, target, rttMs)
			if reAlert {
				card = cardForRe(state, name, target, rttMs)
			}
			pw.postJSON(url, map[string]string{"text": card})
		case "discord":
			card := discordCard(oldState, state, name, target, rttMs)
			if reAlert {
				card = discordCardRe(state, name, target, rttMs)
			}
			pw.postJSON(url, map[string]string{"content": card})
		}
	}
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
	if url == "" {
		return false, "no " + p.Label + " webhook URL configured"
	}
	var body map[string]string
	if p.Kind == "discord" {
		body = map[string]string{"content": "🟢 **pulsemon: test alert**\nSensor: settings · Target: webhook-verify · State: **test** — your Discord webhook works."}
	} else {
		body = map[string]string{"text": "🟢 *pulsemon: test alert*\n*Sensor*: settings\n*Target*: webhook-verify\n*State*: **test** — this message confirms your " + p.Label + " webhook works."}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(mustJSON(body)))
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookClient.Do(req)
	if err != nil {
		return false, err.Error()
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
// give the delivery a bounded second chance after Run returns.
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
func (pw *ProbeWorker) sendAlert(id, name, target, oldState, state string, rttMs float64) {
	pw.sendWebhook(id, name, target, oldState, state, rttMs, false)
}

// sendRealert notifies that a sensor has stayed in the same non-up state.
// oldState == state (the re-alert is not a transition; the card just says
// "still <state>").
func (pw *ProbeWorker) sendRealert(id, name, target, state string, rttMs float64) {
	pw.sendWebhook(id, name, target, state, state, rttMs, true)
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

func cardFor(oldState, state, name, target string, rttMs float64) string {
	icon := map[string]string{"up": "🟢", "warning": "🟡", "error": "🔴"}[state]
	if icon == "" {
		icon = "🟢"
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
	icon := map[string]string{"warning": "🟡", "error": "🔴"}[state]
	if icon == "" {
		icon = "🟢"
	}
	card := fmt.Sprintf("%s *pulsemon: still %s (re-alert)*\n*Sensor*: %s\n*Target*: %s\n*State*: **%s** — no change, re-notifying",
		icon, state, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n*Ping*: %d ms", int(rttMs+0.5))
	}
	return card
}

// Discord uses Markdown (**bold**, no *italic* emphasis); the card is plain
// content. Same information, Discord-flavored.
func discordCard(oldState, state, name, target string, rttMs float64) string {
	icon := map[string]string{"up": "🟢", "warning": "🟡", "error": "🔴"}[state]
	if icon == "" {
		icon = "🟢"
	}
	title := recoveryTitle(oldState, state)
	card := fmt.Sprintf("%s **pulsemon: %s**\n**Sensor:** %s\n**Target:** %s\n**State:** %s", icon, title, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n**Ping:** %d ms", int(rttMs+0.5))
	}
	return card
}

func discordCardRe(state, name, target string, rttMs float64) string {
	icon := map[string]string{"warning": "🟡", "error": "🔴"}[state]
	if icon == "" {
		icon = "🟢"
	}
	card := fmt.Sprintf("%s **pulsemon: still %s (re-alert)**\n**Sensor:** %s\n**Target:** %s\n**State:** %s — no change, re-notifying", icon, state, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n**Ping:** %d ms", int(rttMs+0.5))
	}
	return card
}

// postJSON delivers a JSON payload to a webhook with the shared hardened
// client (10s timeout, no redirects). The POST is bound to pw.stopCtx so
// that on shutdown a delivery stuck in a network blip is aborted at its
// next read instead of holding DrainAlerts for the full client timeout.
func (pw *ProbeWorker) postJSON(url string, payload map[string]string) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(pw.stopCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("webhook: send failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookClient.Do(req)
	if err != nil {
		log.Printf("webhook: send failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		log.Printf("webhook: endpoint redirected (refused to follow — possible misconfiguration)")
		return
	}
	if resp.StatusCode >= 300 {
		log.Printf("webhook: endpoint returned %d", resp.StatusCode)
	}
}

// newID generates a unique sensor id.
func newID() string {
	return uuid.NewString()
}

// validateTarget guards against SQL/host injection-ish junk in targets.
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
