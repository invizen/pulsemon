package main

import (
	"context"
	"log"
	"math"
	"pulsemon/internal/store"
	"sort"
	"strings"
	"time"
)

// Stats cache: the in-memory probe series and per-sensor statistics
// that keep the dashboard read path off SQLite (warmStats/recordProbe).

// probeEntry is one probe in the in-memory stats series: its UTC epoch second
// and its RTT in ms (nil = packet lost). The series is what makes the
// dashboard read path (GetStats) an O(1) map lookup instead of 4 SQLite
// queries per sensor — the whole point of v0.1.18.
type probeEntry struct {
	ts int64 // UTC epoch seconds (matches CAST(strftime('%s', ts)))
	// rtt is the reply time in ms; NaN = lost probe (matches SQL
	// rtt_ms IS NULL). A value — not *float64 — so the series is
	// pointer-free: 16-byte entries, no per-reply heap float for the GC to
	// scan (at 100 sensors x 24h x 5s that is ~1.7M entries, so the old layout was tens of MB of heap pointers).
	rtt float32
	// manual marks a "Pulse Now" row: it stays in the series (the 60-probe
	// inspector window reads it) but is excluded from status derivation
	// (recentFromCache skips it) AND from every loss/uptime aggregate —
	// the 1h loss/avg, the status window, the 24h counters, the sparkline
	// (append + computeSensorStats skip it) — so a diagnostic click can
	// never make a healthy sensor show packet loss. See the probes.manual
	// column.
	manual bool
}

// isLost reports whether a series RTT is a lost probe (NaN). Written as a
// self-comparison because Go's math.IsNaN only takes float64.
func isLost(rtt float32) bool { return rtt != rtt }

// rttToPtr converts a series RTT (NaN = lost) to the API shape
// (*float64, nil = lost) without changing the JSON contract.
func rttToPtr(rtt float32) *float64 {
	if isLost(rtt) {
		return nil
	}
	v := float64(rtt)
	return &v
}

// minuteBucket is one minute of folded probe history: the per-minute
// {total, lost, sumRTT, maxRTT} aggregate that keeps the in-memory series
// bounded at max(1h, last-60) raw entries and lets the 24h graph
// be served from memory — folded into 15-min buckets — instead of a
// per-request SQL aggregate over the probes table. Only non-manual probes are
// folded in (a diagnostic click must not move the graph or the uptime counters).
type minuteBucket struct {
	minute int64   // minute start, epoch seconds (ts/60*60)
	total  int32   // non-manual probes in the minute
	lost   int32   // non-manual lost probes in the minute
	sumRTT float64 // sum of non-lost RTTs (ms) — feeds the graph AVG
	maxRTT float32 // max non-lost RTT (ms) — feeds the graph MAX
	hasRTT bool    // at least one non-lost probe (maxRTT valid)
}

// probeSeries is an append-only, oldest-first probe log split into two tiers:
//
//   - raw: the entries the per-probe read path needs at full resolution —
//     max(1h, last 60). The 60-probe inspector window, the status window, the
//     1h loss/avg, and the sparkline all read from raw (computeSensorStats).
//   - buckets: per-minute {total, lost, sumRTT, maxRTT} aggregates for the
//     entries older than the raw window (up to 24h). The 24h graph folds these
//     into 15-min buckets; the 24h uptime comes from the incremental counters
//     below, so the graph and the uptime never need a raw scan past 1h.
//
// Appending is amortized O(1): the new entry lands in raw, raw entries that
// age out of the raw window are folded into a minute bucket (each entry is
// folded exactly once), and minute buckets older than 24h are evicted
// (decrementing the 24h counters). This bounds memory at ~max(1h,60) raw
// entries + 1440 minute buckets per sensor — ~57 KB at a 5s interval — instead
// of a full 24h of raw probes (17,280 entries ≈ 276 KB, up to ~2× with slice
// slack). Slow-interval sensors (whose last-60 window already spans >1h) fold
// nothing and stay at ~60 raw entries + no buckets, as before.
type probeSeries struct {
	raw      []probeEntry
	rawStart int // index (into raw) of the oldest live raw entry
	// raw24Start is the first live raw index inside the 24h window (ts >=
	// newest - retentionSeconds). The raw tier keeps the last-60 tail even for
	// slow-interval sensors, so it can hold entries OLDER than 24h (kept for
	// the 60-probe inspector window); raw24Start walks forward past them so
	// they stay in the series but drop out of the 24h counters. It is clamped
	// to >= rawStart (folded entries are dead and never re-counted).
	raw24Start int

	buckets     []minuteBucket
	bucketStart int // index (into buckets) of the oldest live bucket

	// Incremental 24h counters: total24/lost24 count the LIVE entries inside
	// the 24h window (raw from raw24Start + buckets) so the per-poll stats
	// read is O(1) for uptime instead of a full-series scan. append maintains
	// them: a new non-manual entry is always inside its own window (+1);
	// advancing raw24Start past a raw entry out of the window (-1); and
	// evicting a minute bucket older than 24h subtracts that bucket's
	// total/lost. Folding a raw entry into a bucket is a no-op for the counters
	// (it stays inside the window). Manual "Pulse Now" rows are never counted
	// (a diagnostic click must not move uptime_24h): append skips them on the
	// way in, folding drops them (no bucket), and both walk paths skip them.
	total24 int
	lost24  int
}

// warmStats loads every active sensor's 24h probe history into the cache so a
// fresh process (deploy/restart) serves populated cards immediately instead of
// blanking them until each sensor re-accumulates a window. Runs once, before
// probing starts.
func (pw *ProbeWorker) warmStats(ctx context.Context) {
	// ctx: the warm UNION query on a large DB is
	// the first thing Run does; a shutdown landing during it must be able
	// to abort the load instead of serving from a half-warmed process.
	ids, err := pw.db.QueryContext(ctx, "SELECT id FROM sensors WHERE state = 'active'")
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

	// The warm-up is two phases, matching exactly what the live series holds
	// (the 24h window + the last-60 inspector tail):
	//
	//   Phase 1: the full 24h retention window for every sensor — a plain
	//   index range scan on idx_probes_sensor_ts (no window function, no
	//   dedupe). This is the bulk of the data and gives correct 24h counters
	//   for EVERY sensor (the 24h counters count exactly the 24h rows).
	//
	//   Phase 2: for the few SLOW sensors (fewer than 60 probes in 24h —
	//   long-interval ones whose 60-probe inspector window spans past the
	//   24h cutoff), a per-sensor LIMIT 60 backfill of their last 60 probes.
	//   The last-60 is a superset of the sensor's 24h rows, so it REPLACES
	//   the phase-1 series (no dedupe). A fast sensor's last 60 are all
	//   inside 24h, so phase 1 already covers it and it is skipped.
	//
	// The old query ran ROW_NUMBER() over every sensor's full history plus a
	// deduping UNION — a temp B-tree over the whole 24h set (~1.7M rows at
	// 100 sensors / 5s). Splitting it this way drops both the window function
	// and the dedupe; phase 2 is a handful of small per-sensor queries (only
	// the slow sensors need it), so a large fleet of fast sensors pays just
	// the phase-1 scan.
	//
	// manual MUST be selected: warmed Pulse-Now rows default to manual=false
	// otherwise and re-enter the aggregates + status derivation as scheduled
	// probes for up to 24h after every restart — the exact class the
	// 2026-10-23 manual-exclusion batch closed on the live and DB paths.
	//
	// Phase 1 runs in store.InQueryChunk batches (see db.go): one IN-clause
	// per chunk stays far under the driver's 32,766 host-parameter limit, so
	// a very large fleet can't fail the warm-up with "too many SQL variables".
	// Partitioning by sensor id keeps each sensor's rows in exactly one chunk,
	// so per-sensor order is preserved. The closure defers the cursor close
	// per chunk — top-level defer, not a bare close below a loop — so no
	// pooled connection is held across chunks.
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	type acc struct {
		series *probeSeries
		n24    int // rows loaded from phase 1 (drives the slow-sensor split)
	}
	byID := make(map[string]*acc, len(idList))

	// Phase 1: the 24h window for all sensors (batched, no window function).
	fetchChunk24 := func(chunk []string) {
		q := make([]string, len(chunk))
		for i := range q {
			q[i] = "?"
		}
		args := make([]any, 0, len(chunk)+1)
		for _, id := range chunk {
			args = append(args, id)
		}
		args = append(args, store.FormatTS(cutoff))
		rows, err := pw.db.QueryContext(ctx,
			`SELECT sensor_id, ts, rtt_ms, manual FROM probes
			WHERE sensor_id IN (`+strings.Join(q, ",")+`) AND ts >= ?
			ORDER BY sensor_id, ts`, args...)
		if err != nil {
			log.Printf("stats warm: 24h chunk fetch failed: %v", err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var sid string
			var ts time.Time
			var rtt *float64
			var mRaw int
			if err := rows.Scan(&sid, &ts, &rtt, &mRaw); err != nil {
				continue
			}
			a, ok := byID[sid]
			if !ok {
				a = &acc{series: &probeSeries{}}
				byID[sid] = a
			}
			e := probeEntry{ts: ts.UTC().Unix(), rtt: float32(math.NaN()), manual: mRaw == 1}
			if rtt != nil {
				e.rtt = float32(*rtt)
			}
			a.series.append(e)
			a.n24++
		}
		if err := rows.Err(); err != nil {
			log.Printf("stats warm: 24h chunk read ended early: %v", err)
		}
	}
	for i := 0; i < len(idList); i += store.InQueryChunk {
		if ctx.Err() != nil {
			log.Printf("stats warm: aborted during 24h phase (shutdown)")
			return
		}
		end := i + store.InQueryChunk
		if end > len(idList) {
			end = len(idList)
		}
		fetchChunk24(idList[i:end])
	}

	// Phase 2: backfill the last 60 for the slow sensors. A sensor with fewer
	// than 60 probes in 24h (including zero — it may still have older history)
	// has a 60-probe inspector window that spans past the 24h cutoff, so phase
	// 1 alone under-fills it. The per-sensor LIMIT 60 is a superset of the 24h
	// rows, so it replaces the phase-1 series (no dedupe).
	var slow []string
	for _, id := range idList {
		if a, ok := byID[id]; !ok || a.n24 < seriesTailProbes {
			slow = append(slow, id)
		}
	}
	backfillLast60 := func(id string) {
		rows, err := pw.db.QueryContext(ctx,
			`SELECT ts, rtt_ms, manual FROM probes
			WHERE sensor_id = ? ORDER BY ts DESC LIMIT ?`, id, seriesTailProbes)
		if err != nil {
			log.Printf("stats warm: last-60 backfill failed for %s: %v", id, err)
			return
		}
		defer rows.Close()
		type row struct {
			ts   time.Time
			rtt  *float64
			mRaw int
		}
		var got []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.ts, &r.rtt, &r.mRaw); err != nil {
				continue
			}
			got = append(got, r)
		}
		if err := rows.Err(); err != nil {
			log.Printf("stats warm: last-60 backfill read ended early for %s: %v", id, err)
		}
		if len(got) == 0 {
			return // no history: leave the sensor out of the cache
		}
		s := &probeSeries{}
		for i := len(got) - 1; i >= 0; i-- { // append oldest-first
			e := probeEntry{ts: got[i].ts.UTC().Unix(), rtt: float32(math.NaN()), manual: got[i].mRaw == 1}
			if got[i].rtt != nil {
				e.rtt = float32(*got[i].rtt)
			}
			s.append(e)
		}
		byID[id] = &acc{series: s, n24: 60}
	}
	for _, id := range slow {
		if ctx.Err() != nil {
			log.Printf("stats warm: aborted during last-60 phase (shutdown)")
			return
		}
		backfillLast60(id)
	}
	pw.statsMu.Lock()
	built := 0
	for sid, a := range byID {
		// Don't clobber a live write that landed DURING the warm read:
		// recordProbe (probe loop or API PingNow) may have appended a
		// fresher entry while this chunk query was in flight. Carry the
		// newer tail over so the warm snapshot never goes backwards
		// (append keeps counters coherent).
		if old := pw.statsCache[sid]; old != nil && a.series.len() > 0 {
			newest := a.series.lastTs()
			for _, e := range old.snapshot() {
				if e.ts > newest {
					a.series.append(e)
				}
			}
		}
		pw.statsCache[sid] = a.series
		built += a.series.len()
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
	// Monotonic ts clamp: probeEntry.ts is captured
	// OUTSIDE statsMu (each path stamps the time before calling in), so a
	// manual pulse and a scheduled tick racing can append out of order by
	// milliseconds and break the ts-monotonic invariant the in24Start
	// cutoff walks depend on. Clamping to the newest stored ts costs one
	// comparison per append and restores the invariant; equality is fine
	// for the cutoff walks.
	if n := len(s.raw); n > 0 && e.ts < s.raw[n-1].ts {
		e.ts = s.raw[n-1].ts
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
	// computeSensorStats only reads (the *float64 API values it derives are
	// per-read copies). This avoids copying up to 24h of entries (276 KB for
	// a 5s sensor) per sensor per dashboard poll.
	pw.statsMu.RLock()
	defer pw.statsMu.RUnlock()
	s, ok := pw.statsCache[id]
	if !ok || s.len() == 0 {
		return nil
	}
	// computeSensorStats reads only the raw tier: the 60-probe inspector
	// window, the status window, the 1h loss/avg, and the sparkline all fit
	// inside max(1h, last 60). The 24h uptime comes from the incremental
	// counters, so the per-poll read never scans the minute buckets.
	return computeSensorStats(s.raw[s.rawStart:], nowUnix, s.total24, s.lost24)
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
// Manual "Pulse Now" rows count in the 60-probe inspector window (it reads
// the raw history) but are EXCLUDED from every loss/uptime aggregate —
// the 1h pass, the status window (which mirrors deriveStatus), the 24h
// counters, and the sparkline: a
// diagnostic click must not make a healthy sensor show packet loss.
//
// nowUnix (epoch seconds) is the "current time" the time windows anchor to.
// GetStats passes time.Now().Unix(); the differential test passes a fixed
// value to both the SQL and in-memory paths so they compare deterministically
// (no flake from a minute-boundary crossing mid-test). A NaN rtt is a lost
// probe (matches SQL `rtt_ms IS NULL`).
//
// total24/lost24 are the series' incremental 24h counters (probeSeries);
// production passes the live values, tests pass a recount of the slice —
// either way they must count the entries with ts >= nowUnix-86400.
func computeSensorStats(entries []probeEntry, nowUnix int64, total24, lost24 int) *SensorStats {
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
		if st.RTTLast == nil && !isLost(rtt) { // first non-lost from the newest
			v := float64(rtt)
			st.RTTLast = &v
		}
		if len(st.Recent) < 30 {
			st.Recent = append(st.Recent, rttToPtr(rtt))
		}
		if isLost(rtt) {
			st.LostCount++
			continue
		}
		v := float64(rtt)
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

	// Past-hour loss % + avg RTT. The series is ts-sorted, so binary-search
	// the first entry inside the hour and skip the older tail (before, this scanned all 24h on every poll).
	h1, l1 := 0, 0
	var h1sum float64
	i1 := sort.Search(len(entries), func(i int) bool { return entries[i].ts >= nowUnix-3600 })
	for _, e := range entries[i1:] {
		if e.manual {
			continue
		}
		h1++
		if isLost(e.rtt) {
			l1++
		} else {
			h1sum += float64(e.rtt)
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
	//
	// Manual rows are skipped in BOTH numerator and denominator: the badge
	// derives from scheduled probes only (deriveStatus skips manual rows),
	// so a manual loss in an otherwise healthy window must not read as
	// loss%.
	st.StatusWindowSize = statusWindow
	// Walk back collecting statusWindow SCHEDULED probes (skipping manual),
	// mirroring recentFromCache / deriveStatus EXACTLY. Not "last statusWindow
	// raw entries then skip manual" — that shrinks the window below
	// statusWindow after a Pulse Now, so the inspector number would come from
	// a different window than the badge.
	swTotal, swLost := 0, 0
	for i := len(entries) - 1; i >= 0 && swTotal < statusWindow; i-- {
		if entries[i].manual {
			continue
		}
		swTotal++
		if isLost(entries[i].rtt) {
			swLost++
		}
	}
	st.StatusLostCount = swLost
	if swTotal > 0 {
		st.StatusLossPct = float64(swLost) / float64(swTotal) * 100
	}

	// 24h uptime — straight from the incremental counters (maintained in
	// probeSeries.append), no full-series scan.
	d24, l24 := total24, lost24
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
	for _, e := range entries[i1:] {
		if e.manual {
			continue
		}
		if e.ts > nowUnix {
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
		if !isLost(e.rtt) {
			v := float64(e.rtt)
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
