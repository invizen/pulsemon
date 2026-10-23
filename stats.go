package main

import (
	"log"
	"math"
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

// probeSeries is an append-only, oldest-first log of probeEntry with a
// logical `start` offset. Appending is amortized O(1); entries older than the
// 24h retention are evicted by advancing `start`, and the backing array is
// compacted only occasionally (when `start` grows large) so the common
// append path never pays an O(n) memmove.
type probeSeries struct {
	data  []probeEntry
	start int // index (into data) of the oldest live entry

	// Incremental 24h counters: total24 and
	// lost24 count the LIVE entries inside the 24h window so the per-poll
	// stats read is O(1) for uptime instead of a full-series scan. append
	// maintains them: the new entry is always inside its own window (+1),
	// and in24Start — the first live index still inside the window — walks
	// forward as the cutoff (newest ts - retention, monotonic) passes
	// entries out of it (-1). in24Start only moves forward, so the
	// bookkeeping is amortized O(1). The invariant start <= in24Start holds
	// by induction: eviction (start) only passes entries that are OUT of
	// the window, which in24Start has already passed — so the evict loop
	// never touches the counters (decrementing there would double-count).
	// A long-interval sensor's last-60 tail can hold entries older than 24h
	// (kept by the 60-probe rule): in24Start passes them out of the
	// counters even though start keeps them in the series. Manual "Pulse
	// Now" rows are never counted (a diagnostic click must not move
	// uptime_24h): append skips them on the way in and in24Start skips
	// them on the way out.
	total24   int
	lost24    int
	in24Start int
}

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
	// sensor's own row counts (the UNION ALL "fix" was reverted for breaking this contract).
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
			e := probeEntry{ts: ts.UTC().Unix(), rtt: float32(math.NaN())}
			if rtt != nil {
				e.rtt = float32(*rtt)
			}
			a.series.append(e)
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
	// computeSensorStats only reads (the *float64 API values it derives are
	// per-read copies). This avoids copying up to 24h of entries (276 KB for
	// a 5s sensor) per sensor per dashboard poll.
	pw.statsMu.RLock()
	defer pw.statsMu.RUnlock()
	s, ok := pw.statsCache[id]
	if !ok || s.len() == 0 {
		return nil
	}
	return computeSensorStats(s.data[s.start:], nowUnix, s.total24, s.lost24)
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
	sw := entries
	if len(sw) > statusWindow {
		sw = sw[len(sw)-statusWindow:]
	}
	swTotal, swLost := 0, 0
	for _, e := range sw {
		if e.manual {
			continue
		}
		swTotal++
		if isLost(e.rtt) {
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
