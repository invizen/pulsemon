package main

import (
	"path/filepath"
	"testing"
	"time"
)

// TestInQueryChunking locks the IN(...) batch-size fix. Both batch queries
// (SensorTagsFor and warmStats' probe load) used to build one IN-list with one
// placeholder per id, unbounded. modernc.org/sqlite accepts 32,766 bound
// params (32,767 fails with "too many SQL variables" — verified against the
// real driver), and warmStats repeats its id list twice (once per UNION arm),
// so a fleet of >16,383 sensors would have failed the startup warm-up
// outright. Both now run in inQueryChunk-sized batches.
//
// The test seeds a fleet LARGER than one chunk and verifies the chunked path
// returns complete, per-sensor-correct results — a bug in the chunk boundaries
// (off-by-one, dropped last partial chunk, ids landing in the wrong chunk)
// would surface as a missing or wrong sensor.
func TestInQueryChunking(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "chunk.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// A fleet that spans multiple chunks, including a partial final one.
	n := 2*inQueryChunk + 70 // 1070 -> chunks of 500, 500, 70
	now := time.Now().UTC().Format(time.RFC3339Nano)
	probeRTT := func(i int) float64 { return float64(10 + i%7) } // 10..16 ms

	// Seed sensors, one probe each (ts within 24h so warmStats loads it), and
	// one tag each. Chunked ourselves to stay under the param limit — the same
	// pattern the production code now uses.
	for start := 0; start < n; start += inQueryChunk {
		end := start + inQueryChunk
		if end > n {
			end = n
		}
		sVals := make([]string, 0, end-start)
		sArgs := make([]any, 0, (end-start)*2)
		pVals := make([]string, 0, end-start)
		pArgs := make([]any, 0, (end-start)*3)
		tVals := make([]string, 0, end-start)
		tArgs := make([]any, 0, (end-start)*2)
		for i := start; i < end; i++ {
			id := "s" + itoa(i)
			sVals = append(sVals, "(?, ?, '127.0.0.1', 15, 1000, 25, 4, 'active', 'up', '2026-01-01T00:00:00Z')")
			sArgs = append(sArgs, id, id)
			pVals = append(pVals, "(?, ?, ?)")
			pArgs = append(pArgs, id, now, probeRTT(i))
			tVals = append(tVals, "(?, ?)")
			tArgs = append(tArgs, id, "tag"+itoa(i%13))
		}
		if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, state, status, created_at)
			VALUES `+joinComma(sVals), sArgs...); err != nil {
			t.Fatalf("seed sensors chunk %d: %v", start, err)
		}
		if _, err := db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES "+joinComma(pVals), pArgs...); err != nil {
			t.Fatalf("seed probes chunk %d: %v", start, err)
		}
		if _, err := db.Exec("INSERT INTO sensor_tags (sensor_id, tag) VALUES "+joinComma(tVals), tArgs...); err != nil {
			t.Fatalf("seed tags chunk %d: %v", start, err)
		}
	}

	// 1) SensorTagsFor across >1 chunk: every sensor's tag returned, complete
	// and per-sensor correct. A dropped/partial final chunk would be missing.
	allIDs := make([]string, n)
	for i := range allIDs {
		allIDs[i] = "s" + itoa(i)
	}
	tagMap := db.SensorTagsFor(allIDs)
	if len(tagMap) != n {
		t.Fatalf("SensorTagsFor returned %d sensors, want %d (chunking dropped some)", len(tagMap), n)
	}
	for i := 0; i < n; i += 97 {
		want := "tag" + itoa(i%13)
		if got := tagMap[allIDs[i]]; len(got) != 1 || got[0] != want {
			t.Errorf("SensorTagsFor[%s] = %v, want [%s]", allIDs[i], got, want)
		}
	}
	// The last sensor of the final (partial) chunk — the classic off-by-one spot.
	last := allIDs[n-1]
	if got := tagMap[last]; len(got) != 1 || got[0] != "tag"+itoa((n-1)%13) {
		t.Errorf("last partial-chunk sensor %s tags = %v, want [tag%d]", last, got, (n-1)%13)
	}

	// 2) warmStats across >1 chunk: every sensor's one probe loaded with the
	// right RTT. A chunking bug (dropped partial chunk, wrong partition) leaves
	// a sensor's series empty (GetStats nil) or with the wrong RTT.
	pw := NewProbeWorker(db)
	pw.warmStats()
	bad := 0
	for i := 0; i < n; i += 97 {
		st := pw.GetStats(allIDs[i])
		if st == nil {
			t.Errorf("GetStats(%s) = nil after warmStats, want a series (chunk dropped this sensor)", allIDs[i])
			bad++
			continue
		}
		if st.Total != 1 || st.RTTLast == nil || *st.RTTLast != probeRTT(i) {
			t.Errorf("GetStats(%s) = total %d last %v, want total 1 last %v", allIDs[i], st.Total, st.RTTLast, probeRTT(i))
			bad++
		}
	}
	if bad == 0 {
		t.Logf("chunking verified across %d sensors (%d chunks): tags + warmStats complete and per-sensor correct",
			n, (n+inQueryChunk-1)/inQueryChunk)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
