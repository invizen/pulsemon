package main

import (
	"context"
	"fmt"
	"path/filepath"
	"pulsemon/internal/store"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestProbeWriteSoakFleetCadence (external review #10): the fleet-scale write
// soak, bounded to fit the gate. 100 goroutines — the reviewer's 100-sensor
// fleet — hammer the dedicated probe-write handle (exactly doProbe's hot
// INSERT path: ProbeExecContext on the MaxOpenConns(1) handle with
// busy_timeout = ProbeWriteTimeout) with 20 writes each, all concurrent.
//
// Properties locked: every write lands (2000/2000 rows), and NO writer
// surfaces an error. The handle serializes commits, so concurrent writers
// QUEUE in the ctx-aware database/sql pool wait — they must never come back
// as SQLITE_BUSY: a busy error under queue-only contention means the probe
// handle lost its cap configuration (see TestProbeHandleCarriesCappedBusyTimeout)
// or the queue stopped being context-aware (the mid-write cancel path that
// store's probe-handle contract guarantees).
//
// Latency stats are logged, not hard-asserted (absolute times under -race are
// meaningless); a busy-handler park WOULD surface, as SQLITE_BUSY errors plus
// a total far past the busy cap, and the gate wall-clock exposes pathological
// stalls. Raw sustainable-rate numbers live in BenchmarkProbeWrites.
func TestProbeWriteSoakFleetCadence(t *testing.T) {
	db := fcDB(t)
	pw := NewProbeWorker(db)
	const sensorsN, writesN = 100, 20
	ctx := context.Background()
	for i := 0; i < sensorsN; i++ {
		fcSensor(t, db, fmt.Sprintf("soak-%03d", i), fmt.Sprintf("soak-%03d", i), "active")
	}
	base := time.Now().UTC().Add(-time.Minute)

	start := time.Now()
	errCh := make(chan error, sensorsN)
	sensorDur := make([]time.Duration, sensorsN)
	var wg sync.WaitGroup
	for i := 0; i < sensorsN; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("soak-%03d", i)
			t0 := time.Now()
			for j := 0; j < writesN; j++ {
				ts := base.Add(time.Duration(i*writesN+j) * time.Millisecond)
				if _, err := pw.db.ProbeExecContext(ctx,
					`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES (?,?,?)`,
					id, store.FormatTS(ts), 1.0); err != nil {
					errCh <- fmt.Errorf("sensor %s write %d: %w", id, j, err)
					return
				}
			}
			sensorDur[i] = time.Since(t0)
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("fleet write soak failed (probe-write handle must queue, never busy-fail): %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM probes`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != sensorsN*writesN {
		t.Fatalf("soak rows = %d, want %d (every queued write must land)", n, sensorsN*writesN)
	}
	total := time.Since(start)
	var sum, max time.Duration
	for _, d := range sensorDur {
		sum += d
		if d > max {
			max = d
		}
	}
	t.Logf("100 sensors x %d concurrent writes: total=%v avg-sensor=%v max-sensor=%v throughput=%.0f writes/s",
		writesN, total, sum/time.Duration(sensorsN), max, float64(n)/total.Seconds())
}

// BenchmarkProbeWrites measures the sustained probe-write path at the
// reviewer's fleet scale: each b.N iteration is one "5s tick wave" — 100
// sensors each landing one hot INSERT concurrently through the probe-write
// handle — i.e. the exact 20 writes/s duty cycle a 100-sensor @5s fleet
// imposes. ns/op is one full wave; divide by 100 for per-write cost. Opt-in
// like the other benchmarks (run explicitly:
// `go test -run=^$ -bench=BenchmarkProbeWrites -benchtime=100x .`); it
// answers the finding's scaling question with a repeatable number instead of
// a one-off scratch run.
func BenchmarkProbeWrites(b *testing.B) {
	db, err := store.NewStore(filepath.Join(b.TempDir(), "wbench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < benchPurgeSensors; i++ {
		id := fmt.Sprintf("wbench-%03d", i)
		if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at)
			VALUES (?,?,'10.0.0.1','icmp',5,1000,25,2,5,'active','up',?)`, id, id, store.Now()); err != nil {
			b.Fatal(err)
		}
	}
	ctx := context.Background()
	base := time.Now().UTC()
	var seq int64
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		for s := 0; s < benchPurgeSensors; s++ {
			wg.Add(1)
			go func(s int) {
				defer wg.Done()
				k := atomic.AddInt64(&seq, 1)
				ts := base.Add(time.Duration(k) * time.Millisecond)
				if _, err := db.ProbeExecContext(ctx,
					`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES (?,?,?)`,
					fmt.Sprintf("wbench-%03d", s), store.FormatTS(ts), 1.0); err != nil {
					b.Errorf("wave %d sensor %d: %v", i, s, err)
				}
			}(s)
		}
		wg.Wait()
	}
}
