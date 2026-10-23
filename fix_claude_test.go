package main

// Regression tests for the Claude track of the review fixes (C3, M1, M8, M9, M10a, M11, timestamps).
// Each test name carries the review item id.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
)

func fcDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "fc.db"))
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func fcSensor(t *testing.T, db *DB, id, name, state string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at)
		VALUES (?,?,'10.0.0.1','icmp',60,1000,25,2,5,?,'up',?)`, id, name, state, tsNow()); err != nil {
		t.Fatal(err)
	}
}

func fcProbe(t *testing.T, db *DB, id string, ts time.Time, rtt any) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES (?,?,?)`, id, fmtTS(ts), rtt); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------- M1

func TestFix_M1_StaggerPhaseAlwaysInRange(t *testing.T) {
	for _, interval := range []time.Duration{time.Second, 15 * time.Second, 60 * time.Second, time.Hour} {
		low := 0
		for i := 0; i < 20000; i++ {
			p := staggerPhase(uuid.NewString(), interval)
			if p < 250*time.Millisecond {
				t.Fatalf("interval %v: phase %v < 250ms (negative/immediate => no stagger)", interval, p)
			}
			if p > interval+250*time.Millisecond {
				t.Fatalf("interval %v: phase %v exceeds interval+250ms", interval, p)
			}
			if p < interval/2 {
				low++
			}
		}
		if low < 8000 || low > 12000 { // distribution sanity: ~50% below half-interval
			t.Errorf("interval %v: %d/20000 below half interval, distribution looks skewed", interval, low)
		}
	}
}

func TestFix_M1_StaggerPhaseZeroIntervalDoesNotPanic(t *testing.T) {
	if p := staggerPhase("x", 0); p < 250*time.Millisecond {
		t.Fatalf("zero interval phase = %v", p)
	}
}

func TestFix_M1_ProbePanicIsContained(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "s1", "s1", "active")
	pw := NewProbeWorker(db)
	pw.sensors["s1"] = &ProbeState{id: "s1"}
	old := probeTarget
	defer func() { probeTarget = old }()
	probeTarget = func(ctx context.Context, typ, target string, d time.Duration) probeOutcome { panic("boom") }
	// must not propagate
	pw.safeProbe(context.Background(), sensorConfig{id: "s1", name: "s1", target: "10.0.0.1", probeType: "icmp", intervalS: 60, timeoutMS: 100, lossWarn: 25, downAfter: 2})
}

// ---------------------------------------------------------------- C3

func TestFix_C3_PerTargetSendErrorsAreNotEngineFailures(t *testing.T) {
	for name, err := range map[string]error{
		"ENETUNREACH":      syscall.ENETUNREACH,
		"EHOSTUNREACH":     syscall.EHOSTUNREACH,
		"EPERM(netfilter)": syscall.EPERM,
		"EACCES":           syscall.EACCES,
		"wrapped":          &os.SyscallError{Syscall: "sendto", Err: syscall.ENETUNREACH},
	} {
		if isBrokenSendErr(err) {
			t.Errorf("%s classified as engine-broken; it is a per-target loss", name)
		}
	}
	for name, err := range map[string]error{
		"EBADF":         syscall.EBADF,
		"ENOTSOCK":      syscall.ENOTSOCK,
		"ErrClosed":     net.ErrClosed,
		"wrapped EBADF": &os.SyscallError{Syscall: "sendto", Err: syscall.EBADF},
	} {
		if !isBrokenSendErr(err) {
			t.Errorf("%s should be engine-broken", name)
		}
	}
}

func TestFix_C3_PingPerTargetErrorDoesNotTouchGlobalCounter(t *testing.T) {
	probeErrCount.Store(0)
	e := &Engine{send: func(net.IP, uint16) error { return syscall.ENETUNREACH }}
	res := e.Ping(context.Background(), net.ParseIP("10.255.255.1").To4(), 50*time.Millisecond)
	if !res.Lost || res.Broken {
		t.Fatalf("res = %+v, want Lost && !Broken", res)
	}
	if n := probeErrCount.Load(); n != 0 {
		t.Fatalf("probeErrCount = %d after a per-target send error, want 0", n)
	}
	e2 := &Engine{send: func(net.IP, uint16) error { return syscall.EBADF }}
	res = e2.Ping(context.Background(), net.ParseIP("10.255.255.2").To4(), 50*time.Millisecond)
	if !res.Lost || !res.Broken || probeErrCount.Load() != 1 {
		t.Fatalf("EBADF: res=%+v count=%d, want Lost && Broken && count 1", res, probeErrCount.Load())
	}
	probeErrCount.Store(0)
}

func TestFix_C3_OtherSensorsErrorsDoNotChangeStatus(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	now := time.Now()
	for i := 0; i < 4; i++ { // 4 straight losses => error
		fcProbe(t, db, "a", now.Add(time.Duration(i-5)*time.Second), nil)
	}
	pw := NewProbeWorker(db)
	probeErrCount.Store(7) // another sensor/engine bumped the global counter
	defer probeErrCount.Store(0)
	c := sensorConfig{id: "a", downAfter: 2, lossWarn: 25}
	if got := pw.deriveStatus(c, "up"); got != "error" {
		t.Fatalf("derived %q with an unrelated global counter bump, want error", got)
	}
}

func TestFix_C3_BrokenProbeKeepsErrorAndFlagsWarning(t *testing.T) {
	pw := NewProbeWorker(nil)
	c := sensorConfig{id: "a", downAfter: 2, lossWarn: 25, probeBroken: true}
	if got := pw.deriveStatus(c, "error"); got != "error" {
		t.Errorf("broken probe on an error sensor derived %q, want error (no fake partial recovery)", got)
	}
	if got := pw.deriveStatus(c, "up"); got != "warning" {
		t.Errorf("broken probe on an up sensor derived %q, want warning", got)
	}
}

// ---------------------------------------------------------------- M8

func TestFix_M8_RedactErrDropsURL(t *testing.T) {
	secret := "bot123456:SECRETTOKEN"
	_, err := http.NewRequest("POST", "http://x/"+secret, nil)
	_ = err
	ue := &url.Error{Op: "Post", URL: "https://api.telegram.org/" + secret + "/sendMessage", Err: errors.New("connection refused")}
	r := redactErr(fmt.Errorf("wrapped: %w", ue))
	if strings.Contains(r.Error(), "SECRETTOKEN") || strings.Contains(r.Error(), "telegram") {
		t.Fatalf("redacted error still leaks the URL: %q", r.Error())
	}
	if !strings.Contains(r.Error(), "connection refused") {
		t.Fatalf("redacted error lost the cause: %q", r.Error())
	}
	plain := errors.New("plain")
	if redactErr(plain) != plain {
		t.Fatal("non-url errors must pass through unchanged")
	}
}

func TestFix_M8_PostJSONErrorDoesNotLeakToken(t *testing.T) {
	withPlainTransport(t, func() {
		old := alertRetryDelays
		alertRetryDelays = nil
		defer func() { alertRetryDelays = old }()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
		srv.Close() // refuse connections
		pw := NewProbeWorker(nil)
		err := pw.postJSON(srv.URL+"/bot123:SECRETTOKEN/sendMessage", map[string]interface{}{"text": "x"})
		if err == nil {
			t.Fatal("expected an error")
		}
		if strings.Contains(err.Error(), "SECRETTOKEN") {
			t.Fatalf("postJSON error leaks the token: %q", err.Error())
		}
	})
}

// ---------------------------------------------------------------- M9

func TestFix_M9_RetriesTransientFailuresOnly(t *testing.T) {
	withPlainTransport(t, func() {
		old := alertRetryDelays
		alertRetryDelays = []time.Duration{5 * time.Millisecond, 5 * time.Millisecond}
		defer func() { alertRetryDelays = old }()
		pw := NewProbeWorker(nil)

		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hits.Add(1) < 3 {
				w.WriteHeader(503)
				return
			}
			w.WriteHeader(200)
		}))
		defer srv.Close()
		if err := pw.postJSON(srv.URL, map[string]interface{}{"text": "x"}); err != nil {
			t.Fatalf("503,503,200 should succeed after retries: %v", err)
		}
		if hits.Load() != 3 {
			t.Fatalf("hits = %d, want 3", hits.Load())
		}

		var h400 atomic.Int32
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h400.Add(1); w.WriteHeader(400) }))
		defer bad.Close()
		if err := pw.postJSON(bad.URL, map[string]interface{}{"text": "x"}); err == nil {
			t.Fatal("400 must be an error")
		}
		if h400.Load() != 1 {
			t.Fatalf("400 was retried %d times, want 1 attempt", h400.Load())
		}

		var h500 atomic.Int32
		down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h500.Add(1); w.WriteHeader(500) }))
		defer down.Close()
		if err := pw.postJSON(down.URL, map[string]interface{}{"text": "x"}); err == nil {
			t.Fatal("persistent 500 must be an error")
		}
		if h500.Load() != 3 {
			t.Fatalf("persistent 500 attempts = %d, want 3", h500.Load())
		}
	})
}

func TestFix_M9_RetryStopsOnShutdown(t *testing.T) {
	withPlainTransport(t, func() {
		old := alertRetryDelays
		alertRetryDelays = []time.Duration{time.Hour}
		defer func() { alertRetryDelays = old }()
		pw := NewProbeWorker(nil)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
		defer srv.Close()
		done := make(chan struct{})
		go func() { pw.postJSON(srv.URL, map[string]interface{}{"text": "x"}); close(done) }()
		time.Sleep(100 * time.Millisecond)
		pw.StopAlerts()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("postJSON kept sleeping through StopAlerts")
		}
	})
}

func fcProviders(t *testing.T, db *DB, urls map[string]string) {
	t.Helper()
	for kind, u := range urls {
		if err := db.SetSetting(kind+"_url", u); err != nil {
			t.Fatal(err)
		}
		if err := db.SetSetting(kind+"_enabled", "1"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFix_M9_ProvidersAreIndependentAndParallel(t *testing.T) {
	withPlainTransport(t, func() {
		old := alertRetryDelays
		alertRetryDelays = nil
		defer func() { alertRetryDelays = old }()
		db := fcDB(t)
		var slowHits, fastHits atomic.Int32
		slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			slowHits.Add(1)
			time.Sleep(600 * time.Millisecond)
		}))
		defer slow.Close()
		fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fastHits.Add(1) }))
		defer fast.Close()
		fcProviders(t, db, map[string]string{"google_chat": slow.URL, "discord": fast.URL})
		pw := NewProbeWorker(db)
		start := time.Now()
		ok := pw.sendWebhook("id", "n", "10.0.0.1", "up", "error", 0, false)
		if !ok || slowHits.Load() != 1 || fastHits.Load() != 1 {
			t.Fatalf("ok=%v slow=%d fast=%d", ok, slowHits.Load(), fastHits.Load())
		}
		// Parallel: fast one must not have waited behind the slow one, so total ~600ms not ~1.2s.
		if el := time.Since(start); el > 1100*time.Millisecond {
			t.Errorf("providers look sequential: %v", el)
		}
	})
}

func TestFix_M9_SendWebhookReportsTotalFailure(t *testing.T) {
	withPlainTransport(t, func() {
		old := alertRetryDelays
		alertRetryDelays = nil
		defer func() { alertRetryDelays = old }()
		db := fcDB(t)
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
		defer bad.Close()
		fcProviders(t, db, map[string]string{"discord": bad.URL})
		pw := NewProbeWorker(db)
		if pw.sendWebhook("id", "n", "t", "up", "error", 0, false) {
			t.Fatal("all providers failed but sendWebhook reported delivered")
		}
		// no providers configured => nothing to retry => reported as delivered
		db2 := fcDB(t)
		if !NewProbeWorker(db2).sendWebhook("id", "n", "t", "up", "error", 0, false) {
			t.Fatal("no providers configured must not be treated as a failure")
		}
	})
}

func TestFix_M9_FailedErrorAlertSchedulesRetry(t *testing.T) {
	withPlainTransport(t, func() {
		old := alertRetryDelays
		alertRetryDelays = nil
		defer func() { alertRetryDelays = old }()
		db := fcDB(t)
		fcSensor(t, db, "s", "s", "active")
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
		defer bad.Close()
		fcProviders(t, db, map[string]string{"discord": bad.URL})
		pw := NewProbeWorker(db)
		pw.setAlertState("s", "error", time.Now().UTC())
		pw.launchAlert(func() {
			if !pw.sendAlert("s", "s", "t", "up", "error", 0) {
				pw.scheduleAlertRetry("s", "error")
			}
		})
		pw.DrainAlerts(5 * time.Second)
		var st, ts string
		if err := db.QueryRow(`SELECT status,last_ts FROM alert_state WHERE sensor_id='s'`).Scan(&st, &ts); err != nil {
			t.Fatal(err)
		}
		last, err := parseTSForRealert(ts)
		if err != nil {
			t.Fatal(err)
		}
		// default re-alert interval is 30m; retry is scheduled ~1m out => last_ts ~29m in the past
		if age := time.Since(last); age < 25*time.Minute {
			t.Fatalf("alert_state.last_ts only %v old; a failed delivery must backdate it so the next tick retries", age)
		}
		// realert_min=0 means "alert once only": never schedule a retry
		db.SetSetting("realert_min", "0")
		pw.setAlertState("s", "error", time.Now().UTC())
		pw.scheduleAlertRetry("s", "error")
		db.QueryRow(`SELECT last_ts FROM alert_state WHERE sensor_id='s'`).Scan(&ts)
		last, _ = parseTSForRealert(ts)
		if time.Since(last) > time.Minute {
			t.Fatal("realert_min=0 must not backdate")
		}
	})
}

// ---------------------------------------------------------------- M10a

func TestFix_M10a_DeriveStatusReadsMemoryWhenWarm(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	// DB says healthy history; memory (the authority once warm) says 8 straight losses.
	now := time.Now()
	for i := 0; i < 8; i++ {
		fcProbe(t, db, "a", now.Add(time.Duration(i-20)*time.Second), 5.0)
	}
	for i := 0; i < 8; i++ {
		pw.recordProbe("a", probeEntry{ts: now.Unix() + int64(i), rtt: float32(math.NaN())})
	}
	c := sensorConfig{id: "a", downAfter: 2, lossWarn: 25}
	if got := pw.deriveStatus(c, "up"); got != "error" {
		t.Fatalf("derived %q; warm cache (8 losses) should win over the DB", got)
	}
}

func TestFix_M10a_DeriveStatusFallsBackToDBWhenCacheCold(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	now := time.Now()
	for i := 0; i < 4; i++ {
		fcProbe(t, db, "a", now.Add(time.Duration(i-10)*time.Second), nil)
	}
	pw.recordProbe("a", probeEntry{ts: now.Unix(), rtt: float32(math.NaN())}) // 1 cached entry < limit => DB path
	c := sensorConfig{id: "a", downAfter: 2, lossWarn: 25}
	if got := pw.deriveStatus(c, "up"); got != "error" {
		t.Fatalf("derived %q via cold cache fallback, want error", got)
	}
}

func TestFix_M10a_DoProbeStopsReadingStatusPerTick(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	pw.sensors["a"] = &ProbeState{id: "a"}
	old := probeTarget
	defer func() { probeTarget = old }()
	probeTarget = func(ctx context.Context, typ, target string, d time.Duration) probeOutcome {
		return probeOutcome{rttMs: 1}
	}
	c := sensorConfig{id: "a", name: "a", target: "10.0.0.1", probeType: "icmp", intervalS: 60, timeoutMS: 100, lossWarn: 25, downAfter: 2}
	pw.doProbe(context.Background(), c) // first tick reads status from DB once
	if pw.sensors["a"].lastStatus != "up" {
		t.Fatalf("lastStatus = %q after first probe", pw.sensors["a"].lastStatus)
	}
	// Corrupt the DB status behind its back: with memory authoritative, the next tick must NOT notice
	// (proves no per-tick SELECT status) and must not emit a transition.
	db.Exec(`UPDATE sensors SET status='error' WHERE id='a'`)
	pw.doProbe(context.Background(), c)
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM events WHERE sensor_id='a'`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d events; a steady 'up' sensor must not transition", n)
	}
}

func TestFix_M10a_StatusStaysConsistentWhenUpdateFails(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	pw.sensors["a"] = &ProbeState{id: "a"}
	old := probeTarget
	defer func() { probeTarget = old }()
	probeTarget = func(ctx context.Context, typ, target string, d time.Duration) probeOutcome {
		return probeOutcome{lost: true}
	}
	// make the UPDATE fail: trigger raises on status change
	if _, err := db.Exec(`CREATE TRIGGER nostatus BEFORE UPDATE OF status ON sensors BEGIN SELECT RAISE(ABORT,'nope'); END`); err != nil {
		t.Fatal(err)
	}
	c := sensorConfig{id: "a", name: "a", target: "10.0.0.1", probeType: "icmp", intervalS: 60, timeoutMS: 100, lossWarn: 25, downAfter: 2}
	for i := 0; i < 3; i++ {
		pw.doProbe(context.Background(), c)
	}
	if got := pw.sensors["a"].lastStatus; got == "error" {
		t.Fatal("memory says error but the DB UPDATE failed; lastStatus must only advance after persistence so the transition is retried")
	}
	db.Exec(`DROP TRIGGER nostatus`)
	pw.doProbe(context.Background(), c)
	var st string
	db.QueryRow(`SELECT status FROM sensors WHERE id='a'`).Scan(&st)
	if st != "error" {
		t.Fatalf("after the DB recovered the transition was not retried: status=%q", st)
	}
	// Drain the alert goroutines BEFORE the DB closes (t.Cleanup): the
	// up->warning->error transitions above launched alert deliveries, and an
	// in-flight delivery holds a pool connection open past db.Close(), which
	// leaves the SQLite -wal/-shm files behind and fails the TempDir cleanup
	// (same shutdown order as main: StopAlerts -> DrainAlerts -> db.Close).
	pw.DrainAlerts(5 * time.Second)
}

func TestFix_M10a_StatsForDoesNotCopyAndMatches(t *testing.T) {
	pw := NewProbeWorker(nil)
	now := time.Now().Unix()
	for i := 0; i < 500; i++ {
		pw.recordProbe("a", probeEntry{ts: now - int64(500-i), rtt: float32(i%7 + 1)})
	}
	pw.statsMu.RLock()
	sa := pw.statsCache["a"]
	want := computeSensorStats(sa.snapshot(), now, sa.total24, sa.lost24)
	pw.statsMu.RUnlock()
	got := pw.statsFor("a", now)
	if got.Total != want.Total || got.Uptime24h != want.Uptime24h || *got.RTTAvg != *want.RTTAvg {
		t.Fatalf("statsFor diverged from snapshot-based stats: %+v vs %+v", got, want)
	}
	allocs := testing.AllocsPerRun(20, func() { _ = pw.statsFor("a", now) })
	t24, l24 := sa.total24, sa.lost24
	base := testing.AllocsPerRun(20, func() { _ = computeSensorStats(sa.snapshot(), now, t24, l24) })
	if allocs >= base {
		t.Errorf("statsFor allocs %.0f not lower than snapshot path %.0f", allocs, base)
	}
}

func TestFix_M10a_DSNEnablesSynchronousNormal(t *testing.T) {
	db := fcDB(t)
	var v int
	if err := db.QueryRow(`PRAGMA synchronous`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != 1 { // 1 = NORMAL
		t.Fatalf("synchronous = %d, want 1 (NORMAL) with WAL", v)
	}
	var jm string
	db.QueryRow(`PRAGMA journal_mode`).Scan(&jm)
	if jm != "wal" {
		t.Fatalf("journal_mode = %q", jm)
	}
}

// ---------------------------------------------------------------- M11

func TestFix_M11_PartialSyncDoesNotCancelHealthyLoops(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "good", "good", "active")
	fcSensor(t, db, "bad", "bad", "active")
	// SQLite is dynamically typed: a non-numeric string in an INTEGER column makes Scan fail for that row.
	if _, err := db.Exec(`UPDATE sensors SET interval_s='abc' WHERE id='bad'`); err != nil {
		t.Fatal(err)
	}
	pw := NewProbeWorker(db)
	var badCancelled atomic.Bool
	pw.loops["bad"] = func() { badCancelled.Store(true) } // pretend "bad" already had a healthy loop
	pw.sensors["bad"] = &ProbeState{id: "bad", lastStatus: "error"}
	ctx, cancel := context.WithCancel(context.Background())
	pw.syncSensors(ctx)
	cancel()
	pw.wg.Wait()
	if badCancelled.Load() {
		t.Fatal("a row that failed to Scan caused its running loop to be cancelled")
	}
	if pw.sensors["bad"] == nil || pw.sensors["bad"].lastStatus != "error" {
		t.Fatal("ProbeState of the unreadable sensor was deleted")
	}
	if _, ok := pw.loops["good"]; !ok {
		t.Fatal("healthy sensor loop was not started")
	}
}

// ---------------------------------------------------------------- timestamps

func TestFix_TS_FixedWidthLexicographicEqualsChronological(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	base := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	var times []time.Time
	for i := 0; i < 2000; i++ {
		ns := rng.Int63n(int64(3 * time.Second))
		if i%5 == 0 {
			ns = (ns / int64(time.Second)) * int64(time.Second) // exact integer seconds
		}
		if i%7 == 0 {
			ns = (ns / int64(time.Millisecond)) * int64(time.Millisecond) // trailing zeros
		}
		times = append(times, base.Add(time.Duration(ns)))
	}
	strs := make([]string, len(times))
	for i, tm := range times {
		strs[i] = fmtTS(tm)
		if len(strs[i]) != len(fmtTS(base)) {
			t.Fatalf("variable width: %q", strs[i])
		}
		if back, err := time.Parse(time.RFC3339Nano, strs[i]); err != nil || !back.Equal(tm) {
			t.Fatalf("round trip %q: %v %v", strs[i], back, err)
		}
	}
	sortedT := append([]time.Time(nil), times...)
	sort.Slice(sortedT, func(i, j int) bool { return sortedT[i].Before(sortedT[j]) })
	sortedS := append([]string(nil), strs...)
	sort.Strings(sortedS)
	for i := range sortedT {
		if fmtTS(sortedT[i]) != sortedS[i] {
			t.Fatalf("string order != time order at %d: %s vs %s", i, fmtTS(sortedT[i]), sortedS[i])
		}
	}
	if s := tsNow(); len(s) != len(fmtTS(base)) {
		t.Fatalf("tsNow width %d", len(s))
	}
}

func TestFix_TS_PurgeDeletesOnlyOldRowsIncludingLegacyFormat(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	pw := NewProbeWorker(db)
	old := time.Now().Add(-25 * time.Hour)
	young := time.Now().Add(-23 * time.Hour)
	fcProbe(t, db, "a", old, 1.0)
	fcProbe(t, db, "a", young, 1.0)
	// legacy variable-width rows written by older versions
	db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('a', ?, 1)`, old.UTC().Format(time.RFC3339Nano))
	db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('a', ?, 1)`, young.UTC().Format(time.RFC3339Nano))
	pw.purgeOld()
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM probes`).Scan(&n)
	if n != 2 {
		t.Fatalf("%d rows left, want exactly the 2 young ones", n)
	}
}

var _ = sync.Mutex{}
