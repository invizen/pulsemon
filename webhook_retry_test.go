package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

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
