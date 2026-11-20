package main

// Realistic update-check outage backoff: in production updateCheckTTL (30m,
// the success freshness) > updateCheckFailTTL (1m, the failure suppression).
// The existing TestUpdateCheckStaleOnFailure uses the INVERSE (TTL=1ms,
// FailTTL=1h) to stay fast, which hides the real interaction the finding asks
// for: after a success that is OLDER than the success TTL, the first failure
// probe must NOT be suppressed by the success's own age (the dead-code
// `time.Since(updateCheckAt) < updateCheckFailTTL` bug), and the failure is
// backoff'd by the SHORTER FailTTL measured from the ATTEMPT (not the success).
// This test pins the realistic ordering by manipulating the timestamps
// directly (no 30m sleep).
// History: docs/DECISIONS.md → testing-benchmark-gaps

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestUpdateCheckTTLExceedsFailTTLOutageBackoff(t *testing.T) {
	var hits int32
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError) // outage: always fails
	}))
	defer gh.Close()

	oldBase := releaseBase
	releaseBase = gh.URL + "/releases"
	t.Cleanup(func() { releaseBase = oldBase })

	oldCache, oldAt, oldAttempt, oldFailed := updateCheckCached, updateCheckAt, updateCheckAttemptAt, updateCheckFailed
	oldTTL, oldFailTTL := updateCheckTTL, updateCheckFailTTL
	t.Cleanup(func() {
		updateCheckCached, updateCheckAt, updateCheckAttemptAt, updateCheckFailed = oldCache, oldAt, oldAttempt, oldFailed
		updateCheckTTL, updateCheckFailTTL = oldTTL, oldFailTTL
	})
	// Realistic production ratio: success freshness (30m) > failure suppression (1m).
	updateCheckTTL = 30 * time.Minute
	updateCheckFailTTL = 1 * time.Minute

	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	get := func() (int, updateCheckResult) {
		req := httptest.NewRequest("GET", "/api/update-check", nil)
		rec := httptest.NewRecorder()
		srv.handleUpdateCheck(rec, req)
		var res updateCheckResult
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		return rec.Code, res
	}

	// Seed a cached success that is OLDER than the success TTL (31m > 30m):
	// the next poll must PROBE upstream (the stale success is not served fresh).
	updateCheckCached = &updateCheckResult{Latest: "v9.9.9"}
	updateCheckAt = time.Now().Add(-31 * time.Minute)
	updateCheckAttemptAt = time.Now().Add(-31 * time.Minute)
	updateCheckFailed = false

	// 1. Expired success + outage: probes upstream, fails, serves stale. The
	//    first failure must NOT be suppressed by the success's own age —
	//    hits goes 0 -> 1.
	code, res := get()
	if code != http.StatusOK || res.Latest != "v9.9.9" || !res.Cached {
		t.Fatalf("expired-success outage: code=%d res=%+v, want 200 stale cached:true", code, res)
	}
	if h := atomic.LoadInt32(&hits); h != 1 {
		t.Fatalf("after the first (expired) failure: hits=%d, want 1 (the first failure must probe, not be suppressed by the success age)", h)
	}

	// 2. Within FailTTL of the attempt: suppressed, NO new upstream hit. This
	//    is the discriminator: the suppression is measured from
	//    updateCheckAttemptAt (fresh), so it holds. The dead-code version
	//    measured from updateCheckAt (31m old) and would NOT suppress here.
	code, res = get()
	if code != http.StatusOK || !res.Cached {
		t.Fatalf("suppressed outage: code=%d res=%+v, want 200 stale cached:true", code, res)
	}
	if h := atomic.LoadInt32(&hits); h != 1 {
		t.Fatalf("within FailTTL: hits=%d, want still 1 (the failure backoff must suppress the retry; measuring from the success time re-opens the outage hammer)", h)
	}

	// 3. After FailTTL elapses (advance the attempt timestamp past 1m): a
	//    retry is attempted.
	updateCheckMu.Lock()
	updateCheckAttemptAt = time.Now().Add(-2 * time.Minute)
	updateCheckMu.Unlock()
	code, res = get()
	if code != http.StatusOK || !res.Cached {
		t.Fatalf("post-FailTTL outage: code=%d res=%+v, want 200 stale cached:true", code, res)
	}
	if h := atomic.LoadInt32(&hits); h != 2 {
		t.Fatalf("after FailTTL: hits=%d, want 2 (the backoff must expire and retry)", h)
	}
}
