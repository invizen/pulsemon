package main

// /api/update-check negative caching: a failing GitHub lookup serves the stale
// result (cached:true) and suppresses repeats; ?refresh=1 is throttled.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestUpdateCheckStaleOnFailure pins the negative-caching behavior: once a
// good result is cached, a failing GitHub lookup serves the stale result
// with cached:true instead of 503, and the failure is suppressed for
// updateCheckFailTTL (no repeated upstream hits).
func TestUpdateCheckStaleOnFailure(t *testing.T) {
	// Point releaseBase at a server that succeeds once, then fails.
	var hits int
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://github.com/invizen/pulsemon/releases/tag/v9.9.9"}`))
	}))
	defer gh.Close()

	oldBase := releaseBase
	releaseBase = gh.URL + "/releases"
	t.Cleanup(func() { releaseBase = oldBase })

	oldCache, oldAt, oldFailed := updateCheckCached, updateCheckAt, updateCheckFailed
	oldTTL, oldFailTTL := updateCheckTTL, updateCheckFailTTL
	t.Cleanup(func() {
		updateCheckCached, updateCheckAt, updateCheckFailed = oldCache, oldAt, oldFailed
		updateCheckTTL, updateCheckFailTTL = oldTTL, oldFailTTL
	})
	updateCheckCached, updateCheckFailed = nil, false
	updateCheckTTL = time.Millisecond // force upstream on first call
	updateCheckFailTTL = time.Hour    // failure suppression window for the test

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

	code, res := get() // hit 1: success, cached fresh
	if code != 200 || res.Latest != "v9.9.9" || res.Cached {
		t.Fatalf("first check: code=%d res=%+v", code, res)
	}

	time.Sleep(2 * time.Millisecond) // let updateCheckTTL expire
	code, res = get()                // upstream attempted, fails -> stale served
	if code != 200 || res.Latest != "v9.9.9" || !res.Cached {
		t.Fatalf("failure path: code=%d res=%+v, want 200 stale cached:true", code, res)
	}
	if hits != 2 {
		t.Fatalf("upstream hit %d times, want 2 (success + one failed probe)", hits)
	}

	code, res = get() // failure suppressed within updateCheckFailTTL: no upstream hit
	if code != 200 || res.Latest != "v9.9.9" || !res.Cached {
		t.Fatalf("suppressed path: code=%d res=%+v, want 200 stale cached:true", code, res)
	}
	if hits != 2 {
		t.Fatalf("upstream hit %d times during failure suppression, want still 2", hits)
	}
}

// TestUpdateCheckRefreshThrottled pins the ?refresh=1 throttle: a refresh
// younger than updateCheckRefreshMinInterval since the last fetch attempt is
// ignored and served from the cache (no new upstream hit), so the endpoint
// can't be used to hammer the GitHub API by repeated refreshes. A refresh
// once the interval has elapsed DOES force a fresh fetch. Pre-fix, every
// ?refresh=1 bypassed the cache and forced a fetchRelease.

// TestUpdateCheckRefreshThrottled pins the ?refresh=1 throttle: a refresh
// younger than updateCheckRefreshMinInterval since the last fetch attempt is
// ignored and served from the cache (no new upstream hit), so the endpoint
// can't be used to hammer the GitHub API by repeated refreshes. A refresh
// once the interval has elapsed DOES force a fresh fetch. Pre-fix, every
// ?refresh=1 bypassed the cache and forced a fetchRelease.
func TestUpdateCheckRefreshThrottled(t *testing.T) {
	var hits int
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://github.com/invizen/pulsemon/releases/tag/v9.9.9"}`))
	}))
	defer gh.Close()

	oldBase := releaseBase
	releaseBase = gh.URL + "/releases"
	t.Cleanup(func() { releaseBase = oldBase })

	oldCache, oldAt, oldAttempt, oldFailed := updateCheckCached, updateCheckAt, updateCheckAttemptAt, updateCheckFailed
	oldTTL, oldMinRefresh := updateCheckTTL, updateCheckRefreshMinInterval
	t.Cleanup(func() {
		updateCheckCached, updateCheckAt, updateCheckAttemptAt, updateCheckFailed = oldCache, oldAt, oldAttempt, oldFailed
		updateCheckTTL, updateCheckRefreshMinInterval = oldTTL, oldMinRefresh
	})
	updateCheckCached, updateCheckFailed = nil, false
	updateCheckAt, updateCheckAttemptAt = time.Time{}, time.Time{}
	updateCheckTTL = time.Hour // normal polls served from cache, not re-fetched
	updateCheckRefreshMinInterval = 50 * time.Millisecond

	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	get := func(refresh bool) (int, updateCheckResult) {
		u := "/api/update-check"
		if refresh {
			u += "?refresh=1"
		}
		req := httptest.NewRequest("GET", u, nil)
		rec := httptest.NewRecorder()
		srv.handleUpdateCheck(rec, req)
		var res updateCheckResult
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		return rec.Code, res
	}

	// 1. First check (no refresh): fetches and caches. hits=1.
	code, res := get(false)
	if code != 200 || res.Latest != "v9.9.9" || res.Cached {
		t.Fatalf("first check: code=%d res=%+v", code, res)
	}
	if hits != 1 {
		t.Fatalf("first check hit upstream %d times, want 1", hits)
	}

	// 2. Immediate ?refresh=1 (within the min interval): IGNORED — served from
	//    the fresh cache, NO new upstream hit. Pre-fix this forced a fetch
	//    (hits would become 2).
	code, res = get(true)
	if code != 200 || res.Cached {
		t.Fatalf("throttled refresh: code=%d res=%+v, want 200 served from fresh cache", code, res)
	}
	if hits != 1 {
		t.Fatalf("throttled refresh hit upstream %d times, want still 1 (a refresh within the min interval must be ignored)", hits)
	}

	// 3. After the min interval elapses: ?refresh=1 forces a fresh fetch.
	time.Sleep(60 * time.Millisecond)
	code, res = get(true)
	if code != 200 || res.Cached {
		t.Fatalf("post-interval refresh: code=%d res=%+v", code, res)
	}
	if hits != 2 {
		t.Fatalf("post-interval refresh hit upstream %d times, want 2", hits)
	}
}

// TestCertFreshnessReusesConn verifies the cert-freshness optimization:
// after a successful HTTPS probe with cert data, certReadTimes records the
// host; a subsequent probe within certFreshness reuses the pooled
// connection (no forced fresh handshake). After the threshold expires, a
// fresh handshake is forced again.
