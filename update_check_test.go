package main

// /api/update-check negative caching: a failing GitHub lookup serves the stale
// result (cached:true) and suppresses repeats; ?refresh=1 is throttled.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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

// TestUpdateCheckConcurrentPollsCoalesce pins the single-flight fetch: N
// concurrent pollers on a cold/expired cache must produce exactly ONE
// upstream fetch (pre-fix the mutex serialized them into N sequential
// fetches and the throttle read of updateCheckAttemptAt raced its write).
// The stale-serve path must also answer concurrently under -race.
func TestUpdateCheckConcurrentPollsCoalesce(t *testing.T) {
	var hits int32
	release := make(chan struct{})
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release // hold the flight open so joiners pile onto it
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://github.com/invizen/pulsemon/releases/tag/v9.9.9"}`))
	}))
	defer gh.Close()

	oldBase := releaseBase
	releaseBase = gh.URL + "/releases"
	t.Cleanup(func() { releaseBase = oldBase })

	oldCache, oldAt, oldAttempt, oldFailed := updateCheckCached, updateCheckAt, updateCheckAttemptAt, updateCheckFailed
	oldTTL, oldFailTTL, oldMinRefresh := updateCheckTTL, updateCheckFailTTL, updateCheckRefreshMinInterval
	t.Cleanup(func() {
		updateCheckCached, updateCheckAt, updateCheckAttemptAt, updateCheckFailed = oldCache, oldAt, oldAttempt, oldFailed
		updateCheckTTL, updateCheckFailTTL, updateCheckRefreshMinInterval = oldTTL, oldFailTTL, oldMinRefresh
	})
	updateCheckCached, updateCheckFailed = nil, false
	updateCheckAt, updateCheckAttemptAt = time.Time{}, time.Time{}
	updateCheckTTL, updateCheckFailTTL = time.Millisecond, time.Millisecond

	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))

	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := "/api/update-check"
			if i%2 == 1 {
				// refresh pollers exercise the throttle read concurrent
				// with the fetch leader's write of the attempt timestamp.
				u += "?refresh=1"
			}
			req := httptest.NewRequest("GET", u, nil)
			rec := httptest.NewRecorder()
			srv.handleUpdateCheck(rec, req)
			codes[i] = rec.Code
		}(i)
	}
	time.Sleep(100 * time.Millisecond) // all pollers are inside the flight now
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("%d concurrent pollers fired %d upstream fetches, want 1 (single-flight)", n, got)
	}
	for i, c := range codes {
		if c != http.StatusOK {
			t.Fatalf("poller %d got %d, want 200", i, c)
		}
	}

	// Stale path concurrently: expire the fresh entry, upstream now fails;
	// a second concurrent wave must all be served 200 (one fetch + shared
	// stale outcome for the joiners).
	gh.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	var wg2 sync.WaitGroup
	codes2 := make([]int, n)
	for i := 0; i < n; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			req := httptest.NewRequest("GET", "/api/update-check", nil)
			rec := httptest.NewRecorder()
			srv.handleUpdateCheck(rec, req)
			codes2[i] = rec.Code
		}(i)
	}
	wg2.Wait()
	for i, c := range codes2 {
		if c != http.StatusOK {
			t.Fatalf("stale-path poller %d got %d, want 200 (stale cached result)", i, c)
		}
	}

	// A slow fetch in flight (forced by refresh) must not stall a normal
	// poll that the fresh cache can serve: pre-fix the mutex was held
	// across the network call, so the poll blocked for the whole fetch.
	updateCheckMu.Lock()
	updateCheckFailed = false
	updateCheckCached = &updateCheckResult{Latest: "v9.9.9"}
	updateCheckAt = time.Now()
	updateCheckMu.Unlock()
	updateCheckTTL = time.Hour // cache is fresh for this wave
	updateCheckRefreshMinInterval = 0
	slow := make(chan struct{})
	go func() {
		w := httptest.NewRecorder()
		srv.handleUpdateCheck(w, httptest.NewRequest("GET", "/api/update-check?refresh=1", nil))
		close(slow)
	}()
	time.Sleep(50 * time.Millisecond) // the refresh is mid-fetch now
	start := time.Now()
	rec := httptest.NewRecorder()
	srv.handleUpdateCheck(rec, httptest.NewRequest("GET", "/api/update-check", nil))
	if el := time.Since(start); el > 150*time.Millisecond {
		t.Fatalf("normal poll blocked %v behind an in-flight fetch; cache must be served outside the fetch lock", el)
	}
	<-slow
}
