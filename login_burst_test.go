package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestFix_C2_ConcurrentLoginBurst pins the C2 fix: the per-IP login throttle
// used to CHECK (loginAllowed), then run bcrypt, and only AFTER that record
// the attempt (loginFailed) — so N concurrent wrong-password requests from
// one IP all passed the check first and all ran the KDF (repro: 60
// concurrent -> 59x 401, 1x 429). The fix counts the attempt atomically
// BEFORE the KDF (beginAttempt): at most loginFailMax concurrent attempts
// may run bcrypt; the rest are fast 429s.
func TestFix_C2_ConcurrentLoginBurst(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.auth.AddUser("alice", "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}

	const N = 60
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"username":"alice","password":"wrong-guess-%d"}`, i)
			req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
			req.RemoteAddr = "10.9.9.9:4444"
			rr := httptest.NewRecorder()
			srv.handleAuthLogin(rr, req)
			mu.Lock()
			codes[rr.Code]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// AT MOST loginFailMax requests may have run the KDF (401); the rest must
	// be fast 429 rejections.
	if codes[http.StatusUnauthorized] > loginFailMax {
		t.Errorf("burst: %d concurrent wrong passwords -> %d x 401, want at most %d (the KDF ran more than loginFailMax times — throttle bypassed by concurrency)",
			N, codes[http.StatusUnauthorized], loginFailMax)
	}
	if codes[http.StatusTooManyRequests] == 0 {
		t.Errorf("burst: no 429 responses among %d concurrent attempts — the throttle was bypassed by concurrency: %v", N, codes)
	}
	var sum int
	for _, c := range codes {
		sum += c
	}
	if sum != N {
		t.Errorf("burst: unexpected status mix: %v (want only 401/429, total %d)", codes, N)
	}

	// The IP must now be locked out: the next sequential attempt is a fast
	// 429, not a 401 (no bcrypt).
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"alice","password":"x"}`))
	req.RemoteAddr = "10.9.9.9:4444"
	rr := httptest.NewRecorder()
	srv.handleAuthLogin(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("post-burst sequential attempt from the burst IP: %d, want 429 (locked out)", rr.Code)
	}

	// A correct password from a DIFFERENT ip still logs in.
	req = httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"alice","password":"correct-horse-battery"}`))
	req.RemoteAddr = "10.8.8.8:5555"
	rr = httptest.NewRecorder()
	srv.handleAuthLogin(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("correct login from a fresh ip: %d, want 200", rr.Code)
	}

	// A correct login clears the counter for its OWN ip: loginFailMax-1
	// fails (under the limit), then a success, then a FULL fresh budget of
	// loginFailMax more fails — if the success had not cleared the counter,
	// the lockout would have arrived during the second batch.
	ip := "10.7.7.7:6666"
	for i := 0; i < loginFailMax-1; i++ {
		req = httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(fmt.Sprintf(`{"username":"alice","password":"bad-%d"}`, i)))
		req.RemoteAddr = ip
		rr = httptest.NewRecorder()
		srv.handleAuthLogin(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("pre-success fail %d: %d, want 401", i, rr.Code)
		}
	}
	req = httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"alice","password":"correct-horse-battery"}`))
	req.RemoteAddr = ip
	rr = httptest.NewRecorder()
	srv.handleAuthLogin(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("success after %d fails: %d, want 200", loginFailMax-1, rr.Code)
	}
	for i := 0; i < loginFailMax; i++ {
		req = httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(fmt.Sprintf(`{"username":"alice","password":"bad2-%d"}`, i)))
		req.RemoteAddr = ip
		rr = httptest.NewRecorder()
		srv.handleAuthLogin(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("post-success fail %d: %d, want 401 (a successful login must clear the counter; the lockout arrived early)", i, rr.Code)
			break
		}
	}
}
