package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestFix_QueuedCancelRefundsPerIPAttempt pins the 2026-11-13 review
// finding: the login and change-password disconnect arms
// (CreateSession/VerifyUser returning false on a canceled ctx) returned
// WITHOUT refunding the per-IP throttle admission beginAttempt appended.
// A client that disconnects while QUEUED on bcryptSem pays zero KDF cost,
// so under the refund contract ("throttling is for KDF cost") its admission
// must come back — without the refund, an attacker who saturates the
// semaphore (NumCPU slots) turns every operator timeout/double-submit into
// a free budget burn, and the operator's own IP walks into the 7/60s
// 5-minute lockout without typing a single wrong password.
//
// Construction: saturate bcryptSem, then drive loginFailMax canceled-ctx
// requests through BOTH handlers. Pre-fix the bucket reaches 2*loginFailMax
// entries and the follow-up LIVE login 429s; post-fix every queued cancel
// refunded (bucket empty) and the live login succeeds.
func TestFix_QueuedCancelRefundsPerIPAttempt(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	// Live session for the change-password arm (KDF paid BEFORE saturation).
	tok, ok := srv.auth.CreateSession(context.Background(), "admin", "secretpw", false)
	if !ok {
		t.Fatal("CreateSession for test session failed")
	}
	// Saturate the KDF semaphore: every acquireBcryptSem below queues, so a
	// canceled ctx returns from the select in microseconds — the zero-cost
	// window the refund must cover. Non-blocking drain at cleanup so the
	// semaphore is never left saturated for sibling tests.
	t.Cleanup(func() {
		for {
			select {
			case <-bcryptSem:
			default:
				return
			}
		}
	})
	for i := 0; i < cap(bcryptSem); i++ {
		bcryptSem <- struct{}{}
	}

	key := throttleKey("192.0.2.1") // RemoteAddr of httptest.NewRequest

	for i := 0; i < loginFailMax; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // disconnected BEFORE the handler reached the queue
		req := httptest.NewRequest("POST", "/api/auth/login",
			strings.NewReader(`{"username":"ghostuser","password":"wrongpw"}`)).WithContext(ctx)
		rr := httptest.NewRecorder()
		srv.handleAuthLogin(rr, req)
	}
	for i := 0; i < loginFailMax; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req := httptest.NewRequest("POST", "/api/auth/users/admin/password",
			strings.NewReader(`{"current_password":"secretpw","password":"newpassword1"}`)).WithContext(ctx)
		req.AddCookie(&http.Cookie{Name: authSessionName, Value: tok})
		rr := httptest.NewRecorder()
		srv.Mux().ServeHTTP(rr, req)
	}

	srv.auth.loginThrottle.Lock()
	n := len(srv.auth.loginThrottle.fails[key])
	srv.auth.loginThrottle.Unlock()
	if n != 0 {
		t.Errorf("per-IP bucket after %d queued cancels on two handlers: %d counted attempts, want 0 (zero-KDF-cost disconnects must refund)", 2*loginFailMax, n)
	}

	// The operator-lockout repro end-to-end: release the slots and log in
	// for real. Pre-fix the accumulated zero-cost burns set the 5-minute
	// lockout, so this answers 429.
	for i := 0; i < cap(bcryptSem); i++ {
		<-bcryptSem
	}
	req := httptest.NewRequest("POST", "/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	rr := httptest.NewRecorder()
	srv.handleAuthLogin(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("live login after queued cancels: %d, want 200 (zero-cost disconnects must not lock out the operator)", rr.Code)
	}
}

// TestFix_PaidKDFDisconnectNotRefunded pins the OTHER half of the split —
// the guard against the review's literal suggested fix, which refunded on
// r.Context().Err() != nil unconditionally. A client that disconnects DURING
// the KDF (bcrypt runs ctx-ignoring to completion) PAID the cost, so the
// admission must stay counted: refunding it would give a scripted attacker an
// unbounded per-IP guessing channel (abort mid-KDF → refund → re-spray,
// capped only by the global semaphore, with recordUserFail and loginSlowDown
// both skipped). Same split as the setup-mode path, which deliberately does
// NOT refund its in-tx bootstrap race loss ("it DID pay the KDF").
//
// Cancel fires 20ms into a bcrypt that runs ≥50ms: the arm takes the
// paid-KDF branch (elapsed ≥ kdfCostFloor → no refund). If the machine is
// fast enough that the KDF finishes before the 20ms cancel lands, the
// request takes the full 401 path — which counts the attempt too. Both
// outcomes must leave exactly one counted admission.
func TestFix_PaidKDFDisconnectNotRefunded(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	key := throttleKey("192.0.2.1")

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	req := httptest.NewRequest("POST", "/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"wrongpw"}`)).WithContext(ctx)
	rr := httptest.NewRecorder()
	srv.handleAuthLogin(rr, req)

	srv.auth.loginThrottle.Lock()
	n := len(srv.auth.loginThrottle.fails[key])
	srv.auth.loginThrottle.Unlock()
	if n != 1 {
		t.Errorf("per-IP bucket after one paid-KDF disconnect: %d counted attempts, want 1 (a paid KDF is never refunded)", n)
	}
}
