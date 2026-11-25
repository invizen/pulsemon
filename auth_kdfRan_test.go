package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestVerifyUserKdfRanQueuedCancel pins the explicit KDF-cost signal on the
// zero-cost side: a ctx canceled while QUEUED on bcryptSem (saturated) must
// report kdfRan=false — the KDF never ran, so the disconnect arm refunds.
// The old elapsed-time floor read this case by wall clock; a queue wait of
// any length looked identical to a fast paid KDF.
func TestVerifyUserKdfRanQueuedCancel(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if err := a.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
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
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok, kdfRan := a.VerifyUser(ctx, "admin", "secretpw"); ok || kdfRan {
		t.Fatalf("VerifyUser(queued cancel) = ok=%v kdfRan=%v, want false, false (zero KDF cost)", ok, kdfRan)
	}
	// The dummy (unknown-user) path carries the same signal.
	if _, ok, kdfRan := a.VerifyUser(ctx, "ghost", "pw"); ok || kdfRan {
		t.Fatalf("VerifyUser(queued cancel, dummy path) = ok=%v kdfRan=%v, want false, false", ok, kdfRan)
	}
}

// TestVerifyUserKdfRanPaid pins the explicit signal on the paid side: every
// path that acquired a slot reports kdfRan=true — wrong password, unknown
// user (the dummy KDF is a KDF), and success. This is the side the old
// floor misread on fast CPUs (cost 10 in 20–25ms < 25ms floor → the paid
// KDF looked "free" and got refunded, opening an unbounded per-IP guessing
// channel with recordUserFail and loginSlowDown skipped).
func TestVerifyUserKdfRanPaid(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if err := a.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	if _, ok, kdfRan := a.VerifyUser(context.Background(), "admin", "secretpw"); !ok || !kdfRan {
		t.Fatalf("VerifyUser(success) = ok=%v kdfRan=%v, want true, true", ok, kdfRan)
	}
	if _, ok, kdfRan := a.VerifyUser(context.Background(), "admin", "wrongpw"); ok || !kdfRan {
		t.Fatalf("VerifyUser(wrong password) = ok=%v kdfRan=%v, want false, true (the KDF ran)", ok, kdfRan)
	}
	if _, ok, kdfRan := a.VerifyUser(context.Background(), "ghost", "pw"); ok || !kdfRan {
		t.Fatalf("VerifyUser(unknown user) = ok=%v kdfRan=%v, want false, true (the dummy KDF ran)", ok, kdfRan)
	}
}

// TestCreateSessionPropagatesKdfRan pins that CreateSession carries
// VerifyUser's signal through: queued cancel → false, success → true. The
// login arm refunds on this value, so a dropped propagation (e.g. a
// hardcoded false) would refund every disconnect including paid KDFs.
func TestCreateSessionPropagatesKdfRan(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if err := a.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	if tok, ok, kdfRan := a.CreateSession(context.Background(), "admin", "secretpw", false); !ok || tok == "" || !kdfRan {
		t.Fatalf("CreateSession(success) = ok=%v kdfRan=%v, want true, true", ok, kdfRan)
	}
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
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok, kdfRan := a.CreateSession(ctx, "admin", "secretpw", false); ok || kdfRan {
		t.Fatalf("CreateSession(queued cancel) = ok=%v kdfRan=%v, want false, false", ok, kdfRan)
	}
}

// TestLoginQueuedWaitThenDisconnectRefunds is the operator-self-lockout
// repro (the finding's failure mode 1): a multi-IP burst saturates
// bcryptSem, a legitimate login QUEUES, and the client disconnects after
// 40ms in the queue — longer than the old 25ms floor. The KDF never ran
// (zero cost), so the per-IP admission must be refunded. Pre-fix, the
// elapsed-time heuristic read the 40ms queue wait as "paid" and kept the
// admission: repeated by real timeouts/double-submits, the operator's own
// IP walked into the 5-minute lockout without a single wrong password.
func TestLoginQueuedWaitThenDisconnectRefunds(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
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
	key := throttleKey("192.0.2.1")
	ctx, cancel := context.WithCancel(context.Background())
	// Disconnect 40ms into the queue — past the old floor, so the old
	// code's time.Since(t0) < kdfCostFloor test misclassified this as paid.
	time.AfterFunc(40*time.Millisecond, cancel)
	req := httptest.NewRequest("POST", "/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`)).WithContext(ctx)
	rr := httptest.NewRecorder()
	srv.handleAuthLogin(rr, req)
	<-ctx.Done()

	srv.auth.loginThrottle.Lock()
	n := len(srv.auth.loginThrottle.fails[key])
	srv.auth.loginThrottle.Unlock()
	if n != 0 {
		t.Errorf("per-IP bucket after a 40ms queue-wait disconnect: %d counted attempts, want 0 (zero KDF cost — the refund must not depend on how long the queue wait took)", n)
	}
}
