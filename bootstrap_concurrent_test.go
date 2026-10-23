package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestFix_FirstUserConcurrentSingleAdmin pins the single first-admin
// invariant on the production path: N concurrent bootstrap POSTs (the
// fresh-install surface is open to the whole LAN) must yield exactly ONE
// account — the winner's AddUserMode runs COUNT + INSERT +
// auth_bootstrapped in one BEGIN IMMEDIATE transaction, the losers see
// user_count > 0 inside the transaction and get 409. The DB-level
// (*DB).AddUser helper used to duplicate this invariant as a non-atomic
// autocommit COUNT-then-INSERT: a concurrent pair on an empty table could
// both read n==0 and mint two "first" admins, and it never set
// auth_bootstrapped. It had no production callers (API and CLI both go
// through AuthState.AddUserMode), so it was removed (2026-10-22 external
// review) — this test pins the atomic path that now owns the invariant.
func TestFix_FirstUserConcurrentSingleAdmin(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	const N = 8
	var wg sync.WaitGroup
	codes := make([]int, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"username":"user%d","password":"secretpw%d"}`, i, i)
			resp, err := httpSrv.Client().Post(httpSrv.URL+"/api/auth/users", "application/json", strings.NewReader(body))
			if err != nil {
				t.Errorf("bootstrap POST %d: %v", i, err)
				return
			}
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	var ok, conflict int
	for i, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
		default:
			t.Errorf("bootstrap POST %d: status %d, want 200 or 409", i, c)
		}
	}
	if ok != 1 {
		t.Errorf("concurrent bootstraps: %d x 200 (%d x 409), want exactly 1 x 200 (the first-admin invariant): codes=%v", ok, conflict, codes)
	}
	if n, err := db.UserCount(); err != nil || n != 1 {
		t.Fatalf("user count = %d (err %v), want 1 (one and only one first account)", n, err)
	}
	var isAdmin int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = 1").Scan(&isAdmin); err != nil {
		t.Fatal(err)
	}
	if isAdmin != 1 {
		t.Errorf("admin count = %d, want 1 (the single first account is the admin)", isAdmin)
	}
	if db.GetSetting("auth_bootstrapped") != "1" {
		t.Error("auth_bootstrapped not set with the first account (must commit atomically with it)")
	}
}
