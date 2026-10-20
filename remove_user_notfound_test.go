package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRemoveUserNonexistentReportsNotFound pins the 2026-10-20 external-review
// fix: removing a username that doesn't exist must FAIL, not report success.
// db.RemoveUser used to return nil for a nonexistent name (a "silent
// no-op"), so the API answered 200 and the CLI printed
// "User removed: <name>" for a mistyped username — a false success on an
// admin operation. Now:
//   - RemoveUser returns the errUserNotFound sentinel (name in the message)
//   - a mistyped name in a single-user install is "no such user", not
//     "cannot remove the last user"
//   - the API answers 404 — the same policy as the password endpoint
//     (unknown username → 404, not 403, so it doesn't confirm which names
//     exist)
//   - a real removal and the last-user guard are unaffected
func TestRemoveUserNonexistentReportsNotFound(t *testing.T) {
	// --- AuthState level (the CLI path: main.go prints err, exits 1)
	db := newTestDB(t)
	a := NewAuthState(db)
	for _, u := range []string{"admin", "temp", "third"} {
		if err := a.AddUser(u, "secretpw123"); err != nil {
			t.Fatal(err)
		}
	}
	// Multi-user install: nonexistent name → errUserNotFound, users intact.
	if err := a.RemoveUser("ghost"); !errors.Is(err, errUserNotFound) {
		t.Fatalf("RemoveUser(ghost) with 3 users = %v, want errUserNotFound", err)
	} else if !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("RemoveUser(ghost) = %q, want the name in the message", err)
	}
	if n, _ := db.UserCount(); n != 3 {
		t.Fatalf("UserCount after failed remove = %d, want 3", n)
	}
	// Single-user install: nonexistent name is the not-found error, NOT
	// the last-user guard (the guard only protects a REAL last user).
	for _, u := range []string{"admin", "temp"} {
		if err := a.RemoveUser(u); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.RemoveUser("ghost"); !errors.Is(err, errUserNotFound) {
		t.Fatalf("RemoveUser(ghost) with 1 user = %v, want errUserNotFound (not the last-user guard)", err)
	}
	// The real last user is still protected.
	if err := a.RemoveUser("third"); !errors.Is(err, errLastUser) {
		t.Fatalf("RemoveUser(third) with 1 user = %v, want errLastUser", err)
	}

	// --- API level
	db2 := newTestDB(t)
	srv := NewServer(db2, NewProbeWorker(db2))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	do := func(method, path, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, httpSrv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// Setup-mode bootstrap: admin is the ONLY user.
	if code, body := do(http.MethodPost, "/api/auth/users", `{"username":"admin","password":"secretpw123"}`); code != 200 {
		t.Fatalf("bootstrap: got %d (%s), want 200", code, body)
	}
	if code, body := do(http.MethodPost, "/api/auth/login", `{"username":"admin","password":"secretpw123"}`); code != 200 {
		t.Fatalf("login: got %d (%s), want 200", code, body)
	}
	// Single-user install: 404, NOT the last-user 400, NOT a 200.
	if code, body := do(http.MethodDelete, "/api/auth/users/ghost", ""); code != 404 {
		t.Fatalf("DELETE ghost (1 user): got %d (%s), want 404", code, body)
	} else if !strings.Contains(body, "no such user") {
		t.Fatalf("DELETE ghost (1 user): body %q, want the not-found message", body)
	}
	// Two-user install: the db.RemoveUser path — also 404.
	if code, body := do(http.MethodPost, "/api/auth/users", `{"username":"temp","password":"secretpw123"}`); code != 200 {
		t.Fatalf("add temp: got %d (%s), want 200", code, body)
	}
	if code, body := do(http.MethodDelete, "/api/auth/users/ghost", ""); code != 404 {
		t.Fatalf("DELETE ghost (2 users): got %d (%s), want 404", code, body)
	}
	// The real users are intact.
	if code, body := do(http.MethodGet, "/api/auth/status", ""); code != 200 || !strings.Contains(body, "admin") {
		t.Fatalf("status after failed deletes: %d (%s), want admin still present", code, body)
	}
	// A real removal still succeeds (happy path intact).
	if code, body := do(http.MethodDelete, "/api/auth/users/temp", ""); code != 200 {
		t.Fatalf("DELETE temp (real user): got %d (%s), want 200", code, body)
	}
}
