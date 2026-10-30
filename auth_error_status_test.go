package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAuthUserPasswordDeleteErrorStatuses pins the 2026-10-20 external-review
// fix: the change-password and delete-user handlers must map ONLY their
// client-facing errors (validation sentinels, the last-user guard) to 400,
// and return a generic 500 for every other failure — a raw driver string
// (e.g. "no such table: users", "database is locked") is a server fault and
// must not be echoed back as a 400. Both handlers used to do
// `respondWithError(w, 400, err.Error())` on the whole error space.
func TestAuthUserPasswordDeleteErrorStatuses(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	do := func(method, path, body string) (int, string) {
		t.Helper()
		var rd *strings.Reader
		if body != "" {
			rd = strings.NewReader(body)
		} else {
			rd = strings.NewReader("")
		}
		req, err := http.NewRequest(method, httpSrv.URL+path, rd)
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

	// Setup-mode bootstrap: first account is admin and re-enables auth.
	if code, body := do(http.MethodPost, "/api/auth/users", `{"username":"admin","password":"secretpw123"}`); code != 200 {
		t.Fatalf("bootstrap: got %d (%s), want 200", code, body)
	}
	// Login so the cookie jar holds the admin session.
	if code, body := do(http.MethodPost, "/api/auth/login", `{"username":"admin","password":"secretpw123"}`); code != 200 {
		t.Fatalf("login: got %d (%s), want 200", code, body)
	}

	// 1. Weak password: validation sentinel → 400 with our text (current
	// password correct, so the check reaches the new-password validation).
	if code, body := do(http.MethodPost, "/api/auth/users/admin/password", `{"current_password":"secretpw123","password":"short"}`); code != 400 {
		t.Fatalf("weak password change: got %d (%s), want 400", code, body)
	} else if !strings.Contains(body, "password") {
		t.Fatalf("weak password change: body %q does not carry the validation message", body)
	}

	// 2. Normal delete of a NON-last user still works (200) — the fix
	// must not have broken the happy path.
	if code, body := do(http.MethodPost, "/api/auth/users", `{"username":"temp","password":"secretpw123"}`); code != 200 {
		t.Fatalf("add temp user: got %d (%s), want 200", code, body)
	}
	if code, body := do(http.MethodDelete, "/api/auth/users/temp", ""); code != 200 {
		t.Fatalf("delete temp user: got %d (%s), want 200", code, body)
	}

	// 3. Last-user guard: business rule → 400 with the friendly message
	// (now the errLastUser sentinel, message byte-identical).
	if code, body := do(http.MethodDelete, "/api/auth/users/admin", ""); code != 400 {
		t.Fatalf("delete last user: got %d (%s), want 400", code, body)
	} else if !strings.Contains(body, "cannot remove the last user") {
		t.Fatalf("delete last user: body %q does not carry the guard message", body)
	}

	// 4. DB failure: with the users table gone, the current-password
	// verification (2026-10-23) hits the missing table FIRST and must
	// answer a generic 403 — NOT a 400/500 echoing the raw driver text.
	// The session's user-existence check is TTL-cached (2s) and was
	// primed by the requests above, so the gate still passes and the
	// handler runs (this call must stay within that window of step 3 —
	// it is back-to-back).
	if _, err := db.Exec("DROP TABLE users"); err != nil {
		t.Fatalf("drop users table: %v", err)
	}
	if code, body := do(http.MethodPost, "/api/auth/users/admin/password", `{"current_password":"secretpw123","password":"secretpw123"}`); code != 403 {
		t.Fatalf("password change with broken db: got %d (%s), want 403", code, body)
	} else if strings.Contains(body, "no such table") {
		t.Fatalf("password change with broken db: body %q leaks the raw driver text", body)
	}

	// 5. Delete-user DB failure: the gate's IsAdmin("admin") passes on
	// the TTL-cached answer primed by the back-to-back requests above
	// (2026-10-30 review #4 — IsAdmin is now userOKTTL-cached), and the
	// table exists for the handler. A MINIMAL users table (no created_at
	// column) makes the last-admin promotion UPDATE inside db.RemoveUser
	// hit a raw driver error. Deleting 'admin' (the last admin, with a
	// second user present) is the only path that reaches that UPDATE.
	if _, err := db.Exec("CREATE TABLE users (username TEXT PRIMARY KEY, is_admin INTEGER NOT NULL DEFAULT 0)"); err != nil {
		t.Fatalf("recreate minimal users table: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, is_admin) VALUES ('admin', 1), ('other', 0)"); err != nil {
		t.Fatalf("seed minimal users table: %v", err)
	}
	if code, body := do(http.MethodDelete, "/api/auth/users/admin", ""); code != 500 {
		t.Fatalf("delete user with broken db: got %d (%s), want 500", code, body)
	} else if strings.Contains(body, "no such column") || strings.Contains(body, "no such table") {
		t.Fatalf("delete user with broken db: body %q leaks the raw driver text", body)
	}
}
