package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"pulsemon/internal/store"
)

// TestAuthStatusAndLoginCarryIsAdmin pins MINOR-25 (2026-11-25 external
// review): /api/auth/status and /api/auth/login carry is_admin, so the UI
// gates the admin surface from the response itself — no extra
// /api/auth/users round-trip per page load (which non-admins 403'd into
// the fail-closed path).
func TestAuthStatusAndLoginCarryIsAdmin(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatal(err)
	}
	// A non-admin with a REAL bcrypt hash so the login path verifies it.
	hash, err := bcrypt.GenerateFromPassword([]byte("viewerpw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password_hash, created_at, is_admin) VALUES ('viewer', ?, ?, 0)", string(hash), store.Now()); err != nil {
		t.Fatal(err)
	}

	status := func(tok string) map[string]any {
		req := httptest.NewRequest("GET", "/api/auth/status", nil)
		if tok != "" {
			req.AddCookie(&http.Cookie{Name: authSessionName, Value: tok})
		}
		rr := httptest.NewRecorder()
		srv.handleAuthStatus(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status: %d", rr.Code)
		}
		var m map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	adminTok, ok, _ := srv.auth.CreateSession(context.Background(), "admin", "secretpw", false)
	if !ok {
		t.Fatal("admin session failed")
	}
	viewerTok, ok, _ := srv.auth.CreateSession(context.Background(), "viewer", "viewerpw", false)
	if !ok {
		t.Fatal("viewer session failed")
	}

	// status carries the flag per session.
	if v := status(adminTok)["is_admin"]; v != true {
		t.Errorf("status(admin).is_admin = %v, want true", v)
	}
	if v, present := status(viewerTok)["is_admin"]; present && v != false {
		t.Errorf("status(viewer).is_admin = %v, want absent/false (omitempty)", v)
	}
	if v, present := status("")["is_admin"]; present {
		t.Errorf("status(no session).is_admin present = %v, want absent", v)
	}

	// login carries the flag in its response.
	login := func(username, password string) map[string]any {
		body := `{"username":"` + username + `","password":"` + password + `"}`
		req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
		rr := httptest.NewRecorder()
		srv.handleAuthLogin(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("login(%s): %d", username, rr.Code)
		}
		var m map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if v := login("admin", "secretpw")["is_admin"]; v != true {
		t.Errorf("login(admin).is_admin = %v, want true", v)
	}
	if v, present := login("viewer", "viewerpw")["is_admin"]; present && v != false {
		t.Errorf("login(viewer).is_admin = %v, want absent/false (omitempty)", v)
	}
}
