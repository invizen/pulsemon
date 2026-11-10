package main

// DELETE /api/tags is a fleet-wide destructive rewrite, so it is admin-gated
// (a non-admin gets 403; an admin reaches the handler).

import (
	"net/http"
	"net/http/cookiejar"
	"testing"
)

func TestNonAdminCannotDeleteTags(t *testing.T) {
	_, httpSrv := adminFlagServer(t)

	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar}
	bootstrapAdmin(t, admin, httpSrv.URL)
	if code := postJSONStatus(t, admin, httpSrv.URL+"/api/auth/login",
		`{"username":"admin","password":"secretpw"}`); code != 200 {
		t.Fatalf("admin login: %d", code)
	}
	if code := postJSONStatus(t, admin, httpSrv.URL+"/api/auth/users",
		`{"username":"helper","password":"helperpw1"}`); code != 200 {
		t.Fatalf("admin add helper: %d", code)
	}
	hjar, _ := cookiejar.New(nil)
	helper := &http.Client{Jar: hjar}
	if code := postJSONStatus(t, helper, httpSrv.URL+"/api/auth/login",
		`{"username":"helper","password":"helperpw1"}`); code != 200 {
		t.Fatalf("helper login: %d", code)
	}

	if code := requestStatus(t, helper, http.MethodDelete, httpSrv.URL+"/api/tags?tag=alerting", ""); code != http.StatusForbidden {
		t.Fatalf("non-admin DELETE /api/tags: code = %d, want 403", code)
	}
	// Admin still reaches the handler (unknown tag is a benign no-op).
	if code := requestStatus(t, admin, http.MethodDelete, httpSrv.URL+"/api/tags?tag=alerting", ""); code != http.StatusOK {
		t.Fatalf("admin DELETE /api/tags: code = %d, want 200", code)
	}
}
