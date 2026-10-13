package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSetupModeBootstrapOnly locks the pre-bootstrap gate: with zero users in
// the DB, only the bootstrap surface is reachable — static UI assets,
// /api/healthz, /api/auth/status, and POST /api/auth/users (the first
// account). Sensor create/list, settings, and the user list are 403, so an
// unauthenticated LAN host can't use the fresh-install window for SSRF or
// internal port scanning. Once the first account exists, the normal session
// gate takes over (401, not 403) and healthz stays open.
func TestSetupModeBootstrapOnly(t *testing.T) {
	db := newTestDB(t) // fresh DB, zero users
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	code := func(method, path, body string) int {
		var req *http.Request
		var err error
		if body != "" {
			req, err = http.NewRequest(method, httpSrv.URL+path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req, err = http.NewRequest(method, httpSrv.URL+path, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		r, err := httpSrv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}

	// Bootstrap surface: reachable in setup mode.
	if c := code(http.MethodGet, "/api/healthz", ""); c != http.StatusOK {
		t.Errorf("healthz in setup mode: %d, want 200", c)
	}
	if c := code(http.MethodGet, "/api/auth/status", ""); c != http.StatusOK {
		t.Errorf("auth/status in setup mode: %d, want 200", c)
	}
	if c := code(http.MethodGet, "/", ""); c != http.StatusOK {
		t.Errorf("static UI in setup mode: %d, want 200", c)
	}

	// Everything else: 403 in setup mode.
	if c := code(http.MethodPost, "/api/sensors", `{"name":"x","target":"10.99.99.1"}`); c != http.StatusForbidden {
		t.Errorf("sensor create in setup mode: %d, want 403", c)
	}
	if c := code(http.MethodGet, "/api/sensors", ""); c != http.StatusForbidden {
		t.Errorf("sensor list in setup mode: %d, want 403", c)
	}
	if c := code(http.MethodGet, "/api/settings", ""); c != http.StatusForbidden {
		t.Errorf("settings in setup mode: %d, want 403", c)
	}
	if c := code(http.MethodGet, "/api/auth/users", ""); c != http.StatusForbidden {
		t.Errorf("user list in setup mode: %d, want 403", c)
	}

	// First account: allowed — this is the bootstrap.
	if c := code(http.MethodPost, "/api/auth/users", `{"username":"admin","password":"secretpw"}`); c != http.StatusOK {
		t.Fatalf("first user create in setup mode: %d, want 200", c)
	}

	// Post-bootstrap: the same unauthenticated calls are now 401 (session
	// required) — the normal session gate took over, not the setup gate.
	if c := code(http.MethodGet, "/api/sensors", ""); c != http.StatusUnauthorized {
		t.Errorf("sensor list post-bootstrap: %d, want 401", c)
	}
	if c := code(http.MethodGet, "/api/healthz", ""); c != http.StatusOK {
		t.Errorf("healthz post-bootstrap: %d, want 200", c)
	}
}
