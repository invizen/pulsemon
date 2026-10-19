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

// TestMigrateAuthBootstrappedLegacyInstall: regression test for the v0.3.10
// incident. A legacy install — probe history, zero users, no
// auth_bootstrapped flag (it predates the setup-mode gate and ran with auth
// off) — must be marked bootstrapped at startup so the setup-mode gate does
// NOT lock it to the bootstrap surface. The documented "auth off = fully
// open" behavior is preserved. A genuinely fresh install (no probe rows)
// must stay in setup mode.
func TestMigrateAuthBootstrappedLegacyInstall(t *testing.T) {
	seedLegacy := func(t *testing.T) *DB {
		t.Helper()
		db := newTestDB(t)
		if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES ('s1', 'legacy', '10.0.0.1', 'icmp', 60, 1000, 25, 2, 3, 'active', 'up', '2026-01-01T00:00:00Z')`); err != nil {
			t.Fatalf("seed sensor: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('s1', '2026-10-13T00:00:00Z', 1.5)`); err != nil {
			t.Fatalf("seed probe: %v", err)
		}
		return db
	}

	// Legacy install (probe history, zero users, no flag) -> bootstrapped.
	db := seedLegacy(t)
	migrateAuthBootstrapped(db)
	if db.GetSetting("auth_bootstrapped") != "1" {
		t.Error("legacy install (probe history) not marked bootstrapped — dashboard would be locked to setup mode")
	}

	// Fresh install (no probe rows, zero users) -> stays in setup mode.
	fresh := newTestDB(t)
	migrateAuthBootstrapped(fresh)
	if fresh.GetSetting("auth_bootstrapped") == "1" {
		t.Error("fresh install (no probe history) marked bootstrapped — setup mode would be skipped")
	}

	// Idempotent: a second run changes nothing.
	migrateAuthBootstrapped(db)
	if db.GetSetting("auth_bootstrapped") != "1" {
		t.Error("migration not idempotent")
	}
}

// TestMigrateAuthBootstrappedLegacyInstallEndToEnd: the exact zenweb
// scenario, driven through the real gate. A legacy install (probe history,
// zero users) that has run the startup migration must serve the dashboard
// fully open (GET /api/sensors = 200), NOT locked to the bootstrap surface
// (403).
func TestMigrateAuthBootstrappedLegacyInstallEndToEnd(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('s1', 'legacy', '10.0.0.1', 'icmp', 60, 1000, 25, 2, 3, 'active', 'up', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO probes (sensor_id, ts, rtt_ms) VALUES ('s1', '2026-10-13T00:00:00Z', 1.5)`); err != nil {
		t.Fatalf("seed probe: %v", err)
	}
	migrateAuthBootstrapped(db) // what runServer does at startup

	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	r, err := httpSrv.Client().Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Errorf("legacy install sensor list after migration: %d, want 200 (fully open)", r.StatusCode)
	}
}

// setupBootstrapPost POSTs the first-account bootstrap through the auth gate
// with Host and Origin both set to host — the shape a DNS-rebinding page
// produces (Origin==Host passes the CSRF gate) — and returns the status.
func setupBootstrapPost(t *testing.T, srv *Server, host string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/users",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = host
	req.Header.Set("Origin", "http://"+host)
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	return rr.Code
}

// TestSetupModeAllowedHostsRejectsRebind: with PULSEMON_ALLOWED_HOSTS set, a
// bootstrap POST whose Host is not allowlisted (a rebinding page, where
// Origin==Host==rebind.example) is 421 and no account is created
// (2026-10-19 review M2).
func TestSetupModeAllowedHostsRejectsRebind(t *testing.T) {
	t.Setenv("PULSEMON_ALLOWED_HOSTS", "pulsemon.lan, 10.99.99.5:9299")
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if c := setupBootstrapPost(t, srv, "rebind.example:9299"); c != http.StatusMisdirectedRequest {
		t.Fatalf("rebind bootstrap: %d, want 421", c)
	}
	if n, err := db.UserCount(); err != nil || n != 0 {
		t.Fatalf("user count after rejected bootstrap = %d (err %v), want 0", n, err)
	}
	// Port-qualified entry must match the port exactly.
	if c := setupBootstrapPost(t, srv, "10.99.99.5:8080"); c != http.StatusMisdirectedRequest {
		t.Fatalf("wrong-port bootstrap: %d, want 421", c)
	}
}

// TestSetupModeAllowedHostsAccepts: an allowlisted Host (case-insensitive;
// a port-less entry matches any port) bootstraps normally.
func TestSetupModeAllowedHostsAccepts(t *testing.T) {
	t.Setenv("PULSEMON_ALLOWED_HOSTS", "pulsemon.lan, 10.99.99.5:9299")
	for _, host := range []string{"PulseMon.LAN:9299", "10.99.99.5:9299"} {
		db := newTestDB(t)
		srv := NewServer(db, NewProbeWorker(db))
		if c := setupBootstrapPost(t, srv, host); c != http.StatusOK {
			t.Fatalf("allowlisted bootstrap (Host %s): %d, want 200", host, c)
		}
	}
}

// TestSetupModeAllowedHostsUnset: no allowlist = the documented LAN-trust
// default — any Host bootstraps.
func TestSetupModeAllowedHostsUnset(t *testing.T) {
	t.Setenv("PULSEMON_ALLOWED_HOSTS", "")
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if c := setupBootstrapPost(t, srv, "rebind.example:9299"); c != http.StatusOK {
		t.Fatalf("bootstrap with no allowlist: %d, want 200", c)
	}
}
