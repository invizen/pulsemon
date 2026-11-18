package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newAuthOffServer builds a server in the "operator disabled auth" state: zero
// users + the auth_bootstrapped flag set. This is the state
// migrateAuthBootstrapped leaves every older install that never created
// accounts in — and the state the DNS-rebinding read finding targets.
func newAuthOffServer(t *testing.T) *Server {
	t.Helper()
	db := newTestDB(t)
	if err := db.SetSetting("auth_bootstrapped", "1"); err != nil {
		t.Fatal(err)
	}
	return NewServer(db, NewProbeWorker(db))
}

// authOffGet drives a GET through the real authGate with an explicit Host (the
// DNS-rebinding page sets its own Host) and returns the status. GETs are exempt
// from the CSRF gate, so the Host is the only signal the allowlist sees.
func authOffGet(t *testing.T, srv *Server, path, host string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	return rr.Code
}

// TestAuthOffRebindingReadBlocked pins the DNS-rebinding read fix: with auth
// off (operator disabled) and PULSEMON_ALLOWED_HOSTS set, a same-origin GET of a
// DATA endpoint from a non-allowlisted Host (the rebound domain) is refused —
// reads included, not just mutations. The browser treats the rebound origin as
// same-origin, so a plain GET is the whole attack: it reads /api/sensors
// (targets with user:pass@ creds) and /api/settings (SMTP user, Telegram chat
// ID). Pre-fix, only the mutations were gated and these reads stayed open.
func TestAuthOffRebindingReadBlocked(t *testing.T) {
	t.Setenv("PULSEMON_ALLOWED_HOSTS", "pulsemon.lan, 10.99.99.5:9299")
	srv := newAuthOffServer(t)

	// The data endpoints a rebinding page reads.
	for _, path := range []string{"/api/sensors", "/api/settings"} {
		if c := authOffGet(t, srv, path, "rebind.example:9299"); c != http.StatusMisdirectedRequest {
			t.Fatalf("%s from non-allowlisted host: %d, want 421", path, c)
		}
	}
	// An allowlisted Host reads the same endpoints normally.
	for _, path := range []string{"/api/sensors", "/api/settings"} {
		if c := authOffGet(t, srv, path, "10.99.99.5:9299"); c != http.StatusOK {
			t.Fatalf("%s from allowlisted host: %d, want 200", path, c)
		}
	}
	// healthz is the container healthcheck and the external monitoring probe —
	// reachable from any host in every state, allowlist or not.
	if c := authOffGet(t, srv, "/api/healthz", "rebind.example:9299"); c != http.StatusOK {
		t.Fatalf("healthz from non-allowlisted host: %d, want 200 (always open)", c)
	}
}

// TestAuthOffRebindingUnsetStaysOpen pins the LAN-trust default: with auth off
// and NO PULSEMON_ALLOWED_HOSTS, reads stay open (the documented "auth off =
// fully open" behavior). The gate must not silently lock a trusted-LAN install
// that chose the default — the startup warning names that exposure instead.
func TestAuthOffRebindingUnsetStaysOpen(t *testing.T) {
	t.Setenv("PULSEMON_ALLOWED_HOSTS", "")
	srv := newAuthOffServer(t)
	if c := authOffGet(t, srv, "/api/sensors", "rebind.example:9299"); c != http.StatusOK {
		t.Fatalf("read with no allowlist: %d, want 200 (LAN-trust default)", c)
	}
}

// TestAuthOffRebindingMutationStillBlocked pins that the pre-existing mutation
// gate is subsumed, not regressed: a POST from a non-allowlisted Host in the
// same auth-off state is still refused (421) and no sensor is created. The read
// extension must not have loosened the write path.
func TestAuthOffRebindingMutationStillBlocked(t *testing.T) {
	t.Setenv("PULSEMON_ALLOWED_HOSTS", "pulsemon.lan, 10.99.99.5:9299")
	srv := newAuthOffServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/sensors",
		strings.NewReader(`{"name":"r","target":"127.0.0.1","type":"icmp","tags":[],"interval_s":60,"timeout_ms":1000,"loss_warn":25,"down_after":2,"spike_mult":5}`))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "rebind.example:9299"
	req.Header.Set("Origin", "http://rebind.example:9299") // Origin==Host: passes the CSRF gate, so the 421 is the allowlist, not CSRF
	rr := httptest.NewRecorder()
	srv.authGate().ServeHTTP(rr, req)
	if rr.Code != http.StatusMisdirectedRequest {
		t.Fatalf("mutation from non-allowlisted host: %d, want 421", rr.Code)
	}
	if got := len(srv.fetchSensors(context.Background())); got != 0 {
		t.Fatalf("sensor count after rejected mutation = %d, want 0", got)
	}
}
