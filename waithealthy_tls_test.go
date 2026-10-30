package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"pulsemon/internal/store"
	"strings"
	"testing"
	"time"
)

// TestWaitHealthyReachesTLSServer locks the Major fix: once a cert is
// installed, pulsemon serves HTTPS ONLY (the plain-HTTP port is not
// bound). waitHealthy must still find the service after `pulsemon update
// --restart` on a TLS-only install. Before the fix it polled http:// only
// -> connection refused -> false "service is down" after every cert
// change. This test fails against the old code.
func TestWaitHealthyReachesTLSServer(t *testing.T) {
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	t.Setenv("PULSEMON_ADDR", u.Host)

	oldTimeout := healthzTimeout
	healthzTimeout = 3 * time.Second
	t.Cleanup(func() { healthzTimeout = oldTimeout })

	ok, detail := waitHealthy(nil)
	if !ok {
		t.Fatalf("waitHealthy = false against a TLS-only healthz endpoint, want true: %s", detail)
	}
	if hits == 0 {
		t.Fatal("no request reached the TLS server")
	}
}

// TestWaitHealthyReachesTLSOnConfiguredPort locks the finding-7 fix: the
// production shape the old code could NEVER find. PULSEMON_ADDR is the
// plain port — which a TLS install does NOT bind at all — and the healthz
// answers on the CONFIGURED listener_https_port (custom, not 443). The old
// waitHealthy polled only the plain port, so `pulsemon update --restart`
// timed out and exited 1 on every TLS install. This test fails against the
// old code.
func TestWaitHealthyReachesTLSOnConfiguredPort(t *testing.T) {
	db, err := store.NewStore(filepath.Join(t.TempDir(), "tlsport.db"))
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/healthz" {
			w.Write([]byte(`{"status":"ok"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	_, httpsPort, _ := net.SplitHostPort(u.Host)
	if _, err := db.Exec(`INSERT INTO settings (setting_key, value) VALUES ('listener_https_port', ?)`, httpsPort); err != nil {
		t.Fatalf("set listener_https_port: %v", err)
	}

	// PULSEMON_ADDR points at a port nothing listens on: the TLS install
	// serves only the HTTPS port, so the plain port is dead by design.
	t.Setenv("PULSEMON_ADDR", "127.0.0.1:1")

	oldTimeout := healthzTimeout
	healthzTimeout = 3 * time.Second
	t.Cleanup(func() { healthzTimeout = oldTimeout })

	ok, detail := waitHealthy(db)
	if !ok {
		t.Fatalf("waitHealthy = false for a TLS install on a configured port, want true: %s", detail)
	}
	if !strings.HasPrefix(detail, "https://") {
		t.Errorf("healthy via %q, want the https candidate", detail)
	}
}

// TestWaitHealthyIgnoresNonPulsemonAnswers locks the payload check: a 2xx
// from some OTHER service on a candidate port (a reverse proxy on 443, a
// stale process on the HTTP port) must NOT be mistaken for the monitor.
// Without the body check, polling several candidate ports would produce
// false "healthy" results on any box where a candidate port is shared.
func TestWaitHealthyIgnoresNonPulsemonAnswers(t *testing.T) {
	// A stand-in for "something else on the HTTP port": 200 OK, but no
	// pulsemon healthz payload.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"service":"caddy"}`))
	}))
	defer other.Close()
	u, _ := url.Parse(other.URL)

	// PULSEMON_ADDR points at the imposter: its 200-without-payload is the
	// case under test. The 443 candidates are refused on a normal test box.
	t.Setenv("PULSEMON_ADDR", u.Host)

	oldTimeout := healthzTimeout
	healthzTimeout = 1 * time.Second
	t.Cleanup(func() { healthzTimeout = oldTimeout })

	ok, _ := waitHealthy(nil)
	if ok {
		t.Fatal("waitHealthy = true against a 2xx that is not pulsemon's healthz, want false")
	}
}
