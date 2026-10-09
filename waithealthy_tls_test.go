package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	t.Setenv("PULSEMON_ADDR", u.Host)

	oldTimeout := healthzTimeout
	healthzTimeout = 3 * time.Second
	t.Cleanup(func() { healthzTimeout = oldTimeout })

	ok, detail := waitHealthy()
	if !ok {
		t.Fatalf("waitHealthy = false against a TLS-only healthz endpoint, want true: %s", detail)
	}
	if hits == 0 {
		t.Fatal("no request reached the TLS server")
	}
}
