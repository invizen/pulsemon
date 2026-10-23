package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFix_g1_SecurityHeaders(t *testing.T) {
	d := newTestDB(t)
	srv := NewServer(d, NewProbeWorker(d))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	d.SetSetting("auth_bootstrapped", "1")
	// Enable auth by adding a user
	if err := srv.auth.AddUser("admin", "password123"); err != nil {
		t.Fatalf("failed to add admin user: %v", err)
	}

	checkHeaders := func(name string, url string, expectedStatus int) {
		resp, err := http.Get(httpSrv.URL + url)
		if err != nil {
			t.Fatalf("%s: failed GET %s: %v", name, url, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != expectedStatus {
			t.Fatalf("%s: got status %d, want %d", name, resp.StatusCode, expectedStatus)
		}

		if expectedStatus == http.StatusOK {
			headers := []string{
				"X-Content-Type-Options",
				"X-Frame-Options",
				"Referrer-Policy",
				"Content-Security-Policy",
			}
			for _, h := range headers {
				if got := resp.Header.Get(h); got == "" {
					t.Errorf("%s: missing header %s", name, h)
				}
			}
			// Check specific values
			if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("%s: X-Content-Type-Options = %q, want nosniff", name, resp.Header.Get("X-Content-Type-Options"))
			}
			if resp.Header.Get("X-Frame-Options") != "DENY" {
				t.Errorf("%s: X-Frame-Options = %q, want DENY", name, resp.Header.Get("X-Frame-Options"))
			}
			if resp.Header.Get("Referrer-Policy") != "no-referrer" {
				t.Errorf("%s: Referrer-Policy = %q, want no-referrer", name, resp.Header.Get("Referrer-Policy"))
			}
			if resp.Header.Get("Content-Security-Policy") != "frame-ancestors 'none'" {
				t.Errorf("%s: CSP = %q, want frame-ancestors 'none'", name, resp.Header.Get("Content-Security-Policy"))
			}
		}
	}

	// 1) GET /
	checkHeaders("GET /", "/", http.StatusOK)

	// 2) GET /api/healthz
	checkHeaders("GET /api/healthz", "/api/healthz", http.StatusOK)

	// 3) Unauthenticated 401 API response
	// Since auth is enabled, an unauthenticated request to an /api/ endpoint should be 401.
	resp, err := http.Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/sensors: got %d, want 401", resp.StatusCode)
	}
	// Check headers on 401 too
	headers := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Content-Security-Policy",
	}
	for _, h := range headers {
		if got := resp.Header.Get(h); got == "" {
			t.Errorf("unauthenticated 401: missing header %s", h)
		}
	}
}
