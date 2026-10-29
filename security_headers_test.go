package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// must match the Content-Security-Policy set in api.go (authGate). Kept as an
// exact literal on purpose: the whole point of the strict policy is that it is
// a fixed, auditable string with no 'unsafe-inline' and no hashes.
const wantCSP = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

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
			if got := resp.Header.Get("Content-Security-Policy"); got != wantCSP {
				t.Errorf("%s: CSP = %q, want %q", name, got, wantCSP)
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

// The strict CSP (script-src 'self'; style-src 'self', no 'unsafe-inline', no
// hashes) only works if the dashboard ships ZERO inline <script>/<style> —
// the theme, app, and custom CSS all live in files. This test pins that
// invariant so a future edit that re-inlines a block (which the CSP would then
// refuse to run, silently breaking the UI) is caught at test time.
func TestFix_csp_NoInlineScriptsOrStyles(t *testing.T) {
	d := newTestDB(t)
	srv := NewServer(d, NewProbeWorker(d))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	resp, err := http.Get(httpSrv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: got %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	html := string(body)

	// No inline <script> (a <script> tag that is not immediately a <script src=).
	if loc := strings.Index(html, "<script>"); loc != -1 {
		t.Errorf("inline <script> block present (CSP script-src 'self' would block it)")
	}
	// No inline <style> block.
	if strings.Contains(html, "<style>") {
		t.Errorf("inline <style> block present (CSP style-src 'self' would block it)")
	}
	// The external files the CSP 'self' source relies on must be referenced.
	for _, want := range []string{`src="/theme.js"`, `src="/app.js"`, `href="/styles.css"`, `href="/vendor/tailwind.css"`} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html missing expected asset ref %s", want)
		}
	}
}
