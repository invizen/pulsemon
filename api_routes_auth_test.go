package main

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestAPIRoutesAllSessionWrapped audits the authorization rule from external
// review #8 at the SOURCE level: every /api/ route registered in routes()
// must carry an explicit requireAuth/requireAdmin wrapper — defense-in-depth
// so no handler's authorization rests on authGate having run (the
// sessionFrom contract) — EXCEPT the four endpoints that are sessionless by
// definition (healthz + the auth bootstrap surface). The audit is a text
// check on routes() so a future HandleFunc added unwrapped fails the suite
// (precedent: delete_confirm_test.go).
func TestAPIRoutesAllSessionWrapped(t *testing.T) {
	f, err := os.Open("api.go")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	routeRE := regexp.MustCompile(`s\.mux\.HandleFunc\("([^"]+)",`)
	public := map[string]bool{
		"/api/healthz":     true,
		"/api/auth/status": true,
		"/api/auth/login":  true,
		"/api/auth/logout": true,
	}

	inRoutes := false
	checked, publicSeen := 0, map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "func (s *Server) routes()") {
			inRoutes = true
			continue
		}
		if !inRoutes {
			continue
		}
		if line == "}" {
			break // end of routes()
		}
		m := routeRE.FindStringSubmatch(line)
		if m == nil {
			continue // comments, wrapped-handler bodies
		}
		path := m[1]
		if i := strings.LastIndexByte(path, ' '); i >= 0 {
			path = path[i+1:] // strip "GET " / "POST " etc.
		}
		if !strings.HasPrefix(path, "/api/") {
			continue // "/" static catch-all
		}
		wrapped := strings.Contains(line, "s.requireAuth(") ||
			strings.Contains(line, "s.requireAdmin(")
		if public[path] {
			publicSeen[path] = true
			if wrapped {
				t.Errorf("public route %s is session-wrapped — it must stay reachable without a session", path)
			}
			continue
		}
		checked++
		if !wrapped {
			t.Errorf("/api/ route %q registered without requireAuth/requireAdmin — every /api/ route must carry an explicit session wrapper (external review #8)", m[1])
		}
	}
	if checked == 0 {
		t.Fatal("route audit found no /api/ registrations — regex/parser drift")
	}
	for p := range public {
		if !publicSeen[p] {
			t.Errorf("expected public route %s not registered in routes()", p)
		}
	}
	t.Logf("audited %d wrapped /api/ routes + %d public exemptions", checked, len(publicSeen))
}

// TestWrappedReadRoutesDenyWithoutGate proves the wrappers are live, not
// comments: with auth enabled and NO session, every wrapped read route
// (sensors, sensor detail, history, graph, ping, update-check) answers 401
// when the request is served by the mux DIRECTLY — bypassing authGate
// entirely. On the pre-#8 code these routes were unwrapped, so the bare mux
// served them (200/404) and their safety rested solely on the gate.
func TestWrappedReadRoutesDenyWithoutGate(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.auth.AddUser(context.Background(), "audit1", "str0ngpassword"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if !srv.auth.Enabled() {
		t.Fatal("auth must be enabled after AddUser")
	}
	// Hit the mux DIRECTLY: no authGate in the chain.
	bare := httptest.NewServer(srv.mux)
	defer bare.Close()

	type req struct {
		method, path string
	}
	for _, r := range []req{
		{http.MethodGet, "/api/sensors"},
		{http.MethodGet, "/api/sensors/does-not-exist"},
		{http.MethodGet, "/api/sensors/does-not-exist/history"},
		{http.MethodGet, "/api/sensors/does-not-exist/graph"},
		{http.MethodPost, "/api/sensors/does-not-exist/ping"},
		{http.MethodGet, "/api/update-check"},
		{http.MethodGet, "/api/tags"},
		{http.MethodGet, "/api/events"},
	} {
		hreq, err := http.NewRequest(r.method, bare.URL+r.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(hreq)
		if err != nil {
			t.Fatalf("%s %s: %v", r.method, r.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s via bare mux (auth on, no session): got %d, want 401 — the route is not wrapped",
				r.method, r.path, resp.StatusCode)
		}
	}
}
