package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"pulsemon/internal/store"
	"sync"
	"testing"
	"time"
)

// resetSharedEngine rewinds the process-wide engine state so a test can
// simulate each outcome of the startup warm-up. SharedEngine is a
// sync.Once, so the Once must be re-zeroed between tests (tests in this
// package run sequentially by default — no t.Parallel here).
//
// It also restores a clean "not yet opened" state when the test (or subtest)
// ends. Without that, a re-zeroed Once can be consumed by a LATER test's
// EngineMode()/EngineDead() no-op join (Do(func(){})) and left as
// (done, nil, nil) — a state SharedEngine() can't recover from, because
// sync.Once can't re-run NewEngine(). A later icmp probe then panics on a
// nil engine (TestProbeTargetDispatch in the full -race run hit exactly this).
func resetSharedEngine(t *testing.T, mode string, err error) {
	t.Helper()
	sharedEngineOnce = sync.Once{}
	sharedEngineInst = nil
	sharedEngineErr = err
	if mode != "" {
		sharedEngineInst = &Engine{mode: mode}
	}
	t.Cleanup(func() {
		sharedEngineOnce = sync.Once{}
		sharedEngineInst = nil
		sharedEngineErr = nil
	})
}

// runHealthz drives handleHealthz against a real store and decodes the JSON.
func runHealthz(t *testing.T, dbPath string) map[string]any {
	t.Helper()
	db, err := store.NewStore(dbPath)
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	s := NewServer(db, NewProbeWorker(db))
	req := httptest.NewRequest("GET", "/api/healthz", nil)
	rr := httptest.NewRecorder()
	s.handleHealthz(rr, req)
	body, err := io.ReadAll(rr.Result().Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var hz map[string]any
	if err := json.Unmarshal(body, &hz); err != nil {
		t.Fatalf("decode healthz %q: %v", body, err)
	}
	return hz
}

// TestHealthzIcmpMode pins the three /api/healthz ICMP states so the silent
// failure mode can't regress: when BOTH transports fail (e.g. RHEL 8's
// default ping_group_range excludes the uid, no CAP_NET_RAW) healthz must
// report status=degraded + icmp_mode=unavailable + a remediation hint —
// never "ok" with the key simply missing.
func TestHealthzIcmpMode(t *testing.T) {
	t.Run("engine dead: degraded + unavailable + hint", func(t *testing.T) {
		resetSharedEngine(t, "", errNoIcmpTransport)
		hz := runHealthz(t, t.TempDir()+"/z.db")
		if hz["status"] != "degraded" {
			t.Fatalf("status = %v, want degraded", hz["status"])
		}
		if hz["icmp_mode"] != "unavailable" {
			t.Fatalf("icmp_mode = %v, want unavailable", hz["icmp_mode"])
		}
		hint, _ := hz["icmp_hint"].(string)
		if hint == "" {
			t.Fatal("icmp_hint missing — the operator has no remediation guidance")
		}
	})

	t.Run("unprivileged-datagram: ok + mode, no hint", func(t *testing.T) {
		resetSharedEngine(t, "unprivileged-datagram", nil)
		hz := runHealthz(t, t.TempDir()+"/z.db")
		if hz["status"] != "ok" {
			t.Fatalf("status = %v, want ok", hz["status"])
		}
		if hz["icmp_mode"] != "unprivileged-datagram" {
			t.Fatalf("icmp_mode = %v, want unprivileged-datagram", hz["icmp_mode"])
		}
		if _, present := hz["icmp_hint"]; present {
			t.Fatal("icmp_hint must not be present when ICMP works")
		}
	})

	t.Run("raw fallback: ok + raw", func(t *testing.T) {
		resetSharedEngine(t, "raw", nil)
		hz := runHealthz(t, t.TempDir()+"/z.db")
		if hz["status"] != "ok" || hz["icmp_mode"] != "raw" {
			t.Fatalf("status=%v icmp_mode=%v, want ok/raw", hz["status"], hz["icmp_mode"])
		}
	})

	// Leave a clean state for any other test that warms the engine.
	resetSharedEngine(t, "", nil)
}

// TestHealthzVersionGated pins the /api/healthz version-disclosure rule:
//   - auth enabled + unauthenticated: version ABSENT (a targeting signal for
//     known bugs is not leaked to any unauthenticated LAN host),
//   - auth enabled + a valid session: version PRESENT (the logged-in operator
//     sees it),
//   - auth disabled (no users): version PRESENT — there is no session to gate
//     on and the whole dashboard is open to the LAN anyway, so blanking it
//     would leave the dashboard's version pill empty.
func TestHealthzVersionGated(t *testing.T) {
	// handleHealthz reads EngineMode()/EngineDead(), which join the shared
	// engine's sync.Once. Rewind + restore the state so a later icmp test
	// (TestProbeTargetDispatch) can open a real engine instead of hitting the
	// (done, nil, nil) state this test would otherwise leave behind.
	resetSharedEngine(t, "", nil)

	newServer := func(t *testing.T) *Server {
		t.Helper()
		db, err := store.NewStore(t.TempDir() + "/hz.db")
		if err != nil {
			t.Fatalf("store.NewStore: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		if err := db.InitSchema(); err != nil {
			t.Fatalf("InitSchema: %v", err)
		}
		return NewServer(db, NewProbeWorker(db))
	}
	healthz := func(t *testing.T, s *Server, tok string) map[string]any {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/healthz", nil)
		if tok != "" {
			req.AddCookie(&http.Cookie{Name: authSessionName, Value: tok})
		}
		rr := httptest.NewRecorder()
		s.handleHealthz(rr, req)
		var hz map[string]any
		if err := json.NewDecoder(rr.Result().Body).Decode(&hz); err != nil {
			t.Fatalf("decode healthz: %v", err)
		}
		return hz
	}

	t.Run("auth enabled, unauthenticated: version absent", func(t *testing.T) {
		s := newServer(t)
		if err := s.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
			t.Fatalf("AddUser: %v", err)
		}
		if _, present := healthz(t, s, "")["version"]; present {
			t.Fatal("unauthenticated healthz (auth enabled) leaked the version")
		}
	})

	t.Run("auth enabled, authenticated: version present", func(t *testing.T) {
		s := newServer(t)
		if err := s.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
			t.Fatalf("AddUser: %v", err)
		}
		s.auth.sessions["tok"] = authSession{user: "admin", expiry: time.Now().Add(time.Hour), created: time.Now()}
		if v := healthz(t, s, "tok")["version"]; v != Version {
			t.Fatalf("authenticated healthz version = %v, want %q", v, Version)
		}
	})

	t.Run("auth disabled (no users): version present", func(t *testing.T) {
		s := newServer(t) // no user added: auth is disabled, no session to gate on
		if v := healthz(t, s, "")["version"]; v != Version {
			t.Fatalf("auth-disabled healthz version = %v, want %q (the dashboard's version pill would be blank)", v, Version)
		}
	})
}
