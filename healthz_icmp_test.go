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

// TestHealthzVersionGated pins that /api/healthz reveals the exact version only
// to an authenticated session: an unauthenticated LAN host polling healthz must
// not be told the precise version (a targeting signal for known bugs), while a
// logged-in operator still sees it.
func TestHealthzVersionGated(t *testing.T) {
	// handleHealthz reads EngineMode()/EngineDead(), which join the shared
	// engine's sync.Once. Rewind + restore the state so a later icmp test
	// (TestProbeTargetDispatch) can open a real engine instead of hitting the
	// (done, nil, nil) state this test would otherwise leave behind.
	resetSharedEngine(t, "", nil)

	db, err := store.NewStore(t.TempDir() + "/hzver.db")
	if err != nil {
		t.Fatalf("store.NewStore: %v", err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	s := NewServer(db, NewProbeWorker(db))

	// Unauthenticated: version must be absent.
	rr := httptest.NewRecorder()
	s.handleHealthz(rr, httptest.NewRequest("GET", "/api/healthz", nil))
	var hz map[string]any
	if err := json.NewDecoder(rr.Result().Body).Decode(&hz); err != nil {
		t.Fatalf("decode unauth healthz: %v", err)
	}
	if _, present := hz["version"]; present {
		t.Fatalf("unauthenticated healthz leaked version %v", hz["version"])
	}

	// Authenticated (a valid session cookie for an existing user): version
	// must be present.
	if err := s.auth.AddUser(context.Background(), "admin", "secretpw"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	s.auth.sessions["hzver-tok"] = authSession{user: "admin", expiry: time.Now().Add(time.Hour), created: time.Now()}
	req := httptest.NewRequest("GET", "/api/healthz", nil)
	req.AddCookie(&http.Cookie{Name: authSessionName, Value: "hzver-tok"})
	rr2 := httptest.NewRecorder()
	s.handleHealthz(rr2, req)
	var hz2 map[string]any
	if err := json.NewDecoder(rr2.Result().Body).Decode(&hz2); err != nil {
		t.Fatalf("decode auth healthz: %v", err)
	}
	if hz2["version"] != Version {
		t.Fatalf("authenticated healthz version = %v, want %q", hz2["version"], Version)
	}
}
