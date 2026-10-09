package main

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
)

// resetSharedEngine rewinds the process-wide engine state so a test can
// simulate each outcome of the startup warm-up. SharedEngine is a
// sync.Once, so the Once must be re-zeroed between tests (tests in this
// package run sequentially by default — no t.Parallel here).
func resetSharedEngine(t *testing.T, mode string, err error) {
	t.Helper()
	sharedEngineOnce = sync.Once{}
	sharedEngineInst = nil
	sharedEngineErr = err
	if mode != "" {
		sharedEngineInst = &Engine{mode: mode}
	}
}

// runHealthz drives handleHealthz against a real store and decodes the JSON.
func runHealthz(t *testing.T, dbPath string) map[string]interface{} {
	t.Helper()
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
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
	var hz map[string]interface{}
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
