package main

// Regression tests for the 2026-10-24 review NIT batch:
//   (1) respondInternal sanitizes user-supplied values out of log lines
//       (CRLF log forging, control chars, unbounded length).
//   (2) throttle/session map sweeps are rate-limited (a spray made every
//       login pay an O(n) walk — O(n^2) total, serialized on the mutex)
//       and the throttle map carries a hard memory cap.
//   (3) the session cookie's Secure decision is pinned at mint and carried
//       through sliding renewals (a renewal on a request that failed to
//       present X-Forwarded-Proto used to re-issue the SAME token without
//       Secure).
//   (4) entering maintenance mode reads the active-sensor snapshot INSIDE
//       the pause transaction (the pre-tx read let sensors activated in the
//       gap keep probing under mode=ON).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestLogSafe(t *testing.T) {
	if got := logSafe("x\nCRITICAL forged"); got != "x CRITICAL forged" {
		t.Errorf("newline not neutralized: %q", got)
	}
	if got := logSafe("a\r\nb\x00c\x1b[31m"); strings.ContainsAny(got, "\r\n\x00\x1b") {
		t.Errorf("control chars survived: %q", got)
	}
	long := strings.Repeat("é", 200) // multi-byte: clamp must not split runes
	got := logSafe(long)
	if !utf8.ValidString(got) {
		t.Errorf("clamp produced invalid UTF-8 (rune split): %x", got[len(got)-3:])
	}
	if !strings.HasSuffix(got, "…") || len([]rune(got)) != 121 {
		t.Errorf("clamp wrong: runes=%d suffix=%q", len([]rune(got)), got[len(got)-1:])
	}
}

func TestRespondInternalLogSingleLine(t *testing.T) {
	d := newTestDB(t)
	if _, err := d.Exec(`DROP TABLE sensor_tags`); err != nil {
		t.Fatal(err)
	}
	mux := NewServer(d, NewProbeWorker(d)).Mux() // auth off

	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prev) })

	rr := httptest.NewRecorder()
	// Tag carries a CR+LF + "CRITICAL" payload: it must not forge a line.
	mux.ServeHTTP(rr, httptest.NewRequest("DELETE", "/api/tags?tag=evil%0aCRITICAL%20forged%0d%0aFAKE", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500", rr.Code)
	}
	out := strings.TrimRight(logBuf.String(), "\n")
	if lines := strings.Split(out, "\n"); len(lines) != 1 {
		t.Fatalf("log forged: %d lines:\n%s", len(lines), out)
	}
	lower := strings.ToLower(out)
	if i := strings.Index(lower, "critical"); i == 0 {
		t.Fatalf("payload starts its own line: %q", out)
	}
}

func TestThrottleSweepRateLimited(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	now := time.Now()
	stale := now.Add(-2 * loginFailWindow)

	seed := func() {
		a.loginThrottle.Lock()
		a.ensureThrottleMaps()
		for i := 0; i < throttleSweepThreshold+50; i++ {
			a.loginThrottle.fails[fmt.Sprintf("10.%d.%d.%d", (i/65536)%256, (i/256)%256, i%256)] = []time.Time{now}
		}
		a.loginThrottle.fails["9.9.9.9"] = []time.Time{stale}
		a.loginThrottle.Unlock()
	}
	hasStale := func() bool {
		a.loginThrottle.Lock()
		defer a.loginThrottle.Unlock()
		_, ok := a.loginThrottle.fails["9.9.9.9"]
		return ok
	}

	seed()
	a.beginAttempt("1.1.1.1") // first past-threshold call: sweeps
	if hasStale() {
		t.Fatal("first past-threshold attempt should sweep stale entries")
	}
	// Re-seed the stale entry; the next attempt is inside the sweep
	// interval, so the sweep must NOT run (this is the O(n^2) fix).
	a.loginThrottle.Lock()
	a.loginThrottle.fails["9.9.9.9"] = []time.Time{stale}
	a.loginThrottle.Unlock()
	a.beginAttempt("1.1.1.2")
	if !hasStale() {
		t.Fatal("sweep ran again inside the rate-limit window")
	}
	// Force the window open: sweep resumes.
	a.loginThrottle.Lock()
	a.loginThrottle.nextSweep = time.Time{}
	a.loginThrottle.Unlock()
	a.beginAttempt("1.1.1.3")
	if hasStale() {
		t.Fatal("sweep did not run once the interval elapsed")
	}
}

func TestThrottleHardCapResets(t *testing.T) {
	origCap, origThresh := throttleHardCap, throttleSweepThreshold
	defer func() { throttleHardCap, throttleSweepThreshold = origCap, origThresh }()
	throttleSweepThreshold = 10 // sweep gate must open for the cap branch to run
	throttleHardCap = 15
	a := NewAuthState(newTestDB(t))
	now := time.Now()
	a.loginThrottle.Lock()
	a.ensureThrottleMaps()
	for i := 0; i < 20; i++ { // all in-window: the sweep cannot prune
		a.loginThrottle.fails[fmt.Sprintf("10.0.0.%d", i)] = []time.Time{now}
	}
	a.loginThrottle.lockout["10.0.0.3"] = now.Add(loginLockout)
	a.loginThrottle.Unlock()

	if ok, _ := a.beginAttempt("1.2.3.4"); !ok {
		t.Fatal("fresh IP must be allowed")
	}
	a.loginThrottle.Lock()
	n := len(a.loginThrottle.fails)
	l := len(a.loginThrottle.lockout)
	a.loginThrottle.Unlock()
	if n > 20 { // one entry re-added for 1.2.3.4
		t.Fatalf("hard cap did not reset the spray map: %d entries", n)
	}
	if l > 1 {
		t.Fatalf("hard cap did not clear the lockout map: %d entries", l)
	}
}

func TestSessionSweepRateLimited(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	if err := a.AddUserMode("admin", "secretpw", true); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a.mu.Lock()
	for i := 0; i < 68; i++ {
		a.sessions[fmt.Sprintf("tok%03d", i)] = authSession{user: "admin", expiry: now.Add(time.Hour), cookieIssued: now}
	}
	a.sessions["expired"] = authSession{user: "admin", expiry: now.Add(-time.Minute), cookieIssued: now}
	a.mu.Unlock()

	if _, ok := a.CreateSession("admin", "secretpw", false); !ok {
		t.Fatal("CreateSession failed")
	}
	a.mu.Lock()
	_, gone := a.sessions["expired"]
	a.mu.Unlock()
	if gone {
		t.Fatal("first past-threshold CreateSession should sweep the expired session")
	}

	a.mu.Lock()
	a.sessions["expired2"] = authSession{user: "admin", expiry: now.Add(-time.Minute), cookieIssued: now}
	a.mu.Unlock()
	if _, ok := a.CreateSession("admin", "secretpw", false); !ok {
		t.Fatal("CreateSession failed")
	}
	a.mu.Lock()
	_, still := a.sessions["expired2"]
	a.mu.Unlock()
	if !still {
		t.Fatal("session sweep ran inside the rate-limit window")
	}
}

func TestCookieSecurePinAcrossRenewal(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	if err := a.AddUserMode("admin", "secretpw", true); err != nil {
		t.Fatal(err)
	}
	age := func(tok string) {
		a.mu.Lock()
		s := a.sessions[tok]
		s.cookieIssued = time.Now().Add(-authSessionTTL)
		a.sessions[tok] = s
		a.mu.Unlock()
	}

	secureTok, ok := a.CreateSession("admin", "secretpw", true)
	if !ok {
		t.Fatal("CreateSession(secure) failed")
	}
	plainTok, ok := a.CreateSession("admin", "secretpw", false)
	if !ok {
		t.Fatal("CreateSession failed")
	}
	age(secureTok)
	age(plainTok)

	if due, pin := a.CookieRenewalDue(secureTok); !due || !pin {
		t.Fatalf("Secure-minted session lost its pin: due=%v pin=%v", due, pin)
	}
	if due, pin := a.CookieRenewalDue(plainTok); !due || pin {
		t.Fatalf("plain session wrongly reported a Secure pin: due=%v pin=%v", due, pin)
	}
}

func TestEnterMaintenanceWithFreshSnapshot(t *testing.T) {
	d := newTestDB(t)
	ins := func(id, state string) {
		if _, err := d.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
			VALUES (?, ?, '127.0.0.1', 60, 1000, 25, 3, 3, ?, 'up', ?)`,
			id, id, state, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	ins("a1", "active")
	ins("a2", "active")
	ins("p1", "paused")

	ids, err := d.EnterMaintenanceWithFreshSnapshot()
	if err != nil {
		t.Fatalf("EnterMaintenanceWithFreshSnapshot: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("paused ids = %v, want the 2 active sensors", ids)
	}
	var paused, stillActive int
	if err := d.QueryRow(`SELECT COUNT(*) FROM sensors WHERE state='paused'`).Scan(&paused); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM sensors WHERE state='active'`).Scan(&stillActive); err != nil {
		t.Fatal(err)
	}
	if paused != 3 || stillActive != 0 {
		t.Fatalf("states wrong: paused=%d active=%d (want 3/0; p1 was already paused)", paused, stillActive)
	}
	if mode := d.GetSetting("maintenance_mode"); mode != "1" {
		t.Fatalf("maintenance_mode = %q, want 1", mode)
	}
	var snap []string
	if err := json.Unmarshal([]byte(d.GetSetting("maintenance_active_ids")), &snap); err != nil {
		t.Fatalf("snapshot not valid JSON: %v (%q)", err, d.GetSetting("maintenance_active_ids"))
	}
	if len(snap) != 2 {
		t.Fatalf("snapshot = %v, want the 2 previously-active ids", snap)
	}
}
