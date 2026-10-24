package main

// Regression tests for the FULL-LIST minor/hardening batch (review
// 2026-10-24, second wave): the items from the complete review list that
// the selected-minor and nit batches did not cover — authz (users roster,
// setup-path throttle), validation (target/URL length, SMTP send-time
// control chars), SSRF list correction (Teredo), update-path hardening
// (mode preservation, hardlink .prev), probe-worker edge cases (zero
// timeout, monotonic ts, orphan state, ctx-bounded purge), alert-goroutine
// panic survival, and the settings tls_mode/credentials in-tx TOCTOU.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- validation length caps ----------

func TestValidTargetLengthCap(t *testing.T) {
	// 253 is the RFC 1035 FQDN max; the labels already pass targetRe, so
	// only the total bound can reject the 1 MiB-body-length target.
	long := strings.TrimSuffix(strings.Repeat("ab.", 85), ".") + ".com" // > 253
	if len(long) <= 253 {
		t.Fatalf("fixture not long enough: %d", len(long))
	}
	if validTarget(long) {
		t.Errorf("target of %d chars accepted, want reject at >253", len(long))
	}
	if !validTarget("nas") {
		t.Error("bare label must stay valid")
	}
	if !validTarget("192.168.1.1") {
		t.Error("IPv4 must stay valid")
	}
}

func TestValidURLLengthCap(t *testing.T) {
	if validURL("http://host.example/" + strings.Repeat("p", 4000)) {
		t.Error("4 KiB URL must be rejected")
	}
	if !validURL("http://host.example:8080/status?x=1") {
		t.Error("normal URL must stay valid")
	}
}

// ---------- SMTP send-time control-char rejection ----------

func TestSmtpEnvelopeAddrRejectsControlChars(t *testing.T) {
	if _, err := smtpEnvelopeAddr("a@b.com\r\nMAIL FROM:<evil>"); err == nil {
		t.Error("CRLF-carrying stored value must be rejected at SEND time")
	}
	if got, err := smtpEnvelopeAddr("Ops Bot <ops@example.com>"); err != nil || got != "ops@example.com" {
		t.Errorf("legacy display-name rescue: got %q err %v", got, err)
	}
	if got, err := smtpEnvelopeAddr("raw-but-odd"); err != nil || got != "raw-but-odd" {
		t.Errorf("unparseable control-char-free value must pass through raw, got %q err %v", got, err)
	}
}

// ---------- SSRF list: 6to4 labeled, Teredo actually blocked ----------

func TestTeredoBlocked(t *testing.T) {
	// Teredo is 2001:0000::/32 — note the SECOND group must be zero, so
	// this fixture is a genuine Teredo client address (RFC 4380 example).
	for _, ip := range []string{"2002:7f00:1::", "2001:0000:4136:e378:8000:63bf:3fff:fdd2"} {
		if err := checkWebhookIP(net.ParseIP(ip), "tunnel.example"); err == nil {
			t.Errorf("%s must be blocked (6to4 / Teredo embedding)", ip)
		}
	}
	if err := checkWebhookIP(net.ParseIP("2606:4700:4700::1111"), "public.example"); err != nil {
		t.Errorf("normal global v6 must stay allowed: %v", err)
	}
}

// ---------- update path: mode preservation + hardlink .prev ----------

func TestInstallBinaryPreservesModeAndNeverLosesDst(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "pulsemon")
	// Old binary, deliberately NOT 0755.
	if err := os.WriteFile(dst, []byte("OLD"), 0750); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "new")
	if err := os.WriteFile(src, []byte("NEWBINARY"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := installBinary(src, dst, ""); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0750 {
		t.Errorf("dst mode = %o, want preserved 0750 (review nit: forced 0755 widened perms)", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(dst)
	if string(b) != "NEWBINARY" {
		t.Errorf("dst content = %q", b)
	}
	prev, err := os.ReadFile(dst + ".prev")
	if err != nil || string(prev) != "OLD" {
		t.Errorf(".prev = %q err %v, want OLD", prev, err)
	}
	// .prev is a HARDLINK of the old inode taken BEFORE the swap: at no
	// point between the two steps did the dst name not exist (the old
	// rename→rename order had that power-loss hole). Verify the link
	// mechanics the fix relies on: after a second update the previous
	// .prev is replaced, not accumulated.
	src2 := filepath.Join(dir, "new2")
	if err := os.WriteFile(src2, []byte("NEWEST"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := installBinary(src2, dst, ""); err != nil {
		t.Fatal(err)
	}
	prev2, err := os.ReadFile(dst + ".prev")
	if err != nil || string(prev2) != "NEWBINARY" {
		t.Errorf("second .prev = %q err %v, want NEWBINARY", prev2, err)
	}
}

func TestInstallBinaryFreshInstallDefaultsExecutable(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "pulsemon") // no existing dst
	src := filepath.Join(dir, "new")
	if err := os.WriteFile(src, []byte("BIN"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := installBinary(src, dst, ""); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(dst)
	if fi.Mode().Perm()&0100 == 0 {
		t.Errorf("fresh install dst mode = %o, want owner-executable default", fi.Mode().Perm())
	}
}

// ---------- probe worker: zero-timeout fallback ----------

func TestDoProbeZeroTimeoutUsesFallback(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, type, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES ('zero1','zero','10.0.0.1','icmp',60,0,10,2,3,'active','up',?)`, fmtTS(time.Now())); err != nil {
		t.Fatal(err)
	}
	pw := NewProbeWorker(db)
	old := probeTarget
	defer func() { probeTarget = old }()
	var got time.Duration
	probeTarget = func(_ context.Context, _, _ string, d time.Duration) probeOutcome {
		got = d
		return probeOutcome{lost: true}
	}
	pw.doProbe(context.Background(), sensorConfig{id: "zero1", target: "10.0.0.1", probeType: "icmp", timeoutMS: 0})
	if got != pingNowTimeout {
		t.Errorf("zero timeout_ms produced %v, want the %v fallback (legacy row must not read 100%% loss while Pulse Now works)", got, pingNowTimeout)
	}
	// A real config still wins.
	pw.doProbe(context.Background(), sensorConfig{id: "zero1", target: "10.0.0.1", probeType: "icmp", timeoutMS: 3000})
	if got != 3*time.Second {
		t.Errorf("timeout_ms=3000 produced %v", got)
	}
}

// ---------- recordProbe: monotonic ts invariant ----------

func TestRecordProbeMonotonicTs(t *testing.T) {
	pw := NewProbeWorker(newTestDB(t))
	pw.recordProbe("s", probeEntry{ts: 100, rtt: 1})
	pw.recordProbe("s", probeEntry{ts: 90, rtt: 2}) // racing append landed out of order
	pw.recordProbe("s", probeEntry{ts: 95, rtt: 2})
	s := pw.statsCache["s"]
	if got := s.data[len(s.data)-1].ts; got != 100 {
		// data: [100, 100(clamped 90), 100(clamped 95)]
		if got < 100 {
			t.Fatalf("series ends at ts %d — ts-monotonic invariant broken", got)
		}
	}
	for i := 1; i < len(s.data); i++ {
		if s.data[i].ts < s.data[i-1].ts {
			t.Fatalf("ts decreased at %d: %d -> %d", i, s.data[i-1].ts, s.data[i].ts)
		}
	}
}

// ---------- purgeOld: ctx-cancellable ----------

func TestPurgeOldStopsOnCancel(t *testing.T) {
	db := newTestDB(t)
	pw := NewProbeWorker(db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	done := make(chan struct{})
	go func() { pw.purgeOld(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("purgeOld ignored the cancelled context")
	}
}

func TestWarmStatsStopsOnCancel(t *testing.T) {
	db := newTestDB(t)
	pw := NewProbeWorker(db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { pw.warmStats(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("warmStats ignored the cancelled context")
	}
	if len(pw.statsCache) != 0 {
		t.Errorf("cancelled warm must not publish, got %d entries", len(pw.statsCache))
	}
}

// ---------- alerts: panicking delivery survives ----------

func TestAlertGateConsumerSurvivesPanic(t *testing.T) {
	pw := NewProbeWorker(newTestDB(t))
	second := make(chan struct{})
	pw.enqueueAlert("s1", func() { panic("poisoned payload") })
	pw.enqueueAlert("s1", func() { close(second) })
	select {
	case <-second:
	case <-time.After(3 * time.Second):
		t.Fatal("a panicking job killed the gate consumer — the sensor's alerting is now permanently wedged")
	}
}

func TestLaunchAlertSurvivesPanic(t *testing.T) {
	pw := NewProbeWorker(newTestDB(t))
	pw.launchAlert(func() { panic("boom") })
	done := make(chan struct{})
	go func() { pw.alertWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("panicking launchAlert never released its WaitGroup count")
	}
}

// ---------- authz: users roster is admin-facing ----------

func TestUsersRosterSelfRowForNonAdmin(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	// Bootstrap admin, then an authenticated admin creates a helper.
	resp, err := http.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("bootstrap: %d", resp.StatusCode)
	}
	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar}
	resp, err = admin.Post(httpSrv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = admin.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"helper","password":"secretpw2"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin add helper: %d", resp.StatusCode)
	}

	// Admin sees the roster.
	var users []authUser
	getJSON(t, admin, httpSrv.URL+"/api/auth/users", &users)
	if len(users) != 2 {
		t.Fatalf("admin roster = %d users, want 2", len(users))
	}

	// Helper sees ONLY itself.
	jar2, _ := cookiejar.New(nil)
	helper := &http.Client{Jar: jar2}
	resp, err = helper.Post(httpSrv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"helper","password":"secretpw2"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("helper login: %d", resp.StatusCode)
	}
	var mine []authUser
	getJSON(t, helper, httpSrv.URL+"/api/auth/users", &mine)
	if len(mine) != 1 || mine[0].Username != "helper" {
		t.Fatalf("helper roster = %+v, want exactly its own row (roster was client-hidden, not server-gated)", mine)
	}
}

func getJSON(t *testing.T, c *http.Client, url string, out any) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

// ---------- setup-path throttle ----------

func TestSetupPOSTThrottledAndBucketIsolated(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	// Pre-fill the dedicated setup bucket exactly the way the handler
	// computes it (setup|<throttleKey>), WITHOUT touching the login bucket.
	setupKey := "setup|" + throttleKey("127.0.0.1")
	for i := 0; i < loginFailMax; i++ {
		if ok, _ := srv.auth.beginAttempt(setupKey); !ok {
			t.Fatalf("bucket filled in %d attempts (loginFailMax=%d)", i, loginFailMax)
		}
	}

	// The next unauthenticated setup POST must 429 with Retry-After,
	// never reaching bcrypt.
	resp, err := http.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("throttled setup POST = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("429 missing Retry-After")
	}

	// The LOGIN bucket is separate: the operator can still claim the
	// install through a different path once the window allows — prove
	// non-interference directly on the login key.
	if ok, _ := srv.auth.beginAttempt(throttleKey("127.0.0.1")); !ok {
		t.Error("setup throttle leaked into the login bucket")
	}
}

func TestSetupValidationFloodRefundsBucket(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	// Flood with payloads rejected BEFORE bcrypt: every one is refunded,
	// so the free rejections can never lock the operator out of claiming
	// the install (the throttle exists for KDF cost, which none paid).
	for i := 0; i < loginFailMax+3; i++ {
		resp, err := http.Post(httpSrv.URL+"/api/auth/users", "application/json",
			strings.NewReader(`{"username":"!!bad","password":"x"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("flood attempt %d = %d, want 400 (refunded, never 429)", i, resp.StatusCode)
		}
	}
	// Operator claims the install right after the flood: still works.
	resp, err := http.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("post-flood bootstrap = %d, want 200", resp.StatusCode)
	}
}

// ---------- settings: tls_mode=none + credentials TOCTOU (in-tx recheck) ----------

func TestSettingsTLSNoneCredsConcurrentPUTCannotCombine(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	resp, err := http.Post(httpSrv.URL+"/api/auth/users", "application/json",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar}
	resp, err = admin.Post(httpSrv.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	put := func(body string) int {
		r, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/api/settings", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		resp, err := admin.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Pre-fill the guard's check window deterministically: alternate the
	// winning write so BOTH orderings are exercised. The invariant must
	// hold every round: tls_mode=none AND stored credentials never coexist.
	for round := 0; round < 8; round++ {
		if err := db.SetSetting("smtp_tls_mode", "auto"); err != nil {
			t.Fatal(err)
		}
		if err := db.SetSetting("smtp_username", ""); err != nil {
			t.Fatal(err)
		}
		if err := db.SetSetting("smtp_password", ""); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		codeA, codeB := 0, 0
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			codeA = put(`{"providers":[{"kind":"smtp","extra":{"tls_mode":"none"}}]}`)
		}()
		go func() {
			defer wg.Done()
			<-start
			codeB = put(`{"providers":[{"kind":"smtp","extra":{"username":"user","password":"pass"}}]}`)
		}()
		close(start)
		wg.Wait()

		mode := db.GetSetting("smtp_tls_mode")
		creds := db.GetSetting("smtp_username") != "" || db.GetSetting("smtp_password") != ""
		if mode == "none" && creds {
			t.Fatalf("round %d: concurrent PUTs combined tls_mode=none with credentials (codes %d/%d) — in-tx recheck bypassed", round, codeA, codeB)
		}
		// The two bodies conflict by construction, so exactly one must be
		// refused with 400 (never two, never a silent both-OK — and with
		// the write lock pinned at BeginTx, never a BUSY 500 either).
		if got := boolInt(codeA == 400) + boolInt(codeB == 400); got != 1 {
			t.Fatalf("round %d: codes %d/%d — want exactly one 400 (guard must fire once, not over-block and not BUSY-fail)", round, codeA, codeB)
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
