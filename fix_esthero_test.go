package main

// fix_esthero_test.go — asserting tests for the esthero track review fixes
// (one file per track, per docs/RULES.md). Each test is named
// TestFix_<ID>_<what> and fails on the pre-fix baseline.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixSelfSignedCert builds a self-signed cert for ip with the given
// BasicConstraints / KeyUsage shape (the 9-shape matrix from the review).
func fixSelfSignedCert(t *testing.T, bcValid, isCA bool, ku x509.KeyUsage, ip net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "pulsemon-fix"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: ku, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{ip}, BasicConstraintsValid: bcValid, IsCA: isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestFix_M6_SelfSignedShapes pins the M6(a) fix: the old gate
// (leaf.CheckSignatureFrom(leaf)) demanded CA:TRUE plus a certSign-able key
// usage, so only 2 of the 9 real-world self-signed shapes were accepted —
// the common homelab shapes (CA:FALSE, digSig+keyEnc) got FALSE DOWN. The
// fix accepts a cert when issuer==subject AND the signature verifies with
// the leaf's OWN key, then the existing exact-hostname verify runs.
func TestFix_M6_SelfSignedShapes(t *testing.T) {
	ip := net.ParseIP("192.168.1.50")
	type bcv struct {
		n    string
		v    bool
		isCA bool
	}
	type kuv struct {
		n  string
		ku x509.KeyUsage
	}
	for _, b := range []bcv{
		{"no-BC-ext", false, false},
		{"CA:FALSE", true, false},
		{"CA:TRUE", true, true},
	} {
		for _, k := range []kuv{
			{"no-KU", 0},
			{"KU=digSig+keyEnc", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
			{"KU=digSig+certSign", x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign},
		} {
			crt := fixSelfSignedCert(t, b.v, b.isCA, k.ku, ip)
			leaf, err := x509.ParseCertificate(crt.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyHTTPCert([]*x509.Certificate{leaf}, ip.String()); err != nil {
				t.Errorf("SELFSIGNED %-10s %-20s => REJECT (%v), want ACCEPT (real self-signed server cert shape)", b.n, k.n, err)
			}
		}
	}

	// Forged cert: the SAME subject/issuer names as a self-signed cert for
	// the target, but signed by a DIFFERENT key. issuer==subject holds, so
	// the name equality alone must not be enough — the signature must verify
	// with the leaf's own key. REJECT.
	name := pkix.Name{CommonName: "pulsemon-fix"}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: name, Issuer: name,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: name,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{ip},
	}
	forgedDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := x509.ParseCertificate(forgedDER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forged.RawIssuer, forged.RawSubject) {
		t.Fatalf("test setup: forged cert must have issuer==subject names")
	}
	if err := verifyHTTPCert([]*x509.Certificate{forged}, ip.String()); err == nil {
		t.Error("FORGED cert (same names, signed by a different key) was ACCEPTED — the self-signed gate must verify the signature with the leaf's own key")
	}

	// The exact-hostname rule on the self-signed path must stay: a
	// self-signed cert for a DIFFERENT ip is still a reject.
	other := fixSelfSignedCert(t, true, false, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, net.ParseIP("10.1.2.3"))
	otherLeaf, _ := x509.ParseCertificate(other.Certificate[0])
	if err := verifyHTTPCert([]*x509.Certificate{otherLeaf}, ip.String()); err == nil {
		t.Error("self-signed cert for a different ip was ACCEPTED for this target — exact match must be preserved")
	}
}

// fixLanIP returns this machine's private IPv4, or skips the test.
func fixLanIP(t *testing.T) net.IP {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() && ipn.IP.IsPrivate() {
			return ipn.IP.To4()
		}
	}
	t.Skip("no private LAN ip available")
	return nil
}

// TestFix_M6_CrossHostRedirectVerifiesFinalHost pins the M6(b) fix: after a
// redirect, the presented cert belongs to the FINAL hop, but the old code
// verified it against the ORIGINAL target host — a valid self-signed cert
// for the final host was a FALSE DOWN (repro: http://127.0.0.1:A -> 302 ->
// https://<lan-ip>:B, cert valid for <lan-ip>, Lost=true). The fix verifies
// against the final request's host.
func TestFix_M6_CrossHostRedirectVerifiesFinalHost(t *testing.T) {
	lan := fixLanIP(t)

	// B: HTTPS on the LAN ip, cert valid for exactly that IP.
	b := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	b.Listener = ln
	b.TLS = &tls.Config{Certificates: []tls.Certificate{
		fixSelfSignedCert(t, true, true, x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign, lan),
	}}
	b.StartTLS()
	defer b.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	bURL := fmt.Sprintf("https://%s:%d/", lan, port)

	// Control: probing B directly works (cert is valid for B).
	r0 := probeHTTP(context.Background(), bURL, 5*time.Second)
	if r0.Lost {
		t.Fatalf("control: direct probe of B lost: %v", r0.Err)
	}

	// A: plain HTTP on loopback that 302s to B (a different host — the
	// redirect guard allows RFC1918 cross-host hops).
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, bURL, 302)
	}))
	defer a.Close()
	r1 := probeHTTP(context.Background(), a.URL+"/", 5*time.Second)
	if r1.Lost {
		t.Errorf("redirect A(127.0.0.1) -> B(https, valid self-signed cert for %s): lost=%v status=%v err=%v — the cert must be verified against the FINAL host, not the original",
			lan, r1.Lost, r1.Status, r1.Err)
	}
}

// fixServerWithDB builds a Server on a fresh schema-initialized DB.
func fixServerWithDB(t *testing.T) (*Server, *DB) {
	t.Helper()
	db := newTestDB(t)
	return NewServer(db, NewProbeWorker(db)), db
}

// TestFix_M7_PutSettingsKeepsRouting pins the M7(a) fix: a partial
// PUT /api/settings used to reset alert_scope to "all" and alert_filter to
// [] on EVERY save (repro: tags/["prod"] -> all/[] after saving
// {"realert_min":10}). AlertScope/AlertFilter are now pointers: nil = keep.
// Validation of scope/realert/filter also happens BEFORE any write, so a
// 400 leaves the store untouched.
func TestFix_M7_PutSettingsKeepsRouting(t *testing.T) {
	srv, db := fixServerWithDB(t)
	_ = db.SetSetting("alert_scope", "tags")
	_ = db.SetSetting("alert_filter", `["prod"]`)
	_ = db.SetSetting("realert_min", "30")

	// A partial save must keep scope + filter and change only realert_min.
	req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"realert_min": 10}`))
	rr := httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT {realert_min:10}: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := db.GetSetting("alert_scope"); got != "tags" {
		t.Errorf("alert_scope = %q after partial PUT, want \"tags\" (must be kept, not reset to all)", got)
	}
	if got := db.GetSetting("alert_filter"); got != `["prod"]` {
		t.Errorf("alert_filter = %q after partial PUT, want [\"prod\"] (must be kept, not reset to [])", got)
	}
	if got := db.GetSetting("realert_min"); got != "10" {
		t.Errorf("realert_min = %q after PUT, want \"10\"", got)
	}

	// Explicit values are still written (the dashboard saves full objects).
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"alert_scope":"all","alert_filter":[],"realert_min":15}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT full object: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := db.GetSetting("alert_scope"); got != "all" {
		t.Errorf("alert_scope = %q after explicit PUT, want \"all\"", got)
	}
	if got := db.GetSetting("alert_filter"); got != "[]" {
		t.Errorf("alert_filter = %q after explicit PUT, want []", got)
	}

	// An INVALID scope in the same request is a 400 and must not write the
	// valid fields that travel with it (validate everything first).
	_ = db.SetSetting("realert_min", "15")
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"realert_min": 99, "alert_scope": "bogus"}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT bogus scope: %d, want 400", rr.Code)
	}
	if got := db.GetSetting("realert_min"); got != "15" {
		t.Errorf("realert_min = %q after a 400 PUT, want \"15\" (a rejected save must not partially write)", got)
	}
}

// TestFix_M7_PatchInvalidFieldDoesNotPersistTags pins the M7(b) fix: a PATCH
// used to write the tags BEFORE validating the remaining fields, so a 400
// left the tag set changed (repro: {"tags":["sneaky"],"interval_s":0} ->
// 400 with tags persisted). The tag write now happens only after ALL
// validation, in the same transaction as the UPDATE.
func TestFix_M7_PatchInvalidFieldDoesNotPersistTags(t *testing.T) {
	srv, db := fixServerWithDB(t)
	id := newID()
	if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, 'a','10.0.0.1','icmp',60,1000,25,2,5,'paused','up',?)`, id, tsNow()); err != nil {
		t.Fatal(err)
	}

	// Valid tags + an invalid interval: 400, and the tags must NOT persist.
	req := httptest.NewRequest("PATCH", "/api/sensors/"+id, strings.NewReader(`{"tags":["sneaky"],"interval_s":0}`))
	req.SetPathValue("id", id)
	rr := httptest.NewRecorder()
	srv.handleSensorByID(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PATCH {tags, interval_s:0}: %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if tags := db.SensorTags(id); len(tags) != 0 {
		t.Errorf("tags persisted after a 400 PATCH: %v — the tag write must not happen before validation", tags)
	}

	// A valid PATCH with tags still works and persists them.
	req = httptest.NewRequest("PATCH", "/api/sensors/"+id, strings.NewReader(`{"tags":["sneaky","ok"]}`))
	req.SetPathValue("id", id)
	rr = httptest.NewRecorder()
	srv.handleSensorByID(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PATCH valid tags: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	tags := db.SensorTags(id)
	if len(tags) != 2 || tags[0] != "ok" || tags[1] != "sneaky" {
		t.Errorf("tags after valid PATCH = %v, want [ok sneaky]", tags)
	}
}

// TestFix_M7_PatchDuplicateName409 pins the M7(c) fix: a PATCH rename (and a
// clone) hitting the UNIQUE name constraint used to return 500 with raw SQL
// text. It must return 409 {"error":"sensor name already exists"}, exactly
// like POST does.
func TestFix_M7_PatchDuplicateName409(t *testing.T) {
	srv, db := fixServerWithDB(t)
	mk := func(name string) string {
		id := newID()
		if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, ?,'10.0.0.1','icmp',60,1000,25,2,5,'paused','up',?)`, id, name, tsNow()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	_ = mk("one")
	id2 := mk("two")

	req := httptest.NewRequest("PATCH", "/api/sensors/"+id2, strings.NewReader(`{"name":"one"}`))
	req.SetPathValue("id", id2)
	rr := httptest.NewRecorder()
	srv.handleSensorByID(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("PATCH rename to an existing name: %d, want 409: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode 409 body: %v", err)
	}
	if body.Error != "sensor name already exists" {
		t.Errorf("409 body = %q, want \"sensor name already exists\" (no raw SQL text)", body.Error)
	}
	// The original name is untouched.
	var name string
	if err := db.QueryRow("SELECT name FROM sensors WHERE id = ?", id2).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "two" {
		t.Errorf("name = %q after a rejected rename, want \"two\"", name)
	}

	// Clone: a normal clone finds a free "-copy" name and succeeds.
	srcID := mk("cloneme")
	req = httptest.NewRequest("POST", "/api/sensors/"+srcID+"/clone", nil)
	req.SetPathValue("id", srcID)
	rr = httptest.NewRecorder()
	srv.handleSensorClone(rr, req)
	if rr.Code != http.StatusCreated {
		t.Errorf("clone: %d, want 201: %s", rr.Code, rr.Body.String())
	}

	// Clone cap: with every "-copy".."-copy100" name taken, the clone is a
	// 409 (never a 500).
	capID := mk("capped")
	for i := 1; i <= 100; i++ {
		nm := "capped-copy"
		if i > 1 {
			nm = fmt.Sprintf("capped-copy%d", i)
		}
		if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, ?,'10.0.0.1','icmp',60,1000,25,2,5,'paused','up',?)`, newID(), nm, tsNow()); err != nil {
			t.Fatal(err)
		}
	}
	req = httptest.NewRequest("POST", "/api/sensors/"+capID+"/clone", nil)
	req.SetPathValue("id", capID)
	rr = httptest.NewRecorder()
	srv.handleSensorClone(rr, req)
	if rr.Code != http.StatusConflict {
		t.Errorf("clone with all candidate names taken: %d, want 409: %s", rr.Code, rr.Body.String())
	}
}

// TestFix_M2_EnabledFailsClosed pins the M2 fix: Enabled() computed
// `enabled = err == nil && n > 0`, so a transient COUNT(*) error (e.g.
// "database is locked") read as "auth disabled" for the 2s cache TTL — the
// auth gate FAILED OPEN on a DB hiccup. The fix keeps the last known value
// on error, and fails CLOSED (enabled) when there is no last known value
// (first-ever read).
func TestFix_M2_EnabledFailsClosed(t *testing.T) {
	db := newTestDB(t)
	a := NewAuthState(db)
	if err := a.AddUser("bob", "longenoughpw"); err != nil {
		t.Fatal(err)
	}
	if !a.Enabled() {
		t.Fatal("baseline: auth must be enabled with one user")
	}

	// Transient DB error after the cache expired: the gate must keep the
	// last known state (enabled), not open.
	a.userCountFn = func() (int, error) { return 0, errors.New("database is locked") }
	a.enabledMu.Lock()
	a.enabledAt = time.Time{} // expire the cache
	a.enabledMu.Unlock()
	if !a.Enabled() {
		t.Error("Enabled() = false after a transient DB error — the gate failed OPEN; it must keep the last known state (enabled)")
	}

	// First-ever read that errors must fail CLOSED (enabled = true): a
	// fresh AuthState has no last known value, so the safe answer is "auth
	// on".
	b := NewAuthState(db)
	b.userCountFn = func() (int, error) { return 5, errors.New("database is locked") }
	if !b.Enabled() {
		t.Error("Enabled() = false on a first-ever count error — must fail CLOSED (enabled)")
	}

	// refreshEnabledNow must apply the same rule: an error while the state
	// is known keeps it; it must not flip a known-enabled state to open.
	a.refreshEnabledNow()
	if !a.Enabled() {
		t.Error("refreshEnabledNow on a DB error flipped a known-enabled state to disabled")
	}
}

// TestFix_C2_ConcurrentLoginBurst pins the C2 fix: the per-IP login throttle
// used to CHECK (loginAllowed), then run bcrypt, and only AFTER that record
// the attempt (loginFailed) — so N concurrent wrong-password requests from
// one IP all passed the check first and all ran the KDF (repro: 60
// concurrent -> 59x 401, 1x 429). The fix counts the attempt atomically
// BEFORE the KDF (beginAttempt): at most loginFailMax concurrent attempts
// may run bcrypt; the rest are fast 429s.
func TestFix_C2_ConcurrentLoginBurst(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	if err := srv.auth.AddUser("alice", "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}

	const N = 60
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"username":"alice","password":"wrong-guess-%d"}`, i)
			req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
			req.RemoteAddr = "10.9.9.9:4444"
			rr := httptest.NewRecorder()
			srv.handleAuthLogin(rr, req)
			mu.Lock()
			codes[rr.Code]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// AT MOST loginFailMax requests may have run the KDF (401); the rest must
	// be fast 429 rejections.
	if codes[http.StatusUnauthorized] > loginFailMax {
		t.Errorf("burst: %d concurrent wrong passwords -> %d x 401, want at most %d (the KDF ran more than loginFailMax times — throttle bypassed by concurrency)",
			N, codes[http.StatusUnauthorized], loginFailMax)
	}
	if codes[http.StatusTooManyRequests] == 0 {
		t.Errorf("burst: no 429 responses among %d concurrent attempts — the throttle was bypassed by concurrency: %v", N, codes)
	}
	var sum int
	for _, c := range codes {
		sum += c
	}
	if sum != N {
		t.Errorf("burst: unexpected status mix: %v (want only 401/429, total %d)", codes, N)
	}

	// The IP must now be locked out: the next sequential attempt is a fast
	// 429, not a 401 (no bcrypt).
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"alice","password":"x"}`))
	req.RemoteAddr = "10.9.9.9:4444"
	rr := httptest.NewRecorder()
	srv.handleAuthLogin(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("post-burst sequential attempt from the burst IP: %d, want 429 (locked out)", rr.Code)
	}

	// A correct password from a DIFFERENT ip still logs in.
	req = httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"alice","password":"correct-horse-battery"}`))
	req.RemoteAddr = "10.8.8.8:5555"
	rr = httptest.NewRecorder()
	srv.handleAuthLogin(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("correct login from a fresh ip: %d, want 200", rr.Code)
	}

	// A correct login clears the counter for its OWN ip: loginFailMax-1
	// fails (under the limit), then a success, then a FULL fresh budget of
	// loginFailMax more fails — if the success had not cleared the counter,
	// the lockout would have arrived during the second batch.
	ip := "10.7.7.7:6666"
	for i := 0; i < loginFailMax-1; i++ {
		req = httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(fmt.Sprintf(`{"username":"alice","password":"bad-%d"}`, i)))
		req.RemoteAddr = ip
		rr = httptest.NewRecorder()
		srv.handleAuthLogin(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("pre-success fail %d: %d, want 401", i, rr.Code)
		}
	}
	req = httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"alice","password":"correct-horse-battery"}`))
	req.RemoteAddr = ip
	rr = httptest.NewRecorder()
	srv.handleAuthLogin(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("success after %d fails: %d, want 200", loginFailMax-1, rr.Code)
	}
	for i := 0; i < loginFailMax; i++ {
		req = httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(fmt.Sprintf(`{"username":"alice","password":"bad2-%d"}`, i)))
		req.RemoteAddr = ip
		rr = httptest.NewRecorder()
		srv.handleAuthLogin(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("post-success fail %d: %d, want 401 (a successful login must clear the counter; the lockout arrived early)", i, rr.Code)
			break
		}
	}
}

// --- M4: self-update rollback (the auth-off 403 was deferred, see docs/DEFERRED.md) ---------------------------

func fixWriteFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

// TestFix_M4_InstallKeepsPrev pins the M4(a) fix: installBinary must keep
// the previous binary at <exe>.prev (old bytes, mode preserved), and a
// second install must overwrite the stale .prev instead of failing.
func TestFix_M4_InstallKeepsPrev(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "pulsemon")
	oldBytes := []byte("OLD-BINARY")
	newBytes := []byte("NEW-BINARY")
	fixWriteFile(t, exe, oldBytes, 0o755)
	src1 := filepath.Join(dir, "new1")
	fixWriteFile(t, src1, newBytes, 0o755)

	if err := installBinary(src1, exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); !bytes.Equal(b, newBytes) {
		t.Errorf("exe after install = %q, want the new bytes", b)
	}
	prev := exe + ".prev"
	if b, err := os.ReadFile(prev); err != nil {
		t.Fatalf("no %s after install: %v", prev, err)
	} else if !bytes.Equal(b, oldBytes) {
		t.Errorf(".prev after install = %q, want the OLD bytes", b)
	}
	if st, err := os.Stat(prev); err == nil && st.Mode().Perm() != 0o755 {
		t.Errorf(".prev mode = %o, want 0755 (preserved from the original)", st.Mode().Perm())
	}

	// A second install overwrites the stale .prev with the first new bytes.
	src2 := filepath.Join(dir, "new2")
	newerBytes := []byte("NEWER-BINARY")
	fixWriteFile(t, src2, newerBytes, 0o755)
	if err := installBinary(src2, exe); err != nil {
		t.Fatalf("second install (stale .prev present): %v", err)
	}
	if b, _ := os.ReadFile(prev); !bytes.Equal(b, newBytes) {
		t.Errorf(".prev after second install = %q, want the first new bytes", b)
	}
}

// TestFix_M4_RollbackRestores pins the M4(b) helper: rollbackBinary swaps
// the .prev back over the exe (atomic rename) and consumes the .prev; with
// no .prev present it fails cleanly.
func TestFix_M4_RollbackRestores(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "pulsemon")
	oldBytes := []byte("OLD-BINARY")
	newBytes := []byte("NEW-BINARY")
	fixWriteFile(t, exe, oldBytes, 0o755)
	src := filepath.Join(dir, "new")
	fixWriteFile(t, src, newBytes, 0o755)

	if err := installBinary(src, exe); err != nil {
		t.Fatal(err)
	}
	if err := rollbackBinary(exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); !bytes.Equal(b, oldBytes) {
		t.Errorf("exe after rollback = %q, want the OLD bytes", b)
	}
	if _, err := os.Stat(exe + ".prev"); !os.IsNotExist(err) {
		t.Errorf(".prev should be gone after rollback (stat err = %v)", err)
	}
	if err := rollbackBinary(exe); err == nil {
		t.Error("rollback with no .prev must fail, got nil")
	}
}

// TestFix_PostAndCloneTagsAtomic pins the atomic create+tag fix: POST
// /api/sensors and POST /api/sensors/{id}/clone used to INSERT the sensor
// row (autocommit) and ONLY THEN replace the tags in a separate
// SetSensorTags transaction, logging and swallowing that error while still
// returning 201 with the requested tags in the body. A failed tag write
// left a sensor the API claimed was tagged but the DB had none — with
// alert_scope='tags' that silently changes which sensors alert once the
// user resumes the (paused) sensor. Both writes now commit in one
// ImmediateTx: a tag-write failure rolls back the row and the request
// fails, never a 201 with phantom tags. Fails on the pre-fix code (201 +
// a tagless row left behind).
func TestFix_PostAndCloneTagsAtomic(t *testing.T) {
	srv, db := fixServerWithDB(t)

	// Seed a source sensor carrying the poison tag BEFORE the trigger
	// exists (the trigger would block the seed insert too).
	srcID := newID()
	if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, 'src','127.0.0.1','icmp',60,1000,25,2,5,'paused','up',?)`, srcID, tsNow()); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSensorTags(srcID, []string{"bad"}); err != nil {
		t.Fatalf("seed source tags: %v", err)
	}

	// Force a tag-write failure: any insert of tag "bad" aborts (same
	// seam as TestSetSensorTagsAtomic).
	if _, err := db.Exec(`CREATE TRIGGER tagblock BEFORE INSERT ON sensor_tags
		FOR EACH ROW WHEN NEW.tag = 'bad'
		BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	defer db.Exec(`DROP TRIGGER IF EXISTS tagblock`)

	// POST with a failing tag write: not a 201 claiming the tags were
	// saved, and no sensor row may be left behind.
	req := httptest.NewRequest("POST", "/api/sensors", strings.NewReader(`{"name":"tagged","target":"127.0.0.1","type":"icmp","tags":["bad"]}`))
	rr := httptest.NewRecorder()
	srv.handleSensors(rr, req)
	if rr.Code == http.StatusCreated {
		t.Errorf("POST with failing tag write: %d — the API claimed the tags were saved; want a non-201 (the write must roll back)", rr.Code)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors WHERE name = 'tagged'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("sensor row persisted after a failed tag write: %d rows, want 0 (INSERT and tags must commit together)", n)
	}

	// Clone with a failing tag write: the same contract.
	req = httptest.NewRequest("POST", "/api/sensors/"+srcID+"/clone", nil)
	req.SetPathValue("id", srcID)
	rr = httptest.NewRecorder()
	srv.handleSensorClone(rr, req)
	if rr.Code == http.StatusCreated {
		t.Errorf("clone with failing tag write: %d — the API claimed the tags were saved; want a non-201", rr.Code)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors WHERE name = 'src-copy'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("clone row persisted after a failed tag write: %d rows, want 0 (INSERT and tags must commit together)", n)
	}

	// The trigger must not leak: a valid create with tags still works and
	// persists them (guards against an over-zealous rollback).
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS tagblock`); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("POST", "/api/sensors", strings.NewReader(`{"name":"oktag","target":"127.0.0.1","type":"icmp","tags":["good"]}`))
	rr = httptest.NewRecorder()
	srv.handleSensors(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST with valid tag: %d, want 201: %s", rr.Code, rr.Body.String())
	}
	var okID string
	if err := db.QueryRow("SELECT id FROM sensors WHERE name = 'oktag'").Scan(&okID); err != nil {
		t.Fatal(err)
	}
	if tags := db.SensorTags(okID); len(tags) != 1 || tags[0] != "good" {
		t.Errorf("tags after valid POST = %v, want [good]", tags)
	}
}

// TestFix_SettingsAlertFilterBounded pins the alert_filter input gate in
// PUT /api/settings: the field used to be marshaled into the settings
// table with no validation of count, length, or charset — a near-1 MiB
// body could store thousands of unbounded strings that GET /api/settings
// and every shouldAlert decision unmarshal on each read. Entries are now
// trimmed, deduped, and must pass validSensorName (tag names and sensor
// ids both do), capped at 500 entries. An invalid or oversized list 400s
// the whole save and leaves the store untouched — including the other
// fields in the same request (the validate-everything-first contract).
// Fails pre-fix (200 + the garbage stored).
func TestFix_SettingsAlertFilterBounded(t *testing.T) {
	srv, db := fixServerWithDB(t)

	// Baseline values so "untouched after a 400" is checkable.
	_ = db.SetSetting("realert_min", "30")

	// Oversized list (501 entries): 400, and the other field in the same
	// request must NOT be written.
	big := make([]string, 501)
	for i := range big {
		big[i] = fmt.Sprintf("tag%d", i)
	}
	body, _ := json.Marshal(map[string]any{"alert_filter": big, "realert_min": 11})
	req := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT 501-entry alert_filter: %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if got := db.GetSetting("realert_min"); got != "30" {
		t.Errorf("realert_min = %q after a 400 PUT, want 30 (a rejected save must not write other fields)", got)
	}
	if v := db.GetSetting("alert_filter"); v != "" {
		t.Errorf("alert_filter = %q after a 400 PUT, want empty (nothing written)", v)
	}

	// Invalid entry — a quote, exactly the string-escape character the
	// tag/name gate blocks: 400, other fields untouched.
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"alert_filter":["ok","x'"],"realert_min":12}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT alert_filter with quote entry: %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if got := db.GetSetting("realert_min"); got != "30" {
		t.Errorf("realert_min = %q after a 400 PUT, want 30 (a rejected save must not write other fields)", got)
	}

	// Overlong entry (61 runes): 400.
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"alert_filter":["`+strings.Repeat("a", 61)+`"]}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT 61-rune entry: %d, want 400: %s", rr.Code, rr.Body.String())
	}

	// Valid list with dups and surrounding whitespace: 200, stored
	// trimmed + deduped (first-seen order).
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{"alert_filter":[" prod ", "prod", "core"]}`))
	rr = httptest.NewRecorder()
	srv.handleSettingsPut(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT valid alert_filter: %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var got []string
	if err := json.Unmarshal([]byte(db.GetSetting("alert_filter")), &got); err != nil {
		t.Fatalf("decode stored alert_filter: %v", err)
	}
	if len(got) != 2 || got[0] != "prod" || got[1] != "core" {
		t.Errorf("stored alert_filter = %v, want [prod core] (trimmed + deduped)", got)
	}
}

// TestFix_SessionCookieSlides pins the sliding-cookie fix: the session
// cookie was issued once at login with a fixed Max-Age=30d, and
// ValidSession slid only the IN-MEMORY expiry — so the browser deleted
// the cookie exactly 30 days after login even for a daily user, defeating
// the sliding-session design (server expiry = last-use+30d is always >=
// cookie expiry = login+30d, so the cookie always died first). The gate
// now re-issues the SAME token once the cookie ages past half the TTL
// (CookieRenewalDue), and SessionUser (the gate-exempt /api/auth/status
// path) slides like ValidSession. Fails pre-fix (no Set-Cookie on an
// aged session; SessionUser leaves the backdated expiry alone).
func TestFix_SessionCookieSlides(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	if err := srv.auth.AddUser("admin", "secretpw"); err != nil {
		t.Fatal(err)
	}

	// Login: cookie issued, cookieIssued = now.
	resp, err := client.Post(httpSrv.URL+"/api/auth/login", "application/json", strings.NewReader(`{"username":"admin","password":"secretpw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", resp.StatusCode)
	}

	// A fresh (young) session must NOT re-issue: no Set-Cookie on a
	// normal authenticated request (no per-poll header churn).
	resp, err = client.Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sensors: %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == authSessionName {
			t.Fatalf("young session re-issued a cookie on a plain request: %v (at most one per half-TTL of activity)", c)
		}
	}

	// Age the cookie past half the TTL (16d) — as a daily user's cookie
	// would be on day 16. The next authenticated request must re-issue
	// the SAME token with a fresh 30-day Max-Age.
	su, _ := url.Parse(httpSrv.URL)
	var tok string
	for _, c := range jar.Cookies(su) {
		if c.Name == authSessionName {
			tok = c.Value
		}
	}
	if tok == "" {
		t.Fatal("no session cookie in jar")
	}
	srv.auth.mu.Lock()
	s := srv.auth.sessions[tok]
	s.cookieIssued = time.Now().Add(-16 * 24 * time.Hour)
	srv.auth.sessions[tok] = s
	srv.auth.mu.Unlock()

	resp, err = client.Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sensors after aged cookie: %d", resp.StatusCode)
	}
	var reissued *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == authSessionName {
			reissued = c
		}
	}
	if reissued == nil {
		t.Fatal("aged session (cookie 16d old): no Set-Cookie re-issue — the browser would delete the cookie at day 30 and log the active user out (the sliding design is defeated)")
	}
	if reissued.Value != tok {
		t.Errorf("re-issued cookie value = %q, want the SAME token %q (refresh, not rotate)", reissued.Value, tok)
	}
	if reissued.MaxAge != int(authSessionTTL.Seconds()) {
		t.Errorf("re-issued cookie MaxAge = %d, want %d (full TTL from now)", reissued.MaxAge, int(authSessionTTL.Seconds()))
	}

	// A second request right after: no immediate re-issue (the stamp
	// was refreshed by the re-issue).
	resp, err = client.Get(httpSrv.URL + "/api/sensors")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == authSessionName {
			t.Fatalf("cookie re-issued again immediately (the stamp must reset after a re-issue): %v", c)
		}
	}

	// SessionUser (the gate-exempt /api/auth/status path) must slide like
	// ValidSession: backdate the expiry an hour, call SessionUser, and the
	// expiry must be back at now+TTL.
	srv.auth.mu.Lock()
	s = srv.auth.sessions[tok]
	s.expiry = time.Now().Add(authSessionTTL - time.Hour)
	srv.auth.sessions[tok] = s
	srv.auth.mu.Unlock()
	if _, ok := srv.auth.SessionUser(tok); !ok {
		t.Fatal("SessionUser rejected a live session")
	}
	srv.auth.mu.Lock()
	after := srv.auth.sessions[tok].expiry
	srv.auth.mu.Unlock()
	want := time.Now().Add(authSessionTTL)
	if after.Before(want.Add(-2*time.Second)) || after.After(want.Add(2*time.Second)) {
		t.Errorf("SessionUser did not slide expiry to now+TTL: got %v, want ~ %v", after, want)
	}
}

// TestFix_FirstUserConcurrentSingleAdmin pins the single first-admin
// invariant on the production path: N concurrent bootstrap POSTs (the
// fresh-install surface is open to the whole LAN) must yield exactly ONE
// account — the winner's AddUserMode runs COUNT + INSERT +
// auth_bootstrapped in one BEGIN IMMEDIATE transaction, the losers see
// user_count > 0 inside the transaction and get 409. The DB-level
// (*DB).AddUser helper used to duplicate this invariant as a non-atomic
// autocommit COUNT-then-INSERT: a concurrent pair on an empty table could
// both read n==0 and mint two "first" admins, and it never set
// auth_bootstrapped. It had no production callers (API and CLI both go
// through AuthState.AddUserMode), so it was removed (2026-10-22 external
// review) — this test pins the atomic path that now owns the invariant.
func TestFix_FirstUserConcurrentSingleAdmin(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, NewProbeWorker(db))
	httpSrv := httptest.NewServer(srv.authGate())
	defer httpSrv.Close()

	const N = 8
	var wg sync.WaitGroup
	codes := make([]int, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"username":"user%d","password":"secretpw%d"}`, i, i)
			resp, err := httpSrv.Client().Post(httpSrv.URL+"/api/auth/users", "application/json", strings.NewReader(body))
			if err != nil {
				t.Errorf("bootstrap POST %d: %v", i, err)
				return
			}
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	var ok, conflict int
	for i, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
		default:
			t.Errorf("bootstrap POST %d: status %d, want 200 or 409", i, c)
		}
	}
	if ok != 1 {
		t.Errorf("concurrent bootstraps: %d x 200 (%d x 409), want exactly 1 x 200 (the first-admin invariant): codes=%v", ok, conflict, codes)
	}
	if n, err := db.UserCount(); err != nil || n != 1 {
		t.Fatalf("user count = %d (err %v), want 1 (one and only one first account)", n, err)
	}
	var isAdmin int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = 1").Scan(&isAdmin); err != nil {
		t.Fatal(err)
	}
	if isAdmin != 1 {
		t.Errorf("admin count = %d, want 1 (the single first account is the admin)", isAdmin)
	}
	if db.GetSetting("auth_bootstrapped") != "1" {
		t.Error("auth_bootstrapped not set with the first account (must commit atomically with it)")
	}
}

// TestFix_CloneNamePickedInOneQuery pins the clone name-pick optimization:
// the existing clone names are fetched in ONE GLOB query and the first free
// suffix is picked in memory (the old loop ran up to 100 sequential SELECT
// COUNT(*) round-trips before the first INSERT — 2026-10-22 external
// review). The observable behavior must be unchanged — -copy, then
// -copy2..-copy100, 409 past the cap — and the test adds the edge the old
// exact-match loop never had: a base name containing GLOB metacharacters
// (validSensorName is a blacklist, so * ? [ are legal names). A "[" in the
// base turns the pattern's "[b]" into a character class, so the taken name
// "a[b]-copy" does NOT match "a[b]-copy*" — the in-memory scan picks it,
// the INSERT must hit the sensors.name UNIQUE index, and the retry must
// land on a[b]-copy2 (no 500, no duplicate). The UNIQUE index remains the
// arbiter in every case.
func TestFix_CloneNamePickedInOneQuery(t *testing.T) {
	srv, db := fixServerWithDB(t)
	mk := func(name string) string {
		id := newID()
		if _, err := db.Exec(`INSERT INTO sensors (id,name,target,type,interval_s,timeout_ms,loss_warn,down_after,spike_mult,state,status,created_at) VALUES (?, ?,'10.0.0.1','icmp',60,1000,25,2,5,'paused','up',?)`, id, name, tsNow()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	clone := func(srcID string) (int, string) {
		req := httptest.NewRequest("POST", "/api/sensors/"+srcID+"/clone", nil)
		req.SetPathValue("id", srcID)
		rr := httptest.NewRecorder()
		srv.handleSensorClone(rr, req)
		if rr.Code != http.StatusCreated {
			return rr.Code, ""
		}
		var body Sensor
		if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return rr.Code, body.Name
	}

	// 0 existing clones -> base-copy.
	id0 := mk("fresh")
	if code, name := clone(id0); code != http.StatusCreated || name != "fresh-copy" {
		t.Errorf("clone with no existing clones: %d %q, want 201 fresh-copy", code, name)
	}

	// 99 existing clones (fresh-copy..fresh-copy99) -> fresh-copy100: the
	// deep-scan case that used to be 100 sequential COUNT(*) queries.
	for i := 2; i <= 99; i++ { // fresh-copy (i==1) exists from the clone above
		mk(fmt.Sprintf("fresh-copy%d", i))
	}
	if code, name := clone(id0); code != http.StatusCreated || name != "fresh-copy100" {
		t.Errorf("clone with 99 existing clones: %d %q, want 201 fresh-copy100", code, name)
	}

	// Cap: fresh-copy..fresh-copy100 are all taken now -> 409 (never 500).
	if code, _ := clone(id0); code != http.StatusConflict {
		t.Errorf("clone with all 100 candidate names taken: %d, want 409", code)
	}

	// GLOB metacharacter edge (see the test comment): the under-matched
	// taken name is rejected by the UNIQUE index and the retry moves on.
	idMeta := mk("a[b]")
	mk("a[b]-copy")
	if code, name := clone(idMeta); code != http.StatusCreated || name != "a[b]-copy2" {
		t.Errorf("clone of a GLOB-metacharacter base: %d %q, want 201 a[b]-copy2 (UNIQUE index is the arbiter)", code, name)
	}
}
