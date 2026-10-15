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
	"net/http/httptest"
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
