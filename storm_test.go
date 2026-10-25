package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// sameCert reports whether two loaded certs carry identical leaf DER.
func sameCert(a, b *tls.Certificate) bool { return bytes.Equal(a.Leaf.Raw, b.Leaf.Raw) }

// withStormBudget runs fn with the storm budget shrunk to (budget, window),
// restoring the originals afterwards.
func withStormBudget(t *testing.T, budget int, window time.Duration, fn func()) {
	t.Helper()
	oldBudget, oldWindow := stormBudget, stormWindow
	stormBudget, stormWindow = budget, window
	defer func() { stormBudget, stormWindow = oldBudget, oldWindow }()
	fn()
}

// newStormTestWorker builds a worker with a google_chat provider pointing at
// a capture server; bodies (the "text" field) are returned via the closure.
func newStormTestWorker(t *testing.T) (*ProbeWorker, *DB, func() []string, func()) {
	t.Helper()
	db := newTestDB(t)
	pw := NewProbeWorker(db)
	var (
		mu     sync.Mutex
		bodies []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		bodies = append(bodies, b["text"])
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	_ = db.SetSetting("google_chat_url", srv.URL)
	get := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(bodies))
		copy(out, bodies)
		return out
	}
	cleanup := func() {
		pw.StopAlerts()
		srv.Close()
	}
	return pw, db, get, cleanup
}

func insertStormSensor(t *testing.T, db *DB, id string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO sensors (id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state, status, created_at)
		VALUES (?, ?, '127.0.0.1', 15, 1000, 25, 2, 5, 'active', 'up', ?)`, id, id, now); err != nil {
		t.Fatalf("insert sensor %s: %v", id, err)
	}
}

// TestStormCoalescing: 5 simultaneous error alerts with a budget of 3 must
// produce exactly 3 individual alerts + ONE coalesced summary carrying the
// 2 suppressed sensors — 4 deliveries total, not 5 (2026-10-19 review M8).
func TestStormCoalescing(t *testing.T) {
	withStormBudget(t, 3, 200*time.Millisecond, func() {
		withPlainTransport(t, func() { // loopback httptest vs the SSRF blocklist
			pw, db, getBodies, cleanup := newStormTestWorker(t)
			defer cleanup()
			for i := 0; i < 5; i++ {
				insertStormSensor(t, db, fmt.Sprintf("s%d", i))
			}
			for i := 0; i < 5; i++ {
				i := i
				pw.launchAlert(func() {
					pw.sendAlert(fmt.Sprintf("s%d", i), fmt.Sprintf("s%d", i), "127.0.0.1", "up", "error", 0)
				})
			}
			// Mirror the engine: the probe loop writes the new status to the DB
			// BEFORE launching the alert (probe.go: DB UPDATE → launchAlert).
			// The storm flush filters its queue on that column.
			for i := 0; i < 5; i++ {
				if _, err := db.Exec(`UPDATE sensors SET status = 'error' WHERE id = ?`, fmt.Sprintf("s%d", i)); err != nil {
					t.Fatalf("set s%d error: %v", i, err)
				}
			}
			// Wait for the coalesced summary: the flush fires at window end,
			// AFTER the individual deliveries have drained alertWG, so
			// DrainAlerts alone returns before it (and racing it is what the
			// race detector flags). Poll for 3 individual + 1 summary.
			var bodies []string
			deadline := time.Now().Add(2 * time.Second)
			for {
				bodies = getBodies()
				if len(bodies) >= 4 || time.Now().After(deadline) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			var individual, summaries int
			var summaryBody string
			for _, b := range bodies {
				if strings.Contains(b, "alert storm") {
					summaries++
					summaryBody = b
				} else {
					individual++
				}
			}
			if individual != 3 {
				t.Errorf("individual alerts = %d, want 3 (budget)", individual)
			}
			if summaries != 1 {
				t.Fatalf("storm summaries = %d, want exactly 1", summaries)
			}
			if !strings.Contains(summaryBody, "2 sensors changed state") {
				t.Errorf("summary should name 2 suppressed sensors, got:\n%s", summaryBody)
			}
			// Every sensor appears exactly once across individual + summary.
			for i := 0; i < 5; i++ {
				id := fmt.Sprintf("s%d", i)
				n := 0
				for _, b := range bodies {
					if strings.Contains(b, "*Sensor*: "+id) || strings.Contains(b, id+": up → error") {
						n++
					}
				}
				if n != 1 {
					t.Errorf("sensor %s appears %d times, want exactly 1", id, n)
				}
			}
		})
	})
}

// TestStormRecoveryAlwaysAdmitted: recoveries bypass the budget entirely —
// even at budget 0 the operator hears every recovery individually.
func TestStormRecoveryAlwaysAdmitted(t *testing.T) {
	withStormBudget(t, 0, time.Hour, func() {
		withPlainTransport(t, func() { // loopback httptest vs the SSRF blocklist
			pw, db, getBodies, cleanup := newStormTestWorker(t)
			defer cleanup()
			insertStormSensor(t, db, "r0")
			insertStormSensor(t, db, "r1")
			pw.launchAlert(func() { pw.sendAlert("r0", "r0", "127.0.0.1", "error", "up", 0) })
			pw.launchAlert(func() { pw.sendAlert("r1", "r1", "127.0.0.1", "error", "up", 0) })
			pw.DrainAlerts(5 * time.Second)
			bodies := getBodies()
			if len(bodies) != 2 {
				t.Fatalf("recoveries at budget 0: deliveries = %d, want 2 (individual)", len(bodies))
			}
			for _, b := range bodies {
				if strings.Contains(b, "alert storm") {
					t.Error("recovery must never be coalesced into a storm summary")
				}
			}
		})
	})
}

// TestStormFlushDropsRecovered: a suppressed sensor that recovers before the
// flush must not appear in the summary (it would contradict the recovery
// alert it raced).
func TestStormFlushDropsRecovered(t *testing.T) {
	withStormBudget(t, 0, 500*time.Millisecond, func() {
		withPlainTransport(t, func() { // loopback httptest vs the SSRF blocklist
			pw, db, getBodies, cleanup := newStormTestWorker(t)
			defer cleanup()
			insertStormSensor(t, db, "a0")
			insertStormSensor(t, db, "a1")
			pw.launchAlert(func() { pw.sendAlert("a0", "a0", "127.0.0.1", "up", "error", 0) })
			pw.launchAlert(func() { pw.sendAlert("a1", "a1", "127.0.0.1", "up", "error", 0) })
			// Mirror the engine's DB write (see TestStormCoalescing).
			if _, err := db.Exec(`UPDATE sensors SET status = 'error' WHERE id IN ('a0','a1')`); err != nil {
				t.Fatalf("set a0/a1 error: %v", err)
			}

			// Wait until BOTH are in the suppressed queue. Budget is 0, not 1:
			// with a budget of 1 the FIRST alert is admitted individually and
			// only the second is queued, so WHICH one ends up queued is a coin
			// flip between the two concurrent launchAlert goroutines — and the
			// assertions below (summary has a0, not a1) only hold when a0 is
			// the queued one. When the race went the other way (a0 admitted,
			// a1 queued), a1 recovered → dropped → empty queue → no summary
			// ("summaries = 0, want 1"): the flake. Budget 0 queues BOTH
			// deterministically (no admission), so the recovered-sensor drop is
			// tested against a guaranteed non-empty summary.
			deadline := time.Now().Add(3 * time.Second)
			for {
				pw.stormMu.Lock()
				n := len(pw.stormQueue)
				pw.stormMu.Unlock()
				if n >= 2 || time.Now().After(deadline) {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			// a1 recovers before the window elapses.
			if _, err := db.Exec(`UPDATE sensors SET status = 'up' WHERE id = 'a1'`); err != nil {
				t.Fatalf("mark a1 up: %v", err)
			}
			// Poll for the summary (same reason as TestStormCoalescing: the
			// flush lands after alertWG has drained).
			var bodies []string
			deadline = time.Now().Add(2 * time.Second)
			for {
				bodies = getBodies()
				hasSummary := false
				for _, b := range bodies {
					if strings.Contains(b, "alert storm") {
						hasSummary = true
					}
				}
				if hasSummary || time.Now().After(deadline) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			var summaries []string
			for _, b := range bodies {
				if strings.Contains(b, "alert storm") {
					summaries = append(summaries, b)
				}
			}
			if len(summaries) != 1 {
				t.Fatalf("summaries = %d, want 1", len(summaries))
			}
			s := summaries[0]
			if !strings.Contains(s, "a0: up → error") {
				t.Errorf("summary missing the still-down sensor a0:\n%s", s)
			}
			if strings.Contains(s, "a1:") {
				t.Errorf("summary includes recovered sensor a1:\n%s", s)
			}
		})
	})
}

// --- m10: TLS cert hot reload ---

// writeTestCertPEM writes a fresh self-signed ECDSA pair to (certPath,
// keyPath). Each call produces a distinct key/cert.
func writeTestCertPEM(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "pulsemon-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

// TestHotReloadCert pins the m10 behavior: the served pair follows the files
// (a renewal takes effect at the next handshake, no restart), and a broken
// reload keeps the last good pair instead of failing handshakes.
func TestHotReloadCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeTestCertPEM(t, certPath, keyPath)

	get := hotReloadCert(certPath, keyPath)
	c1, err := get(nil)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	// Renew: new pair, explicitly bumped mtime (no reliance on FS
	// timestamp granularity).
	writeTestCertPEM(t, certPath, keyPath)
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(certPath, time.Time{}, future); err != nil {
		t.Fatalf("chtime: %v", err)
	}
	c2, err := get(nil)
	if err != nil {
		t.Fatalf("reload after renewal: %v", err)
	}
	if sameCert(c1, c2) {
		t.Fatal("renewal did not take effect — the old pair is still served")
	}

	// Second call with unchanged files: same pair, no reload churn.
	c2b, err := get(nil)
	if err != nil {
		t.Fatalf("cached call: %v", err)
	}
	if !sameCert(c2, c2b) {
		t.Fatal("unchanged files must serve the cached pair")
	}

	// Corrupt the cert: the reload fails, but the LAST GOOD pair is kept
	// (handshakes keep working until the file is repaired).
	if err := os.WriteFile(certPath, []byte("garbage"), 0o600); err != nil {
		t.Fatalf("corrupt cert: %v", err)
	}
	if err := os.Chtimes(certPath, time.Time{}, time.Now().Add(2*time.Second)); err != nil {
		t.Fatalf("chtime: %v", err)
	}
	c3, err := get(nil)
	if err != nil {
		t.Fatalf("corrupt reload must keep the last good pair, got error: %v", err)
	}
	if !sameCert(c3, c2) {
		t.Fatal("corrupt reload changed the served pair")
	}

	// Repair: the next handshake picks up the good pair again.
	writeTestCertPEM(t, certPath, keyPath)
	if err := os.Chtimes(certPath, time.Time{}, time.Now().Add(3*time.Second)); err != nil {
		t.Fatalf("chtime: %v", err)
	}
	c4, err := get(nil)
	if err != nil {
		t.Fatalf("reload after repair: %v", err)
	}
	if sameCert(c4, c2) {
		t.Fatal("repair did not take effect — the old pair is still served")
	}
}

// TestStormSummaryMarkdownEscapesAsterisks (2026-10-24 review n2):
// stormSummaryMarkdown wraps each line in *…*, and cardFor uses
// *Sensor*-style emphasis. * is legal in sensor names (validSensorName
// only blocks quotes/angles/backticks/controls) and in URL paths, so a
// raw * in the data renders as a literal asterisk in Google Chat /
// Discord. The data must be backslash-escaped; the emphasis markers
// (format string, not data) stay intact.
func TestStormSummaryMarkdownEscapesAsterisks(t *testing.T) {
	entries := []stormEntry{
		{id: "a", name: "nas*01", target: "https://nas.lan/x*y", oldState: "up", state: "error"},
	}
	md := stormSummaryMarkdown(entries)
	want := "*nas\\*01: up → error (https://nas.lan/x\\*y)*"
	if !strings.Contains(md, want) {
		t.Fatalf("markdown line not escaped:\n%s\nwant line %q", md, want)
	}
	if !strings.Contains(md, "*pulsemon: alert storm — 1 sensors changed state (coalesced to limit alert noise)*") {
		t.Fatalf("header emphasis lost: %q", md)
	}
}

// TestStormSummaryMentionNeutralizationScopedToMarkdown (2026-10-24 review):
// discordMentionSafe injects an invisible \u200b into @everyone/@here to
// defuse Discord mass-mentions. That neutralization belongs ONLY to the
// Discord/Google Chat Markdown path — the Telegram (HTML) and SMTP (plain)
// summaries must carry the sensor name verbatim, or the invisible char
// corrupts email copy-paste and renders as tofu in non-UTF-8 readers.
func TestStormSummaryMentionNeutralizationScopedToMarkdown(t *testing.T) {
	entries := []stormEntry{
		{id: "a", name: "@everyone", target: "10.0.0.1", oldState: "up", state: "error"},
	}
	const zwsp = "\u200b"
	// Markdown (Discord/Google Chat): the mention IS neutralized.
	if md := stormSummaryMarkdown(entries); !strings.Contains(md, zwsp) {
		t.Errorf("markdown summary must neutralize the mention (want %q present): %q", zwsp, md)
	}
	// Plain (SMTP) and HTML (Telegram): the mention is NOT neutralized.
	if p := stormSummaryPlain(entries); strings.Contains(p, zwsp) {
		t.Errorf("SMTP plain summary must not carry the zero-width space: %q", p)
	}
	if h := stormSummaryHTML(entries); strings.Contains(h, zwsp) {
		t.Errorf("Telegram HTML summary must not carry the zero-width space: %q", h)
	}
	// The plain summary carries the sensor name verbatim.
	if p := stormSummaryPlain(entries); !strings.Contains(p, "@everyone") {
		t.Errorf("SMTP plain summary must carry the sensor name verbatim: %q", p)
	}
}
