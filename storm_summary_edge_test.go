package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"pulsemon/internal/store"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// Tests for the 2026-11-25 external review MAJOR-7 storm-summary edge
// cases: (1) truncateSummaryLines must reserve footer space so the capped
// body never exceeds the provider's content limit (Discord 400s the whole
// message otherwise — a non-retryable drop of the only outage alert),
// (2) re-alerts must not ride the new-transition storm budget (they are
// the operator's re-alert cadence, and coalescing them renders bogus
// "svc: error -> error" lines in a "sensors changed state" summary),
// (3) a storm summary that fails on ALL providers must be re-offered
// through the normal alert path, not logged and discarded (on a
// realert_min == 0 install the coalesced sensors #11..#N never alert
// otherwise).

// TestTruncateSummaryLinesReservesFooter (MAJOR-7.1): the cap check must
// leave room for the "\n… and N more" footer it is about to append. The
// input below was measured against the pre-fix algorithm (kept inline as
// oldTruncateSummaryLines): it lands the pre-fix body at 2,002 runes for
// discordContentMax = 2,000 — a non-retryable HTTP 400 that drops the
// whole storm summary — and the fixed output at 1,961.
func TestTruncateSummaryLinesReservesFooter(t *testing.T) {
	const maxRunes = 2000 // discordContentMax
	header := strings.Repeat("H", 100)
	lines := make([]string, 50)
	for i := range lines {
		lines[i] = strings.Repeat("L", 41)
	}

	// The pre-fix algorithm on this input MUST overflow the cap —
	// otherwise the pin no longer reproduces the defect shape.
	if old := oldTruncateSummaryLines(header, lines, maxRunes); utf8.RuneCountInString(old) <= maxRunes {
		t.Fatalf("test input no longer overflows the pre-fix cap (got %d runes): the pin has no teeth", utf8.RuneCountInString(old))
	}

	out := truncateSummaryLines(header, lines, maxRunes)
	if n := utf8.RuneCountInString(out); n > maxRunes {
		t.Fatalf("capped summary = %d runes > %d: the provider 400s the whole message", n, maxRunes)
	}
	if !strings.HasPrefix(out, header) {
		t.Errorf("capped summary must keep the header verbatim:\n%q", out)
	}
	if !strings.Contains(out, "\n… and 6 more") {
		t.Errorf("capped summary must end with the overflow footer:\n%q", out)
	}

	// Everything fits: no footer, exact body.
	small := truncateSummaryLines("head", []string{"a: up → error (127.0.0.1)", "b: up → error (127.0.0.1)"}, maxRunes)
	if small != "head\na: up → error (127.0.0.1)\nb: up → error (127.0.0.1)" {
		t.Errorf("no-overflow body mangled:\n%q", small)
	}
	// 0 = uncapped (SMTP): every line, no footer.
	uncapped := truncateSummaryLines(header, lines, 0)
	if n := utf8.RuneCountInString(uncapped); n != utf8.RuneCountInString(header)+50*(1+41) {
		t.Errorf("uncapped body = %d runes, want header + all 50 lines", n)
	}
	if strings.Contains(uncapped, "… and") {
		t.Errorf("uncapped body must carry no footer:\n%q", uncapped)
	}
}

// oldTruncateSummaryLines is the pre-MAJOR-7 algorithm, kept so the pin
// above proves the overflow shape is reachable (sabotage: reverting
// truncateSummaryLines to this shape makes the test red).
func oldTruncateSummaryLines(header string, lines []string, maxRunes int) string {
	var b strings.Builder
	b.WriteString(header)
	runes := utf8.RuneCountInString(header)
	shown := 0
	for _, line := range lines {
		lineRunes := utf8.RuneCountInString(line)
		if maxRunes > 0 && runes+1+lineRunes > maxRunes {
			fmt.Fprintf(&b, "\n… and %d more", len(lines)-shown)
			break
		}
		b.WriteString("\n")
		b.WriteString(line)
		runes += 1 + lineRunes
		shown++
	}
	return b.String()
}

// TestRealertBypassesStormBudget (MAJOR-7.2): a sustained-error re-alert
// (oldState == state) must deliver individually even when the
// new-transition storm budget is exhausted (0) — and must NOT consume the
// budget or land in the storm queue. Pre-fix it rode stormAdmit like a
// transition: it burned budget meant for new transitions and, when
// coalesced, rendered a bogus "s1: error → error" line in a "sensors
// changed state" summary.
func TestRealertBypassesStormBudget(t *testing.T) {
	withStormBudget(t, 0, 500*time.Millisecond, func() {
		withPlainTransport(t, func() { // loopback httptest vs the SSRF blocklist
			pw, db, getBodies, cleanup := newStormTestWorker(t)
			defer cleanup()
			insertStormSensor(t, db, "s1")
			// Mirror the engine: the probe loop stamps the new status in
			// the DB before the alert fires — the flush filter reads it.
			if _, err := db.Exec(`UPDATE sensors SET status = 'error' WHERE id = 's1'`); err != nil {
				t.Fatalf("set s1 error: %v", err)
			}
			// Budget 0: a transition would coalesce. The re-alert must
			// still deliver individually (the re-alert cadence is the
			// operator's, not a transition burst).
			pw.launchAlert(func() { pw.sendRealert("s1", "s1", "127.0.0.1", "error", 0) })
			var bodies []string
			deadline := time.Now().Add(2 * time.Second)
			for {
				bodies = getBodies()
				if len(bodies) >= 1 || time.Now().After(deadline) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if len(bodies) != 1 {
				t.Fatalf("re-alert deliveries at storm budget 0 = %d, want 1 (individual, not coalesced)", len(bodies))
			}
			if !strings.Contains(bodies[0], "still error") {
				t.Fatalf("re-alert must carry the re-alert card, got:\n%s", bodies[0])
			}
			// The re-alert consumed no budget and queued nothing.
			pw.stormMu.Lock()
			count, qlen := pw.stormCount, len(pw.stormQueue)
			pw.stormMu.Unlock()
			if count != 0 || qlen != 0 {
				t.Errorf("re-alert consumed storm budget: count=%d queue=%d, want 0/0", count, qlen)
			}
			// Contrast: a real transition at budget 0 coalesces into the
			// storm summary (the budget is intact for it).
			pw.launchAlert(func() { pw.sendAlert("s1", "s1", "127.0.0.1", "up", "error", 0) })
			deadline = time.Now().Add(2 * time.Second)
			for {
				bodies = getBodies()
				if len(bodies) >= 2 || time.Now().After(deadline) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if len(bodies) != 2 {
				t.Fatalf("deliveries after the transition = %d, want 2 (re-alert + coalesced summary)", len(bodies))
			}
			if !strings.Contains(bodies[1], "alert storm") || !strings.Contains(bodies[1], "s1: up → error") {
				t.Errorf("the transition must coalesce into the storm summary, got:\n%s", bodies[1])
			}
		})
	})
}

// newFailingStormWorker is newStormTestWorker with a server that 500s
// while failMode is set — the brief-WAN-outage shape (the provider is
// DOWN, not misconfigured). reqCount counts every request (successes and
// failures) so a test can observe the failed attempts before restoring
// the egress.
func newFailingStormWorker(t *testing.T) (*ProbeWorker, *store.Store, func() []string, *atomic.Bool, *atomic.Int64, func()) {
	t.Helper()
	db := newTestDB(t)
	pw := NewProbeWorker(db)
	var (
		mu     sync.Mutex
		bodies []string
	)
	failMode := &atomic.Bool{}
	reqCount := &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		if failMode.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		bodies = append(bodies, b["text"])
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	_ = db.SetSetting("google_chat_url", srv.URL)
	// The provider is set AFTER NewProbeWorker, so reload the snapshot —
	// the same swap the production PUT /api/settings path does.
	pw.reloadAlertSettings()
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
	return pw, db, get, failMode, reqCount, cleanup
}

// TestStormSummaryAllProvidersFailReOffers (MAJOR-7.3): when the storm
// summary's post fails on EVERY provider (a brief WAN outage takes out
// the targets and the egress together), the batch must be re-offered
// through the normal alert path — not logged and discarded. On a
// realert_min == 0 install there is no re-alert tick to resurrect it, so
// pre-fix the coalesced sensors (#11..#N) never alerted.
func TestStormSummaryAllProvidersFailReOffers(t *testing.T) {
	withStormBudget(t, 0, 500*time.Millisecond, func() {
		withPlainTransport(t, func() {
			oldDelays := alertRetryDelays
			alertRetryDelays = []time.Duration{5 * time.Millisecond, 5 * time.Millisecond}
			defer func() { alertRetryDelays = oldDelays }()
			withRecoveryRetryDelay(t, 60*time.Millisecond, func() {
				pw, db, getBodies, failMode, reqCount, cleanup := newFailingStormWorker(t)
				defer cleanup()
				insertStormSensor(t, db, "s0")
				insertStormSensor(t, db, "s1")
				if _, err := db.Exec(`UPDATE sensors SET status = 'error' WHERE id IN ('s0','s1')`); err != nil {
					t.Fatalf("set s0/s1 error: %v", err)
				}
				failMode.Store(true) // the outage: every provider 500s
				pw.launchAlert(func() { pw.sendAlert("s0", "s0", "127.0.0.1", "up", "error", 0) })
				pw.launchAlert(func() { pw.sendAlert("s1", "s1", "127.0.0.1", "up", "error", 0) })
				// Wait for the FAILED summary attempts (3 in-band 500s)
				// before restoring the egress — the all-failure branch
				// must have run before the retry can fire.
				deadline := time.Now().Add(3 * time.Second)
				for reqCount.Load() < 3 && !time.Now().After(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				if reqCount.Load() < 3 {
					t.Fatalf("summary attempts = %d, want 3 (the coalesced summary was never posted)", reqCount.Load())
				}
				failMode.Store(false) // the egress comes back
				var bodies []string
				deadline = time.Now().Add(4 * time.Second)
				for {
					bodies = getBodies()
					if len(bodies) >= 1 || time.Now().After(deadline) {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if len(bodies) == 0 {
					t.Fatal("no delivery after the providers recovered: the failed storm batch was discarded, not re-offered")
				}
				b := bodies[0]
				if !strings.Contains(b, "alert storm") {
					t.Fatalf("re-offered batch must land as the coalesced summary, got:\n%s", b)
				}
				for _, id := range []string{"s0", "s1"} {
					if !strings.Contains(b, id+": up → error") {
						t.Errorf("re-offered summary missing %s:\n%s", id, b)
					}
				}
				// Exactly one re-offer per batch: one summary, no loop.
				pw.DrainAlerts(2 * time.Second)
				if n := len(getBodies()); n != 1 {
					t.Fatalf("deliveries after drain = %d, want exactly 1 (one re-offer, no loop)", n)
				}
			})
		})
	})
}

// TestStormSummaryNoReOfferOnSuccess (MAJOR-7.3 positive control): a
// healthy provider gets exactly ONE summary — the re-offer path must not
// fire when the first delivery succeeded.
func TestStormSummaryNoReOfferOnSuccess(t *testing.T) {
	withStormBudget(t, 0, 500*time.Millisecond, func() {
		withPlainTransport(t, func() {
			oldDelays := alertRetryDelays
			alertRetryDelays = []time.Duration{5 * time.Millisecond, 5 * time.Millisecond}
			defer func() { alertRetryDelays = oldDelays }()
			withRecoveryRetryDelay(t, 60*time.Millisecond, func() {
				pw, db, getBodies, failMode, _, cleanup := newFailingStormWorker(t)
				defer cleanup()
				failMode.Store(false)
				insertStormSensor(t, db, "s0")
				insertStormSensor(t, db, "s1")
				if _, err := db.Exec(`UPDATE sensors SET status = 'error' WHERE id IN ('s0','s1')`); err != nil {
					t.Fatalf("set s0/s1 error: %v", err)
				}
				pw.launchAlert(func() { pw.sendAlert("s0", "s0", "127.0.0.1", "up", "error", 0) })
				pw.launchAlert(func() { pw.sendAlert("s1", "s1", "127.0.0.1", "up", "error", 0) })
				deadline := time.Now().Add(2 * time.Second)
				for len(getBodies()) == 0 && !time.Now().After(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				if n := len(getBodies()); n != 1 {
					t.Fatalf("deliveries = %d, want 1 (the coalesced summary)", n)
				}
				// Let a (buggy) re-offer fire and land a second body.
				time.Sleep(800 * time.Millisecond)
				pw.DrainAlerts(2 * time.Second)
				if n := len(getBodies()); n != 1 {
					t.Fatalf("deliveries after the retry window = %d, want 1 (no re-offer on success)", n)
				}
			})
		})
	})
}
