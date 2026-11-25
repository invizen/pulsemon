package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// --- Finding #12: storm-summary caps, maintenance gate, moved-on filter ---
//
// Three defects, one scenario: a real rack/router outage is exactly what
// storm coalescing exists for, and pre-fix the coalesced summary (a) was
// dropped by providers over their content limit (non-retryable HTTP 400 —
// the operator's ONLY outage alert vanished), (b) fired during maintenance
// mode (no alertsEnabled() check on the storm path), and (c) listed sensors
// that had already moved on (a partial-recovery card for an error ->
// warning sensor, then a summary line saying it was down).

// stormCapEntries builds n entries sized so the UNCAPPED plain body falls
// strictly between the Discord (2,000) and Telegram / Google Chat (4,096)
// caps: the cap test is only meaningful if the full summary really does
// exceed the smaller limit and fit under the larger one.
func stormCapEntries(n int) []stormEntry {
	entries := make([]stormEntry, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("svc-%04d", i)
		entries = append(entries, stormEntry{id: name, name: name, target: "https://service.internal.example/health", oldState: "up", state: "error"})
	}
	return entries
}

// TestStormSummaryCapsPerProvider: the summary is rendered per provider,
// each under ITS content cap, with the overflow reported as a "… and N
// more" footer. Over the cap the post is a non-retryable HTTP 400 and the
// WHOLE summary is dropped — so a capped body (slightly lossy) beats an
// uncapped body (totally lost). The header still counts ALL sensors.
func TestStormSummaryCapsPerProvider(t *testing.T) {
	entries := stormCapEntries(40)

	// Sizing sanity: the uncapped body must straddle the two caps.
	full := stormSummaryPlain(entries, 0, false)
	if n := utf8.RuneCountInString(full); n <= discordContentMax || n >= telegramTextMax {
		t.Fatalf("test sizing broken: uncapped body is %d runes, want (2000, 4096)", n)
	}

	// Discord (2,000): the body stays under the cap and the footer names
	// exactly how many sensors were cut.
	md := stormSummaryMarkdown(entries, discordContentMax, false)
	if n := utf8.RuneCountInString(md); n > discordContentMax {
		t.Errorf("discord body is %d runes, exceeds the %d cap", n, discordContentMax)
	}
	var shown int
	for i := 0; i < len(entries); i++ {
		if strings.Contains(md, fmt.Sprintf("svc-%04d", i)) {
			shown = i + 1
		}
	}
	if shown == 0 {
		t.Fatalf("discord body shows no sensor lines:\n%s", md)
	}
	if !strings.Contains(md, fmt.Sprintf("\n… and %d more", len(entries)-shown)) {
		t.Errorf("discord body must end with '… and %d more' (showed %d of %d): %q", len(entries)-shown, shown, len(entries), md[max(0, len(md)-80):])
	}
	if strings.Contains(md, "svc-0039") {
		t.Errorf("discord body includes the last sensor — it was truncated:\n%s", md)
	}
	// The header counts ALL sensors, not just the ones shown.
	if !strings.Contains(md, "40 sensors changed state") {
		t.Errorf("truncated header must still count all 40 sensors:\n%s", md)
	}

	// Google Chat (4,096): the full list fits — no footer, every line.
	gc := stormSummaryMarkdown(entries, googleChatMax, false)
	if n := utf8.RuneCountInString(gc); n > googleChatMax {
		t.Errorf("google_chat body is %d runes, exceeds the %d cap", n, googleChatMax)
	}
	if strings.Contains(gc, "… and") {
		t.Errorf("google_chat body under its cap must not truncate:\n%s", gc)
	}
	if !strings.Contains(gc, "svc-0039") {
		t.Errorf("google_chat body must include the last sensor (full list fits):\n%s", gc)
	}

	// Telegram HTML (4,096 in production; 2,000 here to exercise the cut):
	// the cap is measured on the ESCAPED output — what Telegram counts.
	tg := stormSummaryHTML(entries, 2000, false)
	if n := utf8.RuneCountInString(tg); n > 2000 {
		t.Errorf("telegram body is %d runes, exceeds the 2000 cap", n)
	}
	if !strings.Contains(tg, "… and") {
		t.Errorf("telegram body over the cap must truncate:\n%s", tg)
	}

	// SMTP (0 = uncapped): every line, no footer.
	sm := stormSummaryPlain(entries, 0, false)
	if strings.Contains(sm, "… and") {
		t.Errorf("SMTP body is uncapped: no footer expected:\n%s", sm)
	}
	if !strings.Contains(sm, "svc-0039") {
		t.Errorf("SMTP body must include every sensor:\n%s", sm)
	}
}

// TestStormFlushSilencedInMaintenance: maintenance can begin AFTER the
// storm entries were queued (the individual alerts were each gated at
// launch, pre-maintenance; the flush fires up to stormWindow later).
// flushStorm must re-check alertsEnabled() and drop the summary — a storm
// summary is an alert, and maintenance silences all of them.
func TestStormFlushSilencedInMaintenance(t *testing.T) {
	withPlainTransport(t, func() {
		pw, db, getBodies, cleanup := newStormTestWorker(t)
		defer cleanup()
		// Two downed sensors in the queue — the exact rack-outage shape.
		insertStormSensor(t, db, "m0")
		insertStormSensor(t, db, "m1")
		if _, err := db.Exec(`UPDATE sensors SET status = 'error' WHERE id IN ('m0','m1')`); err != nil {
			t.Fatalf("set m0/m1 error: %v", err)
		}
		pw.mu.Lock()
		pw.sensors["m0"] = &ProbeState{id: "m0", lastStatus: "error"}
		pw.sensors["m1"] = &ProbeState{id: "m1", lastStatus: "error"}
		pw.mu.Unlock()
		pw.stormMu.Lock()
		pw.stormQueue = append(pw.stormQueue,
			stormEntry{id: "m0", name: "m0", target: "127.0.0.1", oldState: "up", state: "error"},
			stormEntry{id: "m1", name: "m1", target: "127.0.0.1", oldState: "up", state: "error"},
		)
		pw.stormMu.Unlock()
		// Maintenance flips on AFTER the queue filled.
		if err := db.SetSetting("maintenance_mode", "1"); err != nil {
			t.Fatalf("enable maintenance: %v", err)
		}
		pw.reloadAlertSettings()
		if pw.alertsEnabled() {
			t.Fatal("test setup: alerts must be silenced in maintenance")
		}
		pw.flushStorm(false)
		time.Sleep(100 * time.Millisecond) // settle any (bogus) async delivery
		if bodies := getBodies(); len(bodies) != 0 {
			t.Errorf("maintenance: storm summary delivered (%d bodies), want 0", len(bodies))
		}
	})
}

// TestStormSummarySilencedInMaintenance: the delivery-time gate. The flush
// gate runs in flushStorm; deliverStormSummary is async (launchAlert), so
// maintenance can flip in the gap. The re-check at the top of
// deliverStormSummary drops the summary there.
func TestStormSummarySilencedInMaintenance(t *testing.T) {
	withPlainTransport(t, func() {
		pw, db, getBodies, cleanup := newStormTestWorker(t)
		defer cleanup()
		insertStormSensor(t, db, "g0")
		if _, err := db.Exec(`UPDATE sensors SET status = 'error' WHERE id = 'g0'`); err != nil {
			t.Fatalf("set g0 error: %v", err)
		}
		pw.mu.Lock()
		pw.sensors["g0"] = &ProbeState{id: "g0", lastStatus: "error"}
		pw.mu.Unlock()
		if err := db.SetSetting("maintenance_mode", "1"); err != nil {
			t.Fatalf("enable maintenance: %v", err)
		}
		pw.reloadAlertSettings()
		// Exactly what flushStorm hands to launchAlert for a still-down
		// sensor — with maintenance on in the gap.
		pw.deliverStormSummary([]stormEntry{{id: "g0", name: "g0", target: "127.0.0.1", oldState: "up", state: "error"}}, false)
		if bodies := getBodies(); len(bodies) != 0 {
			t.Errorf("maintenance: storm summary delivered (%d bodies), want 0", len(bodies))
		}
	})
}

// TestStormFlushDropsMovedOnSensors: the flush filter only dropped "up",
// so a sensor that PARTIALLY recovered (error -> warning) stayed in the
// summary — contradicting the partial-recovery card already delivered
// individually (stormAdmit exempts recoveries from coalescing). The filter
// must drop every entry whose sensor no longer holds the entry's state:
// recovered (now "up"), partially recovered (now "warning"), and degraded
// further (entry "warning", now "error" — the newer error transition
// alerted individually, so the older line is stale). A sensor still in the
// entry's state is kept.
func TestStormFlushDropsMovedOnSensors(t *testing.T) {
	withPlainTransport(t, func() {
		pw, db, getBodies, cleanup := newStormTestWorker(t)
		defer cleanup()
		// p0: queued as up->error, now warning (partial recovery fired).
		// p1: queued as up->warning, now error (degraded further; the
		//     newer error transition alerted individually).
		// k0: queued as up->error, still error (the control — kept).
		for _, id := range []string{"p0", "p1", "k0"} {
			insertStormSensor(t, db, id)
		}
		if _, err := db.Exec(`UPDATE sensors SET status = 'warning' WHERE id = 'p0'`); err != nil {
			t.Fatalf("set p0 warning: %v", err)
		}
		if _, err := db.Exec(`UPDATE sensors SET status = 'error' WHERE id IN ('p1','k0')`); err != nil {
			t.Fatalf("set p1/k0 error: %v", err)
		}
		pw.mu.Lock()
		pw.sensors["p0"] = &ProbeState{id: "p0", lastStatus: "warning"}
		pw.sensors["p1"] = &ProbeState{id: "p1", lastStatus: "error"}
		pw.sensors["k0"] = &ProbeState{id: "k0", lastStatus: "error"}
		pw.mu.Unlock()
		pw.stormMu.Lock()
		pw.stormQueue = append(pw.stormQueue,
			stormEntry{id: "p0", name: "p0", target: "127.0.0.1", oldState: "up", state: "error"},
			stormEntry{id: "p1", name: "p1", target: "127.0.0.1", oldState: "up", state: "warning"},
			stormEntry{id: "k0", name: "k0", target: "127.0.0.1", oldState: "up", state: "error"},
		)
		pw.stormMu.Unlock()
		pw.flushStorm(false)
		// k0 is kept, so a summary is delivered; poll for it (same reason
		// as TestStormCoalescing: the flush lands after alertWG drains).
		var bodies []string
		deadline := time.Now().Add(2 * time.Second)
		for {
			bodies = getBodies()
			done := false
			for _, b := range bodies {
				if strings.Contains(b, "alert storm") {
					done = true
				}
			}
			if done || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		var s string
		for _, b := range bodies {
			if strings.Contains(b, "alert storm") {
				s = b
			}
		}
		if !strings.Contains(s, "k0") {
			t.Errorf("summary must keep the still-down sensor k0:\n%s", s)
		}
		if strings.Contains(s, "p0") {
			t.Errorf("summary lists p0 as down — it partially recovered (the card already fired):\n%s", s)
		}
		if strings.Contains(s, "p1") {
			t.Errorf("summary lists a stale warning line for p1 — it degraded to error individually:\n%s", s)
		}
	})
}

// TestStormSummaryDropsMovedOnBeforePost: the same contract at the post
// boundary — a sensor the flush filter KEPT (it was "error" at flush time)
// but that partially recovered in the gap (now "warning") must not be
// listed as "error" in a summary landing after its partial-recovery card.
func TestStormSummaryDropsMovedOnBeforePost(t *testing.T) {
	withPlainTransport(t, func() {
		pw, db, getBodies, cleanup := newStormTestWorker(t)
		defer cleanup()
		insertStormSensor(t, db, "q0")
		insertStormSensor(t, db, "q1")
		if _, err := db.Exec(`UPDATE sensors SET status = 'warning' WHERE id = 'q0'`); err != nil {
			t.Fatalf("set q0 warning: %v", err)
		}
		if _, err := db.Exec(`UPDATE sensors SET status = 'error' WHERE id = 'q1'`); err != nil {
			t.Fatalf("set q1 error: %v", err)
		}
		pw.mu.Lock()
		pw.sensors["q0"] = &ProbeState{id: "q0", lastStatus: "warning"}
		pw.sensors["q1"] = &ProbeState{id: "q1", lastStatus: "error"}
		pw.mu.Unlock()
		pw.deliverStormSummary([]stormEntry{
			{id: "q0", name: "q0", target: "127.0.0.1", oldState: "up", state: "error"},
			{id: "q1", name: "q1", target: "127.0.0.1", oldState: "up", state: "error"},
		}, false)
		bodies := getBodies()
		if len(bodies) != 1 {
			t.Fatalf("deliveries = %d, want 1 (q1 still down)", len(bodies))
		}
		b := bodies[0]
		if strings.Contains(b, "q0") {
			t.Errorf("summary lists q0 as down — it partially recovered:\n%s", b)
		}
		if !strings.Contains(b, "q1") {
			t.Errorf("summary must keep q1 (still down):\n%s", b)
		}
	})
}
