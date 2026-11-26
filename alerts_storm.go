package main

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// stormEntry is one alert suppressed by the storm budget, pending the
// coalesced summary.
type stormEntry struct {
	id       string
	name     string
	target   string
	oldState string
	state    string
	rttMs    float64
}

// stormBudget / stormWindow bound the global alert rate: at most
// stormBudget individual non-recovery alerts per stormWindow.
// recoveryStormBudget / recoveryStormWindow bound the recovery direction
// symmetrically (see the stormMu field comment in probe.go). Vars so tests
// can shrink them.
var (
	stormBudget         = 10
	stormWindow         = 30 * time.Second
	recoveryStormBudget = 10
	recoveryStormWindow = 30 * time.Second
)

// isRecoveryState reports whether a transition is a recovery: full (up) or
// partial (error -> warning). Both ride the recovery storm budget.
func isRecoveryState(oldState, state string) bool {
	return state == "up" || (oldState == "error" && state == "warning")
}

// stormAdmit reports whether this alert may be delivered individually,
// applying the budget of ITS direction (recovery vs non-recovery). See the
// stormMu field comment for the design.
func (pw *ProbeWorker) stormAdmit(id, name, target, oldState, state string, rttMs float64) bool {
	pw.stormMu.Lock()
	defer pw.stormMu.Unlock()
	return pw.stormAdmitLocked(isRecoveryState(oldState, state), stormEntry{
		id: id, name: name, target: target, oldState: oldState, state: state, rttMs: rttMs,
	})
}

// stormAdmitLocked applies ONE direction's budget. Caller holds stormMu.
func (pw *ProbeWorker) stormAdmitLocked(recovery bool, e stormEntry) bool {
	var (
		windowStart *time.Time
		count       *int
		queue       *[]stormEntry
		budget      int
		window      time.Duration
	)
	if recovery {
		windowStart, count, queue = &pw.recoveryStormWindowStart, &pw.recoveryStormCount, &pw.recoveryStormQueue
		budget, window = recoveryStormBudget, recoveryStormWindow
	} else {
		windowStart, count, queue = &pw.stormWindowStart, &pw.stormCount, &pw.stormQueue
		budget, window = stormBudget, stormWindow
	}
	now := time.Now()
	if now.Sub(*windowStart) >= window {
		*windowStart = now
		*count = 0
	}
	if *count < budget {
		*count++
		return true
	}
	*queue = append(*queue, e)
	pw.armStormFlushLocked(recovery, now)
	return false
}

// armStormFlushLocked schedules the one-shot flush of the coalesced queue
// of ONE direction at the end of its current storm window. Caller holds
// stormMu.
func (pw *ProbeWorker) armStormFlushLocked(recovery bool, now time.Time) {
	var (
		armed       *bool
		windowStart *time.Time
		window      time.Duration
	)
	if recovery {
		armed, windowStart, window = &pw.recoveryStormFlushArmed, &pw.recoveryStormWindowStart, recoveryStormWindow
	} else {
		armed, windowStart, window = &pw.stormFlushArmed, &pw.stormWindowStart, stormWindow
	}
	if *armed {
		return
	}
	*armed = true
	due := time.Until(windowStart.Add(window))
	if due < 0 {
		due = 0
	}
	// Track the flush in alertWG from ARM time: the arming caller is an alert
	// path that already holds a launchAlert count (sendWebhook runs inside
	// launchAlert), so this Add can never be the "Add called concurrently with
	// Wait" case at counter 0. DrainAlerts JOINS a pending flush; the goroutine
	// exits promptly on stopCtx, so shutdown is not delayed (a flush due
	// within main's shutdown pre-drain fires before stopCtx cancels; one due
	// after it drops — see shutdownAlerts).
	// History: docs/DECISIONS.md → alert-gate.
	pw.alertWG.Add(1)
	go func() {
		defer pw.alertWG.Done()
		defer alertPanicRecovered("storm-flush")
		select {
		case <-time.After(due):
			pw.flushStorm(recovery)
		case <-pw.stopCtx.Done():
		}
	}()
}

// flushStorm delivers the coalesced storm summary of ONE direction (when
// its queue is non-empty) and resets that direction's budget for the next
// window.
func (pw *ProbeWorker) flushStorm(recovery bool) {
	pw.stormMu.Lock()
	var (
		q           []stormEntry
		windowStart *time.Time
		count       *int
		armed       *bool
	)
	if recovery {
		q = pw.recoveryStormQueue
		pw.recoveryStormQueue = nil
		windowStart, count, armed = &pw.recoveryStormWindowStart, &pw.recoveryStormCount, &pw.recoveryStormFlushArmed
	} else {
		q = pw.stormQueue
		pw.stormQueue = nil
		windowStart, count, armed = &pw.stormWindowStart, &pw.stormCount, &pw.stormFlushArmed
	}
	*windowStart = time.Time{}
	*count = 0
	*armed = false
	pw.stormMu.Unlock()
	if len(q) == 0 {
		return
	}
	// Maintenance mode silences every alert — the summary included. The
	// individual alerts that filled this queue were each gated at launch,
	// but maintenance can begin AFTER an entry was queued (the flush fires
	// up to stormWindow later), so re-check at flush time: a storm summary
	// must never land in a chat the operator has silenced.
	if !pw.alertsEnabled() {
		return
	}
	// Dedupe by sensor first: a sensor that flapped more than once inside
	// the window (up -> error, then warning -> error) leaves one queue
	// entry per transition. Only the latest transition per sensor is
	// actionable — the older line is stale by definition — so keep the
	// latest entry, in first-seen order for stable summaries.
	latest := make(map[string]stormEntry, len(q))
	order := make([]string, 0, len(q))
	for _, e := range q {
		if _, seen := latest[e.id]; !seen {
			order = append(order, e.id)
		}
		latest[e.id] = e
	}
	// Drop entries whose sensor has MOVED ON since the transition was queued:
	// a summary line for a sensor that recovered (now "up") would contradict
	// the recovery alert it raced, and one that degraded further (entry
	// "warning", now "error") is stale — the newer transition alerted
	// individually. The same filter serves both directions symmetrically: a
	// queued recovery (entry "up") whose sensor flapped back to "error" is
	// dropped for the same reason — the newer transition owns its own budget
	// path and is the operator's last word, not this summary. A vanished
	// sensor (deleted mid-storm, read error) is KEPT — the operator should
	// still see it in the storm that took it down. Status is read via
	// currentStatus (in-memory first): actively-probed sensors make
	// lastStatus the freshest source, and it avoids one SQLite round-trip
	// per queued entry.
	// History: docs/DECISIONS.md → storm-summary-caps-maintenance-gate-and-moved-on-filter.
	still := q[:0]
	for _, id := range order {
		if s, err := pw.currentStatus(id); err == nil && s != latest[id].state {
			continue
		}
		still = append(still, latest[id])
	}
	if len(still) == 0 {
		return
	}
	pw.launchAlert(func() {
		pw.deliverStormSummary(still, recovery)
	})
}

// deliverStormSummary sends the coalesced summary of ONE direction to every
// active provider in parallel (same fan-out contract as sendWebhookDeliver).
// It is a global meta-alert — NOT queued on any sensor's alertGate — so it
// cannot disturb a sensor's per-sensor ordering guarantee (F4).
func (pw *ProbeWorker) deliverStormSummary(entries []stormEntry, recovery bool) {
	// Maintenance can begin between flushStorm's check and this delivery
	// (launchAlert queues the job, it does not run it inline): re-check so
	// a summary never lands in a chat silenced in the gap.
	if !pw.alertsEnabled() {
		return
	}
	// Re-check each entry's status immediately before building the summary:
	// flushStorm's filter ran earlier and this delivery is async (launchAlert)
	// — a sensor that moved on in the gap would be listed under a state it no
	// longer holds, contradicting the individual alert the per-sensor gate
	// ordered ahead of this summary (which bypasses that gate). The re-check
	// narrows the race to the instant before the post. currentStatus is
	// in-memory for an actively-probed sensor, so this is cheap.
	// History: docs/DECISIONS.md → storm-summary-recheck-before-post.
	still := make([]stormEntry, 0, len(entries))
	for _, e := range entries {
		if s, err := pw.currentStatus(e.id); err == nil && s != e.state {
			continue
		}
		still = append(still, e)
	}
	if len(still) == 0 {
		return
	}
	entries = still
	dests, ok := pw.resolveDestinations()
	if !ok {
		log.Printf("alert: storm summary (%d sensors) not delivered — provider list unreadable", len(entries))
		return
	}
	// Render per provider, each under ITS content cap: over the cap the
	// post is a non-retryable HTTP 400 and the WHOLE summary is dropped —
	// the operator gets no outage alert at all. The capped formatters
	// replace the overflow with a "… and N more" footer, so every
	// provider receives a body it will accept (see truncateSummaryLines).
	// SMTP has no practical limit: 0 = uncapped.
	kind := "alert"
	if recovery {
		kind = "recovery"
	}
	mdChat := stormSummaryMarkdown(entries, googleChatMax, recovery)
	mdDiscord := stormSummaryMarkdown(entries, discordContentMax, recovery)
	subject := fmt.Sprintf("pulsemon: %s storm — %d sensors %s", kind, len(entries), stormSummaryCountNoun(recovery))
	body := stormSummaryPlain(entries, 0, recovery)
	var wg sync.WaitGroup
	var delivered atomic.Bool
	for _, d := range dests {
		wg.Add(1)
		go func(d dest) {
			defer wg.Done()
			defer alertPanicRecovered("deliver-" + d.p.Kind)
			var ok bool
			switch d.p.Kind {
			case "google_chat":
				ok = pw.postJSON(d.url, map[string]any{"text": mdChat}) == nil
			case "discord":
				ok = pw.postJSON(d.url, map[string]any{
					"content":          mdDiscord,
					"allowed_mentions": map[string]any{"parse": []string{}},
				}) == nil
			case "telegram":
				// d.chatID was resolved up front in resolveDestinations
				// (see dest) — never a live re-read here.
				ok = pw.postJSON(d.url, map[string]any{
					"chat_id":    d.chatID,
					"text":       stormSummaryHTML(entries, telegramTextMax, recovery),
					"parse_mode": "HTML",
				}) == nil
			case "smtp":
				ok = d.smtp != nil && pw.sendSMTPWith(pw.stopCtx, *d.smtp, subject, body) == nil
			}
			if ok {
				delivered.Store(true)
			}
		}(d)
	}
	wg.Wait()
	if len(dests) > 0 && !delivered.Load() {
		// Every provider failed (a brief WAN outage takes out the targets
		// AND the egress together): re-offer each entry through the normal
		// path instead of discarding the batch. On a realert_min == 0
		// install no re-alert tick ever comes, so the coalesced sensors
		// (#11..#N) would never alert — exactly the visibility the storm
		// path exists to preserve.
		log.Printf("alert: storm summary (%d sensors) failed on all %d providers; re-offering each entry", len(entries), len(dests))
		for _, e := range entries {
			pw.scheduleStormRetry(e.id, e.name, e.target, e.oldState, e.state, e.rttMs)
		}
	}
}
