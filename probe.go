package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ProbeState struct {
	id       string
	isPaused bool
}

type sensorConfig struct {
	id        string
	name      string
	target    string
	tags      []string
	intervalS int
	timeoutMS int
	lossWarn  int
	downAfter int
	spikeMult int
	// lastErrCount is the global ICMP-socket error counter as of the last
	// probe; deriveStatus compares against it to detect "probing is broken".
	lastErrCount int64
}

type ProbeWorker struct {
	mu         sync.Mutex
	sensors    map[string]*ProbeState
	loops      map[string]context.CancelFunc
	db         *DB
	webhookURL string
}

func NewProbeWorker(db *DB, webhookURL string) *ProbeWorker {
	return &ProbeWorker{
		sensors:    make(map[string]*ProbeState),
		loops:      make(map[string]context.CancelFunc),
		db:         db,
		webhookURL: webhookURL,
	}
}

// Run reconciles the probe set from the DB every 5s, plus hourly retention.
func (pw *ProbeWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	retention := time.NewTicker(1 * time.Hour)
	defer retention.Stop()

	pw.syncSensors(ctx) // immediate first pass
	// Warm the shared ICMP socket now so a socket-level failure is visible
	// in healthz immediately instead of after the first probe tick.
	if _, err := getSharedConn(); err != nil {
		log.Printf("ProbeWorker: ICMP socket init: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pw.syncSensors(ctx)
		case <-retention.C:
			pw.purgeOld()
		}
	}
}

func (pw *ProbeWorker) syncSensors(ctx context.Context) {
	rows, err := pw.db.Query(`SELECT id, name, target, interval_s, timeout_ms, loss_warn, down_after, spike_mult, state
		FROM sensors WHERE state = 'active'`)
	if err != nil {
		log.Printf("ProbeWorker: failed to query sensors: %v", err)
		return
	}
	type activeCfg struct {
		sensorConfig
		state string
	}
	var configs []activeCfg
	for rows.Next() {
		var c activeCfg
		if err := rows.Scan(&c.id, &c.name, &c.target, &c.intervalS, &c.timeoutMS, &c.lossWarn, &c.downAfter, &c.spikeMult, &c.state); err != nil {
			continue
		}
		if c.spikeMult < 2 {
			c.spikeMult = 5
		}
		c.tags = pw.db.SensorTags(c.id)
		configs = append(configs, c)
	}
	rows.Close()

	pw.mu.Lock()
	defer pw.mu.Unlock()

	seen := make(map[string]bool, len(configs))
	for _, c := range configs {
		seen[c.id] = true
		ps, ok := pw.sensors[c.id]
		if !ok {
			ps = &ProbeState{id: c.id, isPaused: c.state == "paused"}
			pw.sensors[c.id] = ps
		} else {
			ps.isPaused = c.state == "paused" // keep pause in sync with DB
		}
		cancel, ok := pw.loops[c.id]
		if !ok {
			lctx, lcancel := context.WithCancel(ctx)
			pw.loops[c.id] = lcancel
			cfg := c.sensorConfig
			go pw.sensorLoop(lctx, cfg)
			cancel = lcancel
		}
		_ = cancel
	}

	// Stop loops for sensors that vanished or were deleted.
	for id, cancel := range pw.loops {
		if !seen[id] {
			cancel()
			delete(pw.loops, id)
			delete(pw.sensors, id)
		}
	}
}

// SetPaused flips the in-memory pause flag immediately (API PATCH fast path).
func (pw *ProbeWorker) SetPaused(id string, paused bool) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if ps, ok := pw.sensors[id]; ok {
		ps.isPaused = paused
	}
}

// Restart respawns a sensor's probe loop so config changes (target/interval/
// timeout) take effect without a process restart.
func (pw *ProbeWorker) Restart(id string) {
	pw.mu.Lock()
	if cancel, ok := pw.loops[id]; ok {
		cancel()
		delete(pw.loops, id)
	}
	delete(pw.sensors, id)
	pw.mu.Unlock()
}

// Remove drops a deleted sensor's loop and state.
func (pw *ProbeWorker) Remove(id string) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if cancel, ok := pw.loops[id]; ok {
		cancel()
		delete(pw.loops, id)
	}
	delete(pw.sensors, id)
}

// ActiveCount is the number of sensor loops currently tracked (healthz).
func (pw *ProbeWorker) ActiveCount() int {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	return len(pw.loops)
}

func (pw *ProbeWorker) sensorLoop(ctx context.Context, c sensorConfig) {
	interval := time.Duration(c.intervalS) * time.Second

	// Stagger the first tick by a deterministic per-sensor phase (hash of the
	// id, 0 .. interval). Without this, every sensor added at the same time —
	// or every sensor sharing an interval — fires on the same wall-clock second,
	// producing a write thundering-herd against SQLite. Spreading the phases
	// turns N simultaneous writes into N writes spread across the interval.
	phase := time.Duration(fnvHash([]byte(c.id))) % time.Duration(interval)
	if phase < 250*time.Millisecond {
		phase += 250 * time.Millisecond // never probe in the first instant
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// First probe after the staggered phase; subsequent probes every interval.
	first := time.NewTimer(phase)
	defer first.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-ticker.C:
		}
		pw.mu.Lock()
		ps, ok := pw.sensors[c.id]
		if !ok {
			pw.mu.Unlock()
			return
		}
		paused := ps.isPaused
		pw.mu.Unlock()

		if paused {
			continue // paused = no packets, no rows, no alerts
		}
		pw.doProbe(c)
	}
}

// fnvHash is a 64-bit FNV-1a over the byte slice — cheap, deterministic, and
// only used to derive a stable stagger phase per sensor id.
func fnvHash(b []byte) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	var h uint64 = offset64
	for _, c := range b {
		h ^= uint64(c)
		h *= prime64
	}
	return h
}

func (pw *ProbeWorker) doProbe(c sensorConfig) {
	c.lastErrCount = probeErrCount.Load()
	res := pingHost(c.target, time.Duration(c.timeoutMS)*time.Millisecond)

	var rttVal interface{}
	var rttMs float64
	if !res.Lost {
		ms := res.RTT.Seconds() * 1000 // float64 ms, no truncation
		rttVal = ms
		rttMs = ms
	}

	if _, err := pw.db.Exec("INSERT INTO probes (sensor_id, ts, rtt_ms, resolved_ip) VALUES (?, ?, ?, ?)", c.id, time.Now().UTC().Format(time.RFC3339Nano), rttVal, res.ResolvedIP); err != nil {
		log.Printf("ProbeWorker: failed to insert probe for %s: %v", c.id, err)
		return
	}

	newStatus := pw.deriveStatus(c)

	var oldStatus string
	if err := pw.db.QueryRow("SELECT status FROM sensors WHERE id = ?", c.id).Scan(&oldStatus); err != nil {
		return
	}
	if newStatus == oldStatus {
		// No transition: if still not up, a sustained re-alert may be due.
		if newStatus != "up" {
			pw.maybeRealert(c, newStatus, rttMs)
		}
		return
	}

	if _, err := pw.db.Exec("UPDATE sensors SET status = ? WHERE id = ?", newStatus, c.id); err != nil {
		log.Printf("ProbeWorker: failed to update status for %s: %v", c.id, err)
		return
	}

	note := fmt.Sprintf("%s -> %s", oldStatus, newStatus)
	if newStatus == "up" {
		note = "recovered" // first transition back to up after down/degraded
	}
	if _, err := pw.db.Exec("INSERT INTO events (sensor_id, ts, from_status, to_status, note) VALUES (?, ?, ?, ?, ?)",
		c.id, time.Now().UTC().Format(time.RFC3339Nano), oldStatus, newStatus, note); err != nil {
		log.Printf("ProbeWorker: failed to record event for %s: %v", c.id, err)
	}

	pw.setAlertState(c.id, newStatus, time.Now().UTC())
	if pw.shouldAlertNow(c, newStatus) {
		go pw.sendAlert(c.id, c.name, c.target, newStatus, rttMs)
	}
}

// alertsEnabled reports whether any alert may fire: maintenance mode
// silences everything.
func (pw *ProbeWorker) alertsEnabled() bool {
	return pw.db.GetSetting("maintenance_mode") != "1"
}

// alertDegraded reports whether degraded-state alerts fire (default true).
func (pw *ProbeWorker) alertDegraded() bool {
	return pw.db.GetSetting("alert_degraded") != "0"
}

// shouldAlertNow applies the maintenance/degraded gates and the global
// alert routing rule (settings table): "all", "tags" (any of the sensor's
// tags in filter list), or "sensors" (id in filter list).
func (pw *ProbeWorker) shouldAlertNow(c sensorConfig, status string) bool {
	if !pw.alertsEnabled() {
		return false
	}
	if status == "degraded" && !pw.alertDegraded() {
		return false
	}
	return pw.shouldAlert(c.id, c.tags)
}

// shouldAlert applies the global alert routing rule (settings table):
// "all", "tags" (any of the sensor's tags in filter list), or "sensors"
// (id in filter list).
func (pw *ProbeWorker) shouldAlert(id string, tags []string) bool {
	scope := pw.db.GetSetting("alert_scope")
	if scope == "" {
		scope = "all"
	}
	if scope == "all" {
		return true
	}
	var items []string
	if f := pw.db.GetSetting("alert_filter"); f != "" {
		if err := json.Unmarshal([]byte(f), &items); err != nil {
			return false
		}
	}
	switch scope {
	case "tags":
		for _, t := range tags {
			for _, f := range items {
				if t == f {
					return true
				}
			}
		}
	case "sensors":
		for _, s := range items {
			if s == id {
				return true
			}
		}
	}
	return false
}

// maybeRealert re-notifies while a sensor stays in the same non-up state,
// at most once per re-alert interval (default 30 min).
func (pw *ProbeWorker) maybeRealert(c sensorConfig, status string, rttMs float64) {
	now := time.Now().UTC()
	var lastStatus, lastTs string
	err := pw.db.QueryRow("SELECT status, last_ts FROM alert_state WHERE sensor_id = ?", c.id).Scan(&lastStatus, &lastTs)
	if err != nil {
		pw.setAlertState(c.id, status, now)
		return
	}
	if lastStatus != status {
		pw.setAlertState(c.id, status, now)
		return
	}
	if pw.realertMin() == 0 {
		// 0 = "alert once only": no periodic re-alerts while the sensor
		// stays in the same non-up state. (Without this guard the
		// interval check below degenerates to "elapsed < 0", i.e. a
		// re-alert fired on EVERY probe tick.) State transitions and
		// recoveries still alert via doProbe.
		return
	}
	t, err := time.Parse(time.RFC3339, lastTs)
	if err != nil {
		pw.setAlertState(c.id, status, now)
		return
	}
	if now.Sub(t) < time.Duration(pw.realertMin())*time.Minute {
		return
	}
	pw.setAlertState(c.id, status, now)
	if pw.shouldAlertNow(c, status) {
		go pw.sendRealert(c.id, c.name, c.target, status, rttMs)
	}
}

func (pw *ProbeWorker) setAlertState(id, status string, ts time.Time) {
	_, _ = pw.db.Exec(`INSERT INTO alert_state (sensor_id, status, last_ts) VALUES (?, ?, ?)
		ON CONFLICT(sensor_id) DO UPDATE SET status = excluded.status, last_ts = excluded.last_ts`,
		id, status, ts.Format(time.RFC3339))
}

// realertMin returns the re-alert interval in minutes. 0 means alert
// once only (no re-alerts). Default 30.
func (pw *ProbeWorker) realertMin() int {
	if v := pw.db.GetSetting("realert_min"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 1440 {
			return n
		}
	}
	return 30
}

// ResetAlertStates stamps every tracked sensor's alert_state to now, so
// sensors already in a bad state do not immediately re-alert right after
// maintenance mode is turned off.
func (pw *ProbeWorker) ResetAlertStates() {
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = pw.db.Exec(`UPDATE alert_state SET last_ts = ?`, now)
}

// Status is derived from the sensor's most recent probes (last `down_after`,
// a 4-probe window at the default) with fixed precedence:
//
//	down      — `down_after` consecutive losses from the newest probe
//	up        — the newest 2 probes both succeeded (a sensor with only one
//	            probe recorded is up if that single probe succeeded)
//	degraded  — anything else: a loss is present in the recent window but it
//	            is neither fully down nor 2 clean in a row
//
// A probe-level ICMP error (broken socket) forces degraded so a dead probe
// path never reads as "up".
func (pw *ProbeWorker) deriveStatus(c sensorConfig) string {
	// Broken probe path (e.g. ICMP socket cannot be created): probes never
	// land, so we cannot know the real state — flag degraded, never up.
	if probeErrCount.Load() > c.lastErrCount {
		return "degraded"
	}

	// Fetch the last `down_after` probes, newest first. This window is enough
	// to test both "all losses in a row" (down) and "2 successes in a row" (up).
	rows, err := pw.db.Query("SELECT rtt_ms FROM probes WHERE sensor_id = ? ORDER BY ts DESC LIMIT ?", c.id, c.downAfter)
	if err != nil {
		return "up"
	}
	var recent []*float64 // index 0 = newest; nil = lost, non-nil = rtt
	for rows.Next() {
		var rtt *float64
		if rows.Scan(&rtt) == nil {
			recent = append(recent, rtt)
		}
	}
	rows.Close()

	if len(recent) == 0 {
		return "up" // no data yet
	}

	// DOWN: down_after consecutive losses from the newest probe.
	consec := 0
	for _, r := range recent {
		if r == nil {
			consec++
		} else {
			break
		}
	}
	if consec >= c.downAfter {
		return "down"
	}

	// UP: the newest 2 probes both succeeded. With only one probe recorded,
	// a single success is enough (new-sensor grace).
	if recent[0] != nil && (len(recent) == 1 || recent[1] != nil) {
		return "up"
	}

	// DEGRADED: a loss is in the recent window but it's not down and not up.
	return "degraded"
}

// purgeOld enforces 14-day retention on probes/events (SPEC §3).
func (pw *ProbeWorker) purgeOld() {
	cutoff := time.Now().AddDate(0, 0, -14).UTC().Format(time.RFC3339Nano)
	for _, table := range []string{"probes", "events"} {
		res, err := pw.db.Exec("DELETE FROM "+table+" WHERE ts < ?", cutoff)
		if err != nil {
			log.Printf("retention: failed to purge %s: %v", table, err)
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("retention: purged %d rows from %s", n, table)
		}
	}
}

// resolveWebhookURL returns the alert webhook URL: the settings table
// (editable from the dashboard) wins over the GOOGLE_CHAT_WEBHOOK_URL env.
func (pw *ProbeWorker) resolveWebhookURL() string {
	if u := pw.db.GetSetting("webhook_url"); u != "" {
		return u
	}
	return pw.webhookURL
}

// ResolveWebhookURL is the API-facing read of the effective webhook URL.
func (pw *ProbeWorker) ResolveWebhookURL() string { return pw.resolveWebhookURL() }

// HasWebhook reports whether any webhook URL is configured.
func (pw *ProbeWorker) HasWebhook() bool { return pw.resolveWebhookURL() != "" }

// WebhookSource says where the effective URL comes from: "dashboard"
// (settings table) or "env" (container environment).
func (pw *ProbeWorker) WebhookSource() string {
	if pw.db.GetSetting("webhook_url") != "" {
		return "dashboard"
	}
	return "env"
}

func (pw *ProbeWorker) sendAlert(id, name, target, state string, rttMs float64) {
	if url := pw.resolveWebhookURL(); url != "" {
		pw.postCard(url, cardFor(state, name, target, rttMs))
	}
}

// sendRealert notifies that a sensor has stayed in the same non-up state.
func (pw *ProbeWorker) sendRealert(id, name, target, state string, rttMs float64) {
	if url := pw.resolveWebhookURL(); url != "" {
		pw.postCard(url, cardForRe(state, name, target, rttMs))
	}
}

// TestWebhook sends a test alert card to the currently configured webhook
// and reports whether the endpoint accepted it.
func (pw *ProbeWorker) TestWebhook() (bool, string) {
	url := pw.resolveWebhookURL()
	if url == "" {
		return false, "no webhook URL configured"
	}
	body, _ := json.Marshal(map[string]string{
		"text": "🟢 *zenmon: test alert*\n*Sensor*: settings\n*Target*: webhook-verify\n*State*: **test** — this message confirms your Google Chat webhook works.",
	})
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return false, fmt.Sprintf("endpoint returned HTTP %d", resp.StatusCode)
	}
	return true, "test alert sent (HTTP " + http.StatusText(resp.StatusCode) + ")"
}

func cardFor(state, name, target string, rttMs float64) string {
	icon := map[string]string{"up": "🟢", "degraded": "🟡", "down": "🔴"}[state]
	if icon == "" {
		icon = "🟢"
	}
	title := state
	if state == "up" {
		title = "recovered"
	}
	card := fmt.Sprintf("%s *zenmon: %s*\n*Sensor*: %s\n*Target*: %s\n*State*: **%s**",
		icon, title, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n*Ping*: %d ms", int(rttMs+0.5))
	}
	return card
}

func cardForRe(state, name, target string, rttMs float64) string {
	icon := map[string]string{"degraded": "🟡", "down": "🔴"}[state]
	if icon == "" {
		icon = "🟢"
	}
	card := fmt.Sprintf("%s *zenmon: still %s (re-alert)*\n*Sensor*: %s\n*Target*: %s\n*State*: **%s** — no change, re-notifying",
		icon, state, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n*Ping*: %d ms", int(rttMs+0.5))
	}
	return card
}

func (pw *ProbeWorker) postCard(url, card string) {
	payload, _ := json.Marshal(map[string]string{"text": card})
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("webhook: send failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("webhook: endpoint returned %d", resp.StatusCode)
	}
}

// newID generates a unique sensor id.
func newID() string {
	return uuid.NewString()
}

// validateTarget guards against SQL/host injection-ish junk in targets.
var targetRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^\d{1,3}(\.\d{1,3}){3}$`)

func validTarget(t string) bool {
	return targetRe.MatchString(t)
}

var _ = sql.ErrNoRows // keep database/sql import for callers
