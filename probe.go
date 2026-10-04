package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
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
	sensors map[string]*ProbeState
	mu      sync.Mutex
	loops   map[string]context.CancelFunc
	db      *DB
}

func NewProbeWorker(db *DB) *ProbeWorker {
	return &ProbeWorker{
		sensors: make(map[string]*ProbeState),
		loops:   make(map[string]context.CancelFunc),
		db:      db,
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
		configs = append(configs, c)
	}
	rows.Close()

	// ONE batched tag query after the loop — never a per-sensor query inside
	// rows.Next(): the outer iteration holds a pooled connection, and nested
	// per-row queries starve the pool (deadlock risk under concurrency).
	ids := make([]string, len(configs))
	for i := range configs {
		ids[i] = configs[i].id
	}
	tagMap := pw.db.SensorTagsFor(ids)
	for i := range configs {
		configs[i].tags = tagMap[configs[i].id]
	}

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
		// No transition: a sustained ERROR may be due for a re-alert.
		// Warning is never re-alerted (loss flapping is dashboard noise).
		if newStatus == "error" {
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
		note = "recovered" // first transition back to up after warning/error
	}
	if _, err := pw.db.Exec("INSERT INTO events (sensor_id, ts, from_status, to_status, note) VALUES (?, ?, ?, ?, ?)",
		c.id, time.Now().UTC().Format(time.RFC3339Nano), oldStatus, newStatus, note); err != nil {
		log.Printf("ProbeWorker: failed to record event for %s: %v", c.id, err)
	}

	pw.setAlertState(c.id, newStatus, time.Now().UTC())
	// Warning (loss) is dashboard-only; error transitions and recoveries
	// alert.
	if pw.shouldAlertNow(c, newStatus) {
		go pw.sendAlert(c.id, c.name, c.target, newStatus, rttMs)
	}
}

// alertsEnabled reports whether any alert may fire: maintenance mode
// silences everything.
func (pw *ProbeWorker) alertsEnabled() bool {
	return pw.db.GetSetting("maintenance_mode") != "1"
}

// alertable reports whether a transition INTO this status sends an alert.
// Warning (packet loss) is dashboard-only by design — loss flapping was
// alert noise. Error and recovery (up) alert.
func alertable(status string) bool { return status != "warning" }

// shouldAlertNow applies the maintenance gate, the status gate (warning is
// dashboard-only — see alertable), and the global alert routing rule
// (settings table): "all", "tags" (any of the sensor's tags in filter list),
// or "sensors" (id in filter list).
func (pw *ProbeWorker) shouldAlertNow(c sensorConfig, status string) bool {
	if !pw.alertsEnabled() {
		return false
	}
	if !alertable(status) {
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

// statusWindow is the fixed probe count used for loss% detection.
// At the default 15s interval it is ~15 min of history.
const statusWindow = 60

// Status is derived from the sensor's most recent probes with fixed precedence:
//
//	error     — `down_after` consecutive losses from the newest probe
//	warning   — window loss% (last `statusWindow` probes) >= loss_warn
//	up        — the newest 2 probes both succeeded and loss% is below
//	            loss_warn (a sensor with only one probe is up if that
//	            probe succeeded)
//
// The window read is max(statusWindow, down_after) rows so that a sensor
// configured with down_after > statusWindow still has enough history for the
// consecutive-loss test. A probe-level ICMP error (broken socket) forces
// warning so a dead probe path never reads as "up".
func (pw *ProbeWorker) deriveStatus(c sensorConfig) string {
	// Broken probe path (e.g. ICMP socket cannot be created): probes never
	// land, so we cannot know the real state — flag warning, never up.
	if probeErrCount.Load() > c.lastErrCount {
		return "warning"
	}

	// Fetch enough history for the loss% window AND the consecutive-loss
	// test, newest first.
	limit := statusWindow
	if c.downAfter > limit {
		limit = c.downAfter
	}
	rows, err := pw.db.Query("SELECT rtt_ms FROM probes WHERE sensor_id = ? ORDER BY ts DESC LIMIT ?", c.id, limit)
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

	// ERROR: down_after consecutive losses from the newest probe.
	consec := 0
	for _, r := range recent {
		if r == nil {
			consec++
		} else {
			break
		}
	}
	if consec >= c.downAfter {
		return "error"
	}

	// WARNING: loss% over the status window meets loss_warn.
	totalLost := 0
	for _, r := range recent {
		if r == nil {
			totalLost++
		}
	}
	if c.lossWarn > 0 {
		lossPct := float64(totalLost) / float64(len(recent)) * 100
		if lossPct >= float64(c.lossWarn) {
			return "warning"
		}
	}

	// UP: the newest 2 probes both succeeded. With only one probe recorded,
	// a single success is enough (new-sensor grace).
	if recent[0] != nil && (len(recent) == 1 || recent[1] != nil) {
		return "up"
	}

	// WARNING: a loss is in the recent window but it's not error and not up.
	return "warning"
}

// purgeOld enforces 24-hour retention on probes/events (SPEC §3).
// 24h is the longest window the dashboard reads (24h graph / uptime 24h), so
// nothing on screen ever needs older data. Revisit if historical reporting
// is added later.
func (pw *ProbeWorker) purgeOld() {
	cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339Nano)
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

// ---------- alert destinations (multi-provider) ----------
//
// Each provider (google_chat, discord) has its own URL setting and an
// explicit enable flag. Alerts fan out to EVERY active provider. The
// registry is the single source of truth for "which providers exist", so a
// future provider (Slack, ntfy, …) is one entry in this slice plus a card
// builder — the send path, migration, and UI all derive from it.
//
// google_chat is the legacy provider: before this it was THE webhook. Its
// enable flag defaults to ON when a URL is present (dashboard or the
// GOOGLE_CHAT_WEBHOOK_URL env) so existing installs keep alerting with zero
// config; a fresh install has no URL and no flag, so it stays off.

type providerMeta struct {
	Kind        string // settings key prefix: google_chat, discord
	Label       string // display name
	URLField    string // JSON field the settings payload uses
	Placeholder string // input placeholder
	EnvFallback string // env var that supplies a URL when the dashboard one is empty ("") = none
	Enabled     func(db *DB) bool
	HasURL      func(db *DB) bool
}

var providerList = []providerMeta{
	{
		Kind: "google_chat", Label: "Google Chat", URLField: "google_chat_url",
		Placeholder: "https://chat.googleapis.com/v1/spaces/…/messages?key=…",
		EnvFallback: "GOOGLE_CHAT_WEBHOOK_URL",
		Enabled:     chatEnabled,
		HasURL:      chatHasURL,
	},
	{
		Kind: "discord", Label: "Discord", URLField: "discord_url",
		Placeholder: "https://discord.com/api/webhooks/…/…",
		EnvFallback: "",
		Enabled:     flagEnabled("discord"),
		HasURL:      flagHasURL("discord"),
	},
}

func providerByKey(kind string) (providerMeta, bool) {
	for _, p := range providerList {
		if p.Kind == kind {
			return p, true
		}
	}
	return providerMeta{}, false
}

// chatEnabled: google_chat's legacy default. Explicitly enabled ("1") wins;
// explicitly disabled ("0") wins; with no flag, a present URL (dashboard or
// env) keeps it active so an upgrade changes nothing. Fresh install: no URL,
// no flag → off.
func chatEnabled(db *DB) bool {
	switch db.GetSetting("google_chat_enabled") {
	case "1":
		return true
	case "0":
		return false
	}
	return chatHasURL(db)
}

// chatHasURL: the dashboard URL, falling back to the GOOGLE_CHAT_WEBHOOK_URL
// env (the pre-multi-provider mechanism, kept working).
func chatHasURL(db *DB) bool {
	if db.GetSetting("google_chat_url") != "" {
		return true
	}
	return os.Getenv("GOOGLE_CHAT_WEBHOOK_URL") != ""
}

// flagEnabled / flagHasURL: a generic provider — explicit "1" flag and a
// non-empty URL. No env fallback, no legacy default. Built as closures over
// the provider kind so each entry is self-contained.
func flagEnabled(kind string) func(db *DB) bool {
	return func(db *DB) bool { return db.GetSetting(kind+"_enabled") == "1" }
}
func flagHasURL(kind string) func(db *DB) bool {
	return func(db *DB) bool { return db.GetSetting(kind+"_url") != "" }
}

// activeProviders returns every provider currently receiving alerts.
func (pw *ProbeWorker) activeProviders() []providerMeta {
	var out []providerMeta
	for _, p := range providerList {
		if p.Enabled(pw.db) && p.HasURL(pw.db) {
			out = append(out, p)
		}
	}
	return out
}

// providerStatus is the per-provider read the settings API returns to the
// dashboard.
type providerStatus struct {
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	HasURL  bool   `json:"has_url"`
	URL     string `json:"url"` // masked; empty when none
	Source  string `json:"source"`
}

func (pw *ProbeWorker) providerStatuses() []providerStatus {
	out := []providerStatus{}
	for _, p := range providerList {
		url := pw.db.GetSetting(p.Kind + "_url")
		source := "none"
		if url != "" {
			source = "dashboard"
		} else if p.EnvFallback != "" && os.Getenv(p.EnvFallback) != "" {
			url = os.Getenv(p.EnvFallback)
			source = "env"
		}
		out = append(out, providerStatus{
			Kind:    p.Kind,
			Enabled: p.Enabled(pw.db),
			HasURL:  url != "",
			URL:     webhookMasked(url),
			Source:  source,
		})
	}
	return out
}

func (pw *ProbeWorker) sendWebhook(id, name, target, state string, rttMs float64, reAlert bool) {
	for _, p := range pw.activeProviders() {
		url := pw.db.GetSetting(p.Kind + "_url")
		if url == "" && p.EnvFallback != "" {
			url = os.Getenv(p.EnvFallback)
		}
		if url == "" {
			continue
		}
		switch p.Kind {
		case "google_chat":
			card := cardFor(state, name, target, rttMs)
			if reAlert {
				card = cardForRe(state, name, target, rttMs)
			}
			pw.postJSON(url, map[string]string{"text": card})
		case "discord":
			card := discordCard(state, name, target, rttMs)
			if reAlert {
				card = discordCardRe(state, name, target, rttMs)
			}
			pw.postJSON(url, map[string]string{"content": card})
		}
	}
}

// TestWebhook sends a test message to ONE provider and reports whether it
// accepted it. kind is required (the dashboard tests the provider whose URL
// is being verified).
func (pw *ProbeWorker) TestWebhook(kind string) (bool, string) {
	p, ok := providerByKey(kind)
	if !ok {
		return false, "unknown provider"
	}
	url := pw.db.GetSetting(p.Kind + "_url")
	if url == "" && p.EnvFallback != "" {
		url = os.Getenv(p.EnvFallback)
	}
	if url == "" {
		return false, "no " + p.Label + " webhook URL configured"
	}
	var body map[string]string
	if p.Kind == "discord" {
		body = map[string]string{"content": "🟢 **zenmon: test alert**\nSensor: settings · Target: webhook-verify · State: **test** — your Discord webhook works."}
	} else {
		body = map[string]string{"text": "🟢 *zenmon: test alert*\n*Sensor*: settings\n*Target*: webhook-verify\n*State*: **test** — this message confirms your " + p.Label + " webhook works."}
	}
	resp, err := webhookClient.Post(url, "application/json", bytes.NewReader(mustJSON(body)))
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return false, "endpoint redirected (refused to follow — possible misconfiguration)"
	}
	if resp.StatusCode >= 300 {
		return false, fmt.Sprintf("endpoint returned HTTP %d", resp.StatusCode)
	}
	return true, "test alert sent via " + p.Label + " (HTTP " + http.StatusText(resp.StatusCode) + ")"
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// sendAlert dispatches a state-transition alert to every active provider.
func (pw *ProbeWorker) sendAlert(id, name, target, state string, rttMs float64) {
	pw.sendWebhook(id, name, target, state, rttMs, false)
}

// sendRealert notifies that a sensor has stayed in the same non-up state.
func (pw *ProbeWorker) sendRealert(id, name, target, state string, rttMs float64) {
	pw.sendWebhook(id, name, target, state, rttMs, true)
}

func cardFor(state, name, target string, rttMs float64) string {
	icon := map[string]string{"up": "🟢", "warning": "🟡", "error": "🔴"}[state]
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
	icon := map[string]string{"warning": "🟡", "error": "🔴"}[state]
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

// Discord uses Markdown (**bold**, no *italic* emphasis); the card is plain
// content. Same information, Discord-flavored.
func discordCard(state, name, target string, rttMs float64) string {
	icon := map[string]string{"up": "🟢", "warning": "🟡", "error": "🔴"}[state]
	if icon == "" {
		icon = "🟢"
	}
	title := state
	if state == "up" {
		title = "recovered"
	}
	card := fmt.Sprintf("%s **zenmon: %s**\n**Sensor:** %s\n**Target:** %s\n**State:** %s", icon, title, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n**Ping:** %d ms", int(rttMs+0.5))
	}
	return card
}

func discordCardRe(state, name, target string, rttMs float64) string {
	icon := map[string]string{"warning": "🟡", "error": "🔴"}[state]
	if icon == "" {
		icon = "🟢"
	}
	card := fmt.Sprintf("%s **zenmon: still %s (re-alert)**\n**Sensor:** %s\n**Target:** %s\n**State:** %s — no change, re-notifying", icon, state, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n**Ping:** %d ms", int(rttMs+0.5))
	}
	return card
}

// postJSON delivers a JSON payload to a webhook with the shared hardened
// client (10s timeout, no redirects).
func (pw *ProbeWorker) postJSON(url string, payload map[string]string) {
	body, _ := json.Marshal(payload)
	resp, err := webhookClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("webhook: send failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		log.Printf("webhook: endpoint redirected (refused to follow — possible misconfiguration)")
		return
	}
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
