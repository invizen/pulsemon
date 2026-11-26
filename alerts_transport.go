package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"pulsemon/internal/store"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// resolveDestinationsFromDB resolves the active, URL-configured providers
// (with the Telegram chat_id) from the DB — the single place that turns
// raw provider settings into delivery destinations, run at snapshot-load
// time so the hot path reads the result lock-free. Every key — Enabled,
// HasURL, URL, chat_id — is evaluated fail-loud from ONE bulk settings
// read (getAllSettings): a real read failure aborts the load (the caller
// keeps the previous snapshot), for EVERY key. Swallowing Enabled/HasURL
// (GetSetting) let a transient lock silently DROP a provider from an
// installed snapshot — alerts for it stopped until the next settings
// save: the exact half-read state the snapshot design forbids.
// History: docs/DECISIONS.md → provider-reads-bulk-fail-loud.
func resolveDestinationsFromDB(db *store.Store) ([]dest, error) {
	m, err := getAllSettings(db)
	if err != nil {
		return nil, err
	}
	return resolveDestsGet(func(k string) (string, error) { return m[k], nil })
}

func resolveDestsGet(get settingGet) ([]dest, error) {
	var dests []dest
	for _, p := range providerList {
		en, err := p.enabledGet(get)
		if err != nil {
			return nil, err
		}
		hu, err := p.hasURLGet(get)
		if err != nil {
			return nil, err
		}
		if !en || !hu {
			continue
		}
		// p.URLField, NOT p.Kind + "_url": SMTP's value lives in
		// "smtp_host", and a "smtp_url" lookup returns "" for every real
		// SMTP config — silently skipping email (see resolveDestinations).
		url, err := get(p.URLField)
		if err != nil {
			return nil, err
		}
		if url == "" && p.EnvFallback != "" {
			url = os.Getenv(p.EnvFallback)
		}
		if url == "" {
			continue
		}
		var chatID string
		if p.Kind == "telegram" {
			// Resolved up front, error-aware: a transient DB lock must
			// fail the load (and keep the previous snapshot), never post
			// an empty chat_id (Telegram 400).
			chatID, err = get("telegram_chat_id")
			if err != nil || chatID == "" {
				return nil, err
			}
		}
		d := dest{p: p, url: url, chatID: chatID}
		if p.Kind == "smtp" {
			// The full mail config resolves here with the URL/chat_id
			// (one bulk read, fail-loud): delivery then performs ZERO
			// settings reads. The old live smtpConfig() did 7 swallow-to-""
			// GetSetting calls per send — a transient lock degraded into
			// "not configured", which the retry loop skips as permanent.
			cfg, err := smtpConfigFromGet(get)
			if err != nil {
				return nil, err
			}
			d.smtp = &cfg
		}
		dests = append(dests, d)
	}
	return dests, nil
}

type providerMeta struct {
	Kind        string // settings key prefix: google_chat, discord
	Label       string // display name
	URLField    string // JSON field the settings payload uses
	Placeholder string // input placeholder
	EnvFallback string // env var that supplies a URL when the dashboard one is empty ("") = none
	// The canonical predicates take a settingGet so each provider's
	// enabled/has-URL logic lives in EXACTLY ONE place and can be
	// evaluated fail-loud against any read source: the bulk-map adapter
	// (snapshot load + settings GET) or db.GetSettingErr (TestWebhook).
	// The old bool, GetSetting-swallowing predicates survive only as free
	// functions for the test suite; production reads all go through these.
	enabledGet func(get settingGet) (bool, error)
	hasURLGet  func(get settingGet) (bool, error)
}

// settingGet reads one settings key. Contract: absent key is ("", nil);
// a read FAILURE is ("", err) and must abort the caller's evaluation —
// "unset" and "read failed" must never look the same on the alert paths
// (the fail-loud settings-read contract).
type settingGet = func(key string) (string, error)

// getAllSettings is the bulk-load seam (test seam, mirroring
// getSettingErr): the snapshot load and the settings GET payload evaluate
// every provider key from ONE consistent settings-table read.
var getAllSettings = func(db *store.Store) (map[string]string, error) { return db.GetAllSettings() }

var providerList = []providerMeta{
	{
		Kind: "google_chat", Label: "Google Chat", URLField: "google_chat_url",
		Placeholder: "https://chat.googleapis.com/v1/spaces/…/messages?key=…",
		EnvFallback: "GOOGLE_CHAT_WEBHOOK_URL",
		enabledGet:  chatEnabledGet,
		hasURLGet:   chatHasURLGet,
	},
	{
		Kind: "discord", Label: "Discord", URLField: "discord_url",
		Placeholder: "https://discord.com/api/webhooks/…/…",
		EnvFallback: "",
		enabledGet:  flagEnabledGet("discord"),
		hasURLGet:   flagHasURLGet("discord"),
	},
	{
		Kind: "telegram", Label: "Telegram", URLField: "telegram_url",
		Placeholder: "https://api.telegram.org/bot<TOKEN>/sendMessage",
		EnvFallback: "",
		enabledGet:  flagEnabledGet("telegram"),
		hasURLGet:   telegramHasURLGet,
	},
	{
		Kind: "smtp", Label: "Email (SMTP)", URLField: "smtp_host",
		Placeholder: "smtp.example.com",
		EnvFallback: "",
		enabledGet:  smtpEnabledGet,
		hasURLGet:   smtpHasURLGet,
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

// chatEnabledGet: google_chat's legacy default. Explicitly enabled ("1")
// wins; explicitly disabled ("0") wins; with no flag, a present URL
// (dashboard or env) keeps it active so an upgrade changes nothing. Fresh
// install: no URL, no flag → off. (The swallow-to-"" twins the test suite
// uses live in provider_predicates_test.go — every
// production read uses these *Get predicates so a settings read failure
// aborts the caller instead of reading as "provider unset"; 2026-11-13
// review, closing the Enabled/HasURL half of the class the 2026-10-30
// chat_id fix opened.)
func chatEnabledGet(get settingGet) (bool, error) {
	v, err := get("google_chat_enabled")
	if err != nil {
		return false, err
	}
	switch v {
	case "1":
		return true, nil
	case "0":
		return false, nil
	}
	return chatHasURLGet(get)
}

// chatHasURLGet: the dashboard URL, falling back to the
// GOOGLE_CHAT_WEBHOOK_URL env (the pre-multi-provider mechanism, kept
// working).
func chatHasURLGet(get settingGet) (bool, error) {
	v, err := get("google_chat_url")
	if err != nil {
		return false, err
	}
	if v != "" {
		return true, nil
	}
	return os.Getenv("GOOGLE_CHAT_WEBHOOK_URL") != "", nil
}

// flagEnabledGet / flagHasURLGet: a generic provider — explicit "1" flag
// and a non-empty URL. No env fallback, no legacy default. Built as
// closures over the provider kind so each entry is self-contained.
func flagEnabledGet(kind string) func(settingGet) (bool, error) {
	return func(get settingGet) (bool, error) {
		v, err := get(kind + "_enabled")
		return v == "1", err
	}
}

func flagHasURLGet(kind string) func(settingGet) (bool, error) {
	return func(get settingGet) (bool, error) {
		v, err := get(kind + "_url")
		return v != "", err
	}
}

// telegramHasURLGet: Telegram needs BOTH the bot endpoint and a chat_id
// to deliver; a URL alone can't reach anyone.
func telegramHasURLGet(get settingGet) (bool, error) {
	u, err := get("telegram_url")
	if err != nil {
		return false, err
	}
	c, err := get("telegram_chat_id")
	if err != nil {
		return false, err
	}
	return u != "" && c != "", nil
}

// providerStatus is the per-provider read the settings API returns to the
// dashboard.
type providerStatus struct {
	Kind    string            `json:"kind"`
	Enabled bool              `json:"enabled"`
	HasURL  bool              `json:"has_url"`
	URL     string            `json:"url"` // masked; empty when none
	Source  string            `json:"source"`
	Extra   map[string]string `json:"extra,omitempty"` // non-secret fields (e.g. telegram chat_id)
}

// providerExtraGet returns a provider's non-secret, non-URL fields for the
// dashboard to pre-fill. chat_id is not a credential — the token lives in
// the masked URL — so it is returned in the clear. Reads go through the
// settingGet contract (see providerMeta): every read is fail-loud, and
// the fixed slice order keeps the read order deterministic.
func providerExtraGet(p providerMeta, get settingGet) (map[string]string, error) {
	if p.Kind == "telegram" {
		cid, err := get("telegram_chat_id")
		if err != nil {
			return nil, err
		}
		if cid != "" {
			return map[string]string{"chat_id": cid}, nil
		}
	}
	if p.Kind == "smtp" {
		extra := map[string]string{}
		for _, kf := range [][2]string{
			{"smtp_port", "port"}, {"smtp_from", "from"}, {"smtp_to", "to"},
			{"smtp_username", "username"}, {"smtp_tls_mode", "tls_mode"},
		} {
			v, err := get(kf[0])
			if err != nil {
				return nil, err
			}
			if v != "" {
				extra[kf[1]] = v
			}
		}
		// The password is never returned in the clear. A stored password is
		// surfaced as a fixed mask ("••••••••") so the UI knows the field is
		// filled; the save path treats the mask as "unchanged" and omits it.
		pw, err := get("smtp_password")
		if err != nil {
			return nil, err
		}
		if pw != "" {
			extra["password"] = "••••••••"
		}
		if len(extra) > 0 {
			return extra, nil
		}
	}
	return nil, nil
}

// providerStatuses builds the per-provider view for the settings API.
// Every key comes from ONE bulk settings read and every read is fail-loud
// settingsPayload() aborts on a transient DB failure
// for its own fields via GetSettingErr — a swallowed provider read here
// used to answer 200 with providers claiming enabled:false/has_url:false,
// a payload the settings PUT can echo back and write.
func (pw *ProbeWorker) providerStatuses() ([]providerStatus, error) {
	m, err := getAllSettings(pw.db)
	if err != nil {
		return nil, err
	}
	get := func(k string) (string, error) { return m[k], nil }
	out := []providerStatus{}
	for _, p := range providerList {
		// p.URLField is the canonical read (SMTP's display "URL" is
		// smtp_host, which the providerList literal already declares).
		url := m[p.URLField]
		source := "none"
		if url != "" {
			source = "dashboard"
		} else if p.EnvFallback != "" && os.Getenv(p.EnvFallback) != "" {
			url = os.Getenv(p.EnvFallback)
			source = "env"
		}
		en, err := p.enabledGet(get)
		if err != nil {
			return nil, err
		}
		hu, err := p.hasURLGet(get)
		if err != nil {
			return nil, err
		}
		extra, err := providerExtraGet(p, get)
		if err != nil {
			return nil, err
		}
		out = append(out, providerStatus{
			Kind:    p.Kind,
			Enabled: en,
			HasURL:  hu,
			URL:     webhookMasked(url),
			Source:  source,
			Extra:   extra,
		})
	}
	return out, nil
}

// sendWebhook delivers one alert to every active provider and reports
// whether it was delivered. The delivery is queued on the sensor's alertGate
// FIFO so one sensor's alerts run strictly in launch order (a retried
// "error" must never land after that sensor's "recovered" alert — the chat's
// last word must match its current state), and the caller blocks until it
// finishes (tracked in alertWG, so DrainAlerts sees true completion).
func (pw *ProbeWorker) sendWebhook(id, name, target, oldState, state string, rttMs float64, reAlert bool) bool {
	// Storm budget: over-budget transitions coalesce into the storm summary
	// (reports "delivered" — the summary carries it, the caller schedules no
	// retry). Re-alerts (oldState == state) never ride the budget: they are
	// the operator's re-alert cadence, and coalescing them would burn
	// transition budget and render bogus "svc: error -> error" lines.
	// History: docs/DECISIONS.md → storm-summary-edges.
	if !reAlert && !pw.stormAdmit(id, name, target, oldState, state, rttMs) {
		return true
	}
	done := make(chan bool, 1)
	if !pw.enqueueAlert(id, func() {
		// Guarantee a `done` value even if the delivery panics: a skipped
		// send would park this caller on `<-done` forever and leak its
		// alertWG count; the buffer-1 channel makes the defer exact (the
		// normal send fills it, on panic the defer is the sole writer).
		defer func() {
			select {
			case done <- false:
			default:
			}
		}()
		done <- pw.sendWebhookDeliver(id, name, target, oldState, state, rttMs, reAlert)
	}) {
		// FIFO full (provider degradation): dropped, not delivered — report
		// false so the caller schedules its 1-minute retry.
		return false
	}
	select {
	case ok := <-done:
		return ok
	case <-pw.stopCtx.Done():
		// Shutdown began before the FIFO reached this job: abort the wait so
		// this caller releases its alertWG count (no full-backstop park).
		return false
	}
}

// dest is one configured provider with its resolved URL (a webhook POST
// target, or the SMTP host for the smtp kind). chatID carries the
// Telegram chat_id, resolved in resolveDestinations with the same
// error-awareness as the URL: the old code re-read it live in the
// delivery goroutine via the swallow-to-"" GetSetting, so a transient
// DB lock at delivery time posted an empty chat_id (Telegram 400) —
// fatal on the storm-summary path, which has no retry.
type dest struct {
	p      providerMeta
	url    string
	chatID string      // telegram only; "" for every other kind
	smtp   *smtpConfig // smtp kind only, resolved at snapshot load; nil elsewhere
}

// getSettingErr is the settings read resolveDestinations uses for the
// provider URLs and the Telegram chat_id. A var so tests can simulate a
// transient read failure on a specific key (same seam idiom as smtpDial);
// production is a plain DB read.
var getSettingErr = func(db *store.Store, key string) (string, error) { return db.GetSettingErr(key) }

// resolveDestinations returns the active, configured providers with their
// URLs (and, for telegram, the chat_id) from the settings SNAPSHOT. It is
// lock-free: the destinations are resolved at snapshot-load time (worker
// start + every PUT /api/settings commit), so the delivery path performs
// ZERO settings reads. ok is always true — the snapshot is never nil (a
// default is stored before the first load), so there is no "unreadable"
// state to report. The delivery job calls it through the deliverDestinations
// seam so the panic-recovery test can force a job-level panic.
func (pw *ProbeWorker) resolveDestinations() ([]dest, bool) {
	return pw.alertSettings().dests, true
}

// deliverDestinations is the seam the delivery job uses to resolve
// destinations; a var so the panic-recovery test (sendwebhook_panic_test.go)
// can force a JOB-LEVEL panic in sendWebhookDeliver — the m1 done-channel
// guarantee — independent of the per-provider recovers. Production is a
// plain snapshot read.
var deliverDestinations = func(pw *ProbeWorker) ([]dest, bool) { return pw.resolveDestinations() }

// sendWebhookDeliver delivers one alert to every active provider IN
// PARALLEL (a slow endpoint must not delay the others) and reports whether
// it was delivered: true when at least one provider accepted it, or when
// none is configured (there is nothing to retry); false only when every
// configured provider failed after its retries, so the caller can schedule
// another attempt.
func (pw *ProbeWorker) sendWebhookDeliver(id, name, target, oldState, state string, rttMs float64, reAlert bool) bool {
	// Resolve every provider destination from the SNAPSHOT before
	// delivering anything: a transient DB lock can no longer make every
	// provider look unset and the alert silently dropped (the old
	// swallow-to-"" GetSetting). Resolving up front also means no provider
	// has fired yet when we bail.
	dests, ok := deliverDestinations(pw)
	if !ok {
		// The snapshot is never nil in practice, so this is defensive: an
		// empty/unreadable destination list must be reported as NOT
		// delivered so the caller can retry — never "delivered" on an
		// empty provider list.
		log.Printf("alert: provider list unreadable — alert not delivered")
		return false
	}
	var wg sync.WaitGroup
	var delivered atomic.Bool
	for _, d := range dests {
		wg.Add(1)
		go func(d dest) {
			defer wg.Done()
			defer alertPanicRecovered("deliver-" + d.p.Kind)
			if pw.deliverOne(d, name, target, oldState, state, rttMs, reAlert) {
				delivered.Store(true)
			}
		}(d)
	}
	wg.Wait()
	return len(dests) == 0 || delivered.Load()
}

// deliverOne sends one alert to one provider and reports success. The dest
// carries everything resolved up front in resolveDestinations (URL and, for
// telegram, the chat_id) — deliverOne must not re-read settings live: a
// transient DB lock at delivery time would otherwise degrade into a
// half-configured payload
func (pw *ProbeWorker) deliverOne(d dest, name, target, oldState, state string, rttMs float64, reAlert bool) bool {
	p, url := d.p, d.url
	switch p.Kind {
	case "google_chat":
		card := cardFor(oldState, state, name, target, rttMs)
		if reAlert {
			card = cardForRe(state, name, target, rttMs)
		}
		return pw.postJSON(url, map[string]any{"text": card}) == nil
	case "discord":
		card := discordCard(oldState, state, name, target, rttMs)
		if reAlert {
			card = discordCardRe(state, name, target, rttMs)
		}
		// allowed_mentions.parse = []: never let
		// card text trigger role/user mentions — a sensor named
		// "@everyone" would otherwise mass-ping the channel. Pairs with
		// discordMentionSafe, which covers clients that ignore the field.
		return pw.postJSON(url, map[string]any{
			"content":          card,
			"allowed_mentions": map[string]any{"parse": []string{}},
		}) == nil
	case "telegram":
		card := telegramCard(oldState, state, name, target, rttMs)
		if reAlert {
			card = telegramCardRe(state, name, target, rttMs)
		}
		// d.chatID was resolved up front in resolveDestinations (see
		// dest): a live re-read here would map a transient DB lock to ""
		// and Telegram would 400 the message.
		return pw.postJSON(url, map[string]any{
			"chat_id":    d.chatID,
			"text":       card,
			"parse_mode": "HTML",
		}) == nil
	case "smtp":
		// SMTP is not a webhook POST — it dials the mail server. The url
		// variable is the host here (URLField: smtp_host); delivery is a
		// plain-text email via sendSMTP.
		subject := smtpSubject(oldState, state)
		body := smtpBody(oldState, state, name, target, rttMs)
		if reAlert {
			subject = smtpSubject(state, state) + " (re-alert)"
			body = smtpBodyRe(state, name, target, rttMs)
		}
		if d.smtp == nil {
			log.Printf("smtp alert to %s: dest carries no resolved config", url)
			return false
		}
		err := pw.retryAlert(func() (bool, time.Duration, error) {
			err := pw.sendSMTPWith(pw.stopCtx, *d.smtp, subject, body)
			// A configuration gap and a permanent 5xx refusal (535 auth,
			// 550, 554) cannot succeed on retry — a 535 re-hit is a
			// fail2ban/lockout factory. SMTP has no Retry-After: 0 keeps
			// the fixed alertRetryDelays.
			if err != nil && (errors.Is(err, errSMTPNotConfigured) || smtpPermanent(err)) {
				return false, 0, err
			}
			return err != nil, 0, err
		})
		if err != nil {
			log.Printf("smtp alert to %s: %v", url, err)
			return false
		}
		return true
	}
	return false
}

// TestWebhook sends a test message to ONE provider and reports whether it
// accepted it. kind is required (the dashboard tests the provider whose URL
// is being verified). ctx bounds the POST (the handler passes r.Context(),
// so an abandoned dashboard request aborts the delivery at its next read
// instead of holding the client's 10s timeout).
func (pw *ProbeWorker) TestWebhook(ctx context.Context, kind string) (bool, string) {
	p, ok := providerByKey(kind)
	if !ok {
		return false, "unknown provider"
	}
	// Error-aware settings read (getSettingErr — the same seam
	// resolveDestinations uses): the test button is where an operator
	// verifies their config, so a transient DB lock must surface as a
	// database error, not masquerade as "no <provider> webhook URL
	// configured" (the swallow-to-"" GetSetting maps a lock to an empty
	// URL). p.URLField, not p.Kind+"_url": SMTP's value lives in
	// smtp_host (url is unused for SMTP — the smtp branch below uses
	// p.hasURLGet gate + sendSMTP).
	url, err := getSettingErr(pw.db, p.URLField)
	if err != nil {
		return false, "database error reading provider settings"
	}
	if url == "" && p.EnvFallback != "" {
		url = os.Getenv(p.EnvFallback)
	}
	var smtpCfg smtpConfig
	if p.Kind == "smtp" {
		// SMTP has no URL field: ONE bulk read resolves the gate
		// (smtpHasURL: host+sender+recipient) and the send config
		// together, fail-loud through the getAllSettings seam — a
		// transient lock must surface as a database error, never
		// masquerade as "no SMTP host and recipient configured" (the
		// swallow-to-"" contract) and never half-read across the gate
		// and a second per-key read.
		m, err := getAllSettings(pw.db)
		if err != nil {
			return false, "database error reading provider settings"
		}
		get := func(k string) (string, error) { return m[k], nil }
		gate, err := p.hasURLGet(get)
		if err != nil {
			return false, "database error reading provider settings"
		}
		if !gate {
			return false, "no SMTP host and recipient configured"
		}
		smtpCfg, err = smtpConfigFromGet(get)
		if err != nil {
			return false, "database error reading provider settings"
		}
	} else if url == "" {
		return false, "no " + p.Label + " webhook URL configured"
	}
	// map[string]any, not map[string]string: the discord payload nests
	// allowed_mentions — the test-alert body must be
	// structurally identical to the production delivery payloads
	// (deliverOne / deliverStormSummary), so the test button verifies the
	// exact shape the real alerts send.
	var body map[string]any
	if p.Kind == "discord" {
		body = map[string]any{
			"content":          "✅ **pulsemon: test alert**\nSensor: settings · Target: webhook-verify · State: **test** — your Discord webhook works.",
			"allowed_mentions": map[string]any{"parse": []string{}},
		}
	} else if p.Kind == "telegram" {
		// chat_id resolved error-aware (same reason as the URL above): a
		// transient DB lock must not post an empty chat_id to Telegram
		// (HTTP 400).
		chatID, err := getSettingErr(pw.db, "telegram_chat_id")
		if err != nil {
			return false, "database error reading provider settings"
		}
		body = map[string]any{
			"chat_id":    chatID,
			"text":       "✅ <b>pulsemon: test alert</b>\n<b>Sensor:</b> settings · <b>Target:</b> webhook-verify · <b>State:</b> <b>test</b> — your Telegram bot works.",
			"parse_mode": "HTML",
		}
	} else if p.Kind == "smtp" {
		// SMTP test: send a real email (no JSON body). Returns after the
		// protocol round-trip, not the shared http.Client path below.
		subject := "✅ pulsemon: test alert"
		bodyTxt := "✅ pulsemon: test alert\nSensor: settings\nTarget: webhook-verify\nState: test — your SMTP relay works."
		if err := pw.sendSMTPWith(ctx, smtpCfg, subject, bodyTxt); err != nil {
			return false, err.Error()
		}
		return true, "test email sent via " + p.Label + " (SMTP 250 OK)"
	} else {
		body = map[string]any{"text": "✅ *pulsemon: test alert*\n*Sensor*: settings\n*Target*: webhook-verify\n*State*: **test** — this message confirms your " + p.Label + " webhook works."}
	}
	// Single transport seam with postJSON (doWebhookPost): the shared
	// hardened client, the capped drain, and the URL redaction live there.
	// TestWebhook is a cold, operator-initiated path — no retry.
	code, _, respBody, err := pw.doWebhookPost(ctx, url, mustJSON(body))
	if err != nil {
		return false, err.Error()
	}
	if code >= 300 && code < 400 {
		return false, "endpoint redirected (refused to follow — possible misconfiguration)"
	}
	if code >= 300 {
		// Surface the provider's own diagnosis (the 400+ body's
		// description — "chat not found", "migrate_to_chat_id"): the
		// test button is where the operator verifies the config, and a
		// bare status code tells them nothing to fix.
		detail := fmt.Sprintf("endpoint returned HTTP %d", code)
		if _, desc := webhookBodyDiag(respBody); desc != "" {
			detail += ": " + desc
		}
		return false, detail
	}
	return true, "test alert sent via " + p.Label + " (HTTP " + http.StatusText(code) + ")"
}

// alertRetryDelays are the pauses between delivery attempts: 3 attempts
// total (now, +2s, +10s). A var so tests can shrink or clear it.
//
// Alert-retry-budget invariant (docs/DECISIONS.md → alert-retry-budget):
// these sleeps and the maxAlertRetryAfter cap run INSIDE the sensor's
// 8-slot alert-FIFO consumer, so the worst-case single job (3 webhook
// attempts × 10s client timeout + the two in-band sleeps) must stay under
// recoveryRetryDelay (60s) — above it, a degraded provider's sustained
// re-alert arrivals outrun FIFO completions, the queue saturates, and a
// dropped recovery's re-finds a full queue a minute later: the second drop
// loses the notification permanently. Pinned by
// TestInFifoRetryBudgetUnderRecoveryRetryDelay.
var alertRetryDelays = []time.Duration{2 * time.Second, 10 * time.Second}

// redactErr strips the request URL out of a net/http error. url.Error.Error()
// embeds the full URL, and every webhook URL here carries its credential
// (Telegram bot token, Discord/Chat key), so logging or returning the raw error
// would leak the secret to journald and to the browser.
func redactErr(err error) error {
	var ue *neturl.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// maxAlertRetryAfter caps a provider's Retry-After so one hostile or buggy
// header can't park a delivery goroutine (and DrainAlerts) for hours. The
// cap is deliberately SHORT: in-band retries run on the sensor's alert-FIFO
// consumer, so every second slept here lengthens the drain of EVERY later
// alert queued for that sensor (the worst job must stay under
// recoveryRetryDelay — see alertRetryDelays). When a provider asks for a
// longer backoff than the in-band cap allows, the job fails fast and the
// OUTER retry (scheduleAlertRetry / scheduleRecoveryRetry, ~1 min) re-
// offers it on a delay that respects the provider's window better than a
// second in-FIFO sleep that also congests eight queued alerts.
// History: docs/DECISIONS.md → alert-retry-budget.
const maxAlertRetryAfter = 10 * time.Second

// retryAlert runs try until it succeeds, reports a non-retryable failure, or
// the delays are exhausted. It stops sleeping the moment shutdown begins.
// try may return a server-requested retryAfter (a 429's Retry-After): the
// pause is then max(alertRetryDelays[i], retryAfter) — a rate-limited
// provider was otherwise re-hit on our fixed 2s/10s schedule regardless of
// what it asked for.
func (pw *ProbeWorker) retryAlert(try func() (retryable bool, retryAfter time.Duration, err error)) error {
	for i := 0; ; i++ {
		retryable, retryAfter, err := try()
		if err == nil || !retryable || i >= len(alertRetryDelays) {
			return err
		}
		delay := alertRetryDelays[i]
		if retryAfter > maxAlertRetryAfter {
			retryAfter = maxAlertRetryAfter
		}
		if retryAfter > delay {
			delay = retryAfter
		}
		select {
		case <-time.After(delay):
		case <-pw.stopCtx.Done():
			return err
		}
	}
}

// doWebhookPost performs ONE webhook POST with the shared hardened client
// (10s timeout, no redirects, SSRF-guarded dial — webhookClientFor) and
// returns the response status, headers, and — on 400+ responses — the
// first 4 KiB of the body (the provider's JSON error envelope). It is the
// single transport seam for both webhook writers: postJSON (alert
// delivery, retried) and TestWebhook (the settings test button,
// single-shot). The caller passes a pre-marshaled body (postJSON marshals
// once and reuses it across retries) and owns the status classification —
// the two callers classify differently (retry policy vs UI detail
// string). The returned error never contains the URL (it carries the
// provider credential).
func (pw *ProbeWorker) doWebhookPost(ctx context.Context, url string, body []byte) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, redactErr(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookClientFor(req.URL).Do(req)
	if err != nil {
		return 0, nil, nil, redactErr(err)
	}
	defer resp.Body.Close()
	// 400+ bodies carry the provider's diagnosis (Telegram's JSON error
	// envelope: parameters.retry_after on 429, description on 400): keep
	// up to 4 KiB for the caller, then drain the rest (capped) so the
	// transport can reuse the TLS connection — closing an unread body
	// marks the conn non-reusable, so every alert paid a fresh handshake.
	var respBody []byte
	if resp.StatusCode >= 400 {
		respBody, _ = io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, respBody, nil
}

// postJSON delivers a JSON payload to a webhook with the shared hardened
// client (10s timeout, no redirects), retrying transient failures (network
// errors, 429, 5xx) per alertRetryDelays. The POST is bound to pw.stopCtx so
// that on shutdown a delivery stuck in a network blip - or sleeping between
// retries - is aborted promptly instead of holding DrainAlerts. The returned
// error never contains the URL (it carries the provider credential). The
// payload is map[string]any (not map[string]string) because the
// Discord provider needs a nested object — allowed_mentions
// which a string-valued map can't express.
func (pw *ProbeWorker) postJSON(url string, payload map[string]any) error {
	body, _ := json.Marshal(payload)
	err := pw.retryAlert(func() (bool, time.Duration, error) {
		code, header, respBody, err := pw.doWebhookPost(pw.stopCtx, url, body)
		if err != nil {
			return pw.stopCtx.Err() == nil, 0, err
		}
		switch {
		case code >= 300 && code < 400:
			return false, 0, errors.New("endpoint redirected (refused to follow — possible misconfiguration)")
		case code == http.StatusTooManyRequests:
			// Honor the provider's Retry-After: the HTTP header first,
			// the JSON body's parameters.retry_after as fallback
			// (Telegram sends the flood-wait in the body, not a header).
			retryAfter := parseRetryAfter(header.Get("Retry-After"), time.Now())
			if retryAfter == 0 {
				if secs, _ := webhookBodyDiag(respBody); secs > 0 {
					retryAfter = time.Duration(secs) * time.Second
				}
			}
			return true, retryAfter, fmt.Errorf("endpoint returned %d", code)
		case code >= 500:
			return true, 0, fmt.Errorf("endpoint returned %d", code)
		case code >= 300:
			return false, 0, webhookStatusErr(code, respBody)
		}
		return false, 0, nil
	})
	if err != nil {
		log.Printf("webhook: send failed: %v", err)
	}
	return err
}

// webhookBodyDiag extracts the diagnostics from a provider error body:
// parameters.retry_after (Telegram's flood-wait seconds, sent in the JSON
// body when no Retry-After header is) and a truncated description for
// logs and the TestWebhook detail. Non-JSON or foreign shapes yield
// (0, ""). The description is capped at 200 runes: it is provider prose
// echoed into journald and the dashboard toast, not a secret (the
// credential rides the URL), but a verbose body must not bloat them.
func webhookBodyDiag(body []byte) (retryAfterSecs int, description string) {
	if len(body) == 0 {
		return 0, ""
	}
	var env struct {
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return 0, ""
	}
	d := env.Description
	if utf8.RuneCountInString(d) > 200 {
		d = string([]rune(d)[:200]) + "…"
	}
	return env.Parameters.RetryAfter, d
}

// webhookStatusErr renders the non-retryable 4xx classification with the
// provider's own diagnosis (the body's description — "chat not found",
// "migrate_to_chat_id") when present: a misconfigured Telegram chat used
// to report only "endpoint returned 400", which told the operator nothing.
func webhookStatusErr(code int, body []byte) error {
	if _, desc := webhookBodyDiag(body); desc != "" {
		return fmt.Errorf("endpoint returned %d: %s", code, desc)
	}
	return fmt.Errorf("endpoint returned %d", code)
}

// parseRetryAfter parses a Retry-After header value — integer seconds or an
// HTTP-date (relative to now) — into a duration. Unparseable, empty, or
// past values yield 0 (fall back to the fixed schedule). retryAlert applies
// the maxAlertRetryAfter cap.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		if secs > int(maxAlertRetryAfter/time.Second) {
			return maxAlertRetryAfter
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}
