package main

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"unicode/utf8"
)

// discordContentMax / telegramTextMax / googleChatMax are the providers'
// message-content limits (the text field, not the whole request): Discord
// 2,000 characters, Telegram sendMessage 4,096, Google Chat 4,096.
// Exceeding them is a non-retryable HTTP 400 — the provider rejects the
// WHOLE message — so an unbounded storm summary (a 50-sensor rack outage
// easily exceeds 2,000) silently dropped the operator's only outage
// alert. The formatters cap their output per provider; the overflow is
// reported as a "… and N more" footer. Vars so a test can shrink them
// without rendering 40-sensor bodies.
var (
	discordContentMax = 2000
	telegramTextMax   = 4096
	googleChatMax     = 4096
)

// truncateSummaryLines renders a storm summary: header, then one line per
// sensor, capped at maxRunes (0 = uncapped). When the next line would push
// the body over the cap, the remaining lines are replaced with a
// "… and N more" footer — the body stays under the provider's limit, so
// the post is accepted and the operator sees the outage (the first N lines
// name the sensors; the header still counts ALL of them). The cap is on
// RUNES, not bytes: the summaries are operator-facing prose and the
// provider limits are character-based.
func truncateSummaryLines(header string, lines []string, maxRunes int) string {
	var b strings.Builder
	b.WriteString(header)
	runes := utf8.RuneCountInString(header)
	shown := 0
	// The worst-case footer (the "\n… and N more" at the FULL line count)
	// is reserved up front: without the reservation a body ending exactly
	// at maxRunes gets the footer appended on top, the "capped" output
	// exceeds the provider's limit, and the provider rejects the WHOLE
	// summary with a non-retryable HTTP 400.
	limit := maxRunes - utf8.RuneCountInString(fmt.Sprintf("\n… and %d more", len(lines)))
	for _, line := range lines {
		lineRunes := utf8.RuneCountInString(line)
		if maxRunes > 0 && runes+1+lineRunes > limit {
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

// stormSummaryLine renders one entry as a readable transition for the
// non-Markdown summary paths (Telegram HTML, SMTP plain), with the same
// hygiene as the per-sensor cards: credentials stripped (F22). Mention
// tokens are NOT neutralized here: those paths carry the name verbatim, and
// the invisible \u200b discordMentionSafe injects is pointless there and
// corrupts copy-paste in email clients / renders as tofu in non-UTF-8
// readers. The Markdown path (stormSummaryMarkdown)
// builds its own line so it can escape the name without escaping the URL
// target
func stormSummaryLine(e stormEntry) string {
	return fmt.Sprintf("%s: %s → %s (%s)", e.name, e.oldState, e.state, alertTarget(e.target))
}

// stormSummaryCountNoun is the header's verb phrase per direction: a down
// storm is a batch of state changes, a recovery storm a batch of recovered
// sensors (a partial recovery's line shows "error → warning" verbatim).
func stormSummaryCountNoun(recovery bool) string {
	if recovery {
		return "recovered"
	}
	return "changed state"
}

// stormSummaryMarkdown renders the summary for google_chat / discord.
// maxRunes is the destination provider's content cap (googleChatMax /
// discordContentMax); 0 = uncapped (see truncateSummaryLines).
func stormSummaryMarkdown(entries []stormEntry, maxRunes int, recovery bool) string {
	header := stormSummaryHeader("⚠️ *pulsemon: alert storm — %d sensors changed state (coalesced to limit alert noise)*",
		"✅ *pulsemon: recovery storm — %d sensors recovered (coalesced to limit alert noise)*", recovery, len(entries))
	lines := make([]string, len(entries))
	for i, e := range entries {
		// Escape the emphasis chars in the NAME only (free text — a name like
		// db_primary_01 would otherwise render "primary" in italics, and a raw *
		// in the name renders as literal formatting), with mention tokens
		// neutralized. The TARGET is a URL/hostname and stays VERBATIM: mdEscape
		// would inject backslashes into _ and ~ in the path and break the clickable
		// link — but it IS mention-neutralized, exactly like the per-sensor
		// discordCard/discordCardRe: a target path like https://example.com/@every-
		// one would mass-ping the channel on clients that ignore
		// allowed_mentions.parse = []. The emphasis markers come from the format
		// string.
		// History: docs/DECISIONS.md → storm-summary-target-mention-safe.
		lines[i] = "*" + mdEscape(discordMentionSafe(e.name)) + ": " + e.oldState + " → " + e.state + " (" + discordMentionSafe(alertTarget(e.target)) + ")*"
	}
	return truncateSummaryLines(header, lines, maxRunes)
}

// stormSummaryHTML renders the summary for telegram (html-escaped).
// maxRunes is the provider cap (telegramTextMax); 0 = uncapped. The cap is
// measured on the ESCAPED output — that is what Telegram counts.
func stormSummaryHTML(entries []stormEntry, maxRunes int, recovery bool) string {
	header := html.EscapeString(stormSummaryHeader(
		"⚠️ pulsemon: alert storm — %d sensors changed state (coalesced to limit alert noise)",
		"✅ pulsemon: recovery storm — %d sensors recovered (coalesced to limit alert noise)", recovery, len(entries)))
	lines := make([]string, len(entries))
	for i, e := range entries {
		lines[i] = html.EscapeString(stormSummaryLine(e))
	}
	return truncateSummaryLines(header, lines, maxRunes)
}

// stormSummaryPlain renders the summary for SMTP (plain text).
// maxRunes is 0 in production (email has no practical limit).
func stormSummaryPlain(entries []stormEntry, maxRunes int, recovery bool) string {
	header := stormSummaryHeader(
		"pulsemon: alert storm — %d sensors changed state (coalesced to limit alert noise)",
		"pulsemon: recovery storm — %d sensors recovered (coalesced to limit alert noise)", recovery, len(entries))
	lines := make([]string, len(entries))
	for i, e := range entries {
		lines[i] = stormSummaryLine(e)
	}
	return truncateSummaryLines(header, lines, maxRunes)
}

// stormSummaryHeader picks the direction's header format and fills in the
// sensor count (the per-sensor lines follow in the formatters).
func stormSummaryHeader(down, recoveryFmt string, recovery bool, n int) string {
	if recovery {
		return fmt.Sprintf(recoveryFmt, n)
	}
	return fmt.Sprintf(down, n)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// recoveryTitle picks the alert headline for the new status: a full
// recovery reads "recovered", an error -> warning improvement reads
// "partial recovery".
func recoveryTitle(oldState, state string) string {
	if state == "up" {
		return "recovered"
	}
	if state == "warning" && oldState == "error" {
		return "partial recovery"
	}
	return state
}

// statusIcon maps a sensor state to the alert-card emoji, matching the
// dashboard's icon language (check-circle / warning / x-circle / pause-circle).
func statusIcon(state string) string { return statusIcons[state] }

var statusIcons = map[string]string{"up": "✅", "warning": "⚠️", "error": "❌", "paused": "⏸️"}

// alertTarget renders a sensor's target for third-party alert payloads,
// stripping any userinfo AND the query/fragment from the RAW string: a
// target like https://admin:***@nas.lan/health must not go verbatim into
// the Discord/Telegram/Chat/SMTP card (the password would be readable in
// the channel), and a ?token=… is a credential carrier too. Raw-string,
// not net/url: a malformed target (legacy or hand-edited rows) fails
// Parse, and a "return verbatim" fallback would ship the credentials — the
// exact leak this function exists to prevent; and u.String() would
// percent-encode the path. No authority (bare IP/hostname) → nothing to
// strip. The authority ends at the first '/', '?' or '#' (a raw '?'/'#'
// cannot sit inside userinfo — RFC 3986), and userinfo ends at the LAST
// '@' in the authority (net/url permits a raw '@'; cutting at the first
// '@' left a password fragment in the card).
// History: docs/DECISIONS.md → alert-target-last-at, alert-target
// parse-failure redaction, target-query-redaction.
func alertTarget(target string) string {
	prefix := authorityStart(target)
	if prefix < 0 {
		return target
	}
	rest := target[prefix:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}

	// Cut the userinfo (to and including the LAST '@' in the authority)
	// and the query/fragment (from the first '?'/'#' of the remainder —
	// after the userinfo cut the remainder starts at host[:port], which
	// cannot contain '?'/'#', so the first one is the true start).
	out := rest
	if at := strings.LastIndexByte(rest[:end], '@'); at >= 0 {
		out = rest[at+1:]
	}
	if q := strings.IndexAny(out, "?#"); q >= 0 {
		out = out[:q]
	}
	return target[:prefix] + out
}

// authorityStart returns the offset just past "scheme://" (or a leading
// "//" for a scheme-relative URL) — where the authority
// (userinfo@host[:port]) begins — or -1 when the string has no
// authority (bare IP, hostname, path). The scheme check mirrors
// net/url's grammar (a letter, then [A-Za-z0-9+.-]*), so the boundary
// matches what neturl.Parse would have used.
func authorityStart(target string) int {
	if i := strings.Index(target, "://"); i > 0 && validScheme(target[:i]) {
		return i + 3
	}
	if strings.HasPrefix(target, "//") {
		return 2
	}
	return -1
}

// validScheme mirrors net/url's scheme grammar: a letter followed by any
// run of letters, digits, '+', '-', '.'.
func validScheme(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return false
	}
	for j := 1; j < len(s); j++ {
		c := s[j]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// discordMentionSafe neutralizes Discord mention tokens in free text
// a sensor named "@everyone" (or a target path
// containing the token) would fire a mass mention to the whole channel
// when the card posts. A zero-width space inserted right AFTER the @
// breaks the token for Discord's mention parser while keeping the @
// visible in the rendered card (the old code replaced the @ entirely,
// so "@everyone" rendered as "‌everyone" with no @).
// Belt-and-braces with the payload's allowed_mentions.parse = []:
// this covers clients/imports that ignore allowed_mentions.
func discordMentionSafe(s string) string {
	s = strings.ReplaceAll(s, "@everyone", "@\u200beveryone")
	s = strings.ReplaceAll(s, "@here", "@\u200bhere")
	return s
}

// mdEscape backslash-escapes the Markdown metacharacters that
// validSensorName permits: the emphasis characters * _ ~ ` (a sensor named
// db_primary_01 would otherwise render with "primary" italicized) and the
// link brackets [ ] (a sensor named "[click here](https://evil.example)" is
// legal input and would otherwise render as a masked hyperlink in the
// Discord/Google Chat cards and storm summary). The parens are deliberately
// unescaped: with the brackets neutralized no link syntax can form, so
// escaping them would be noise.
//
// Applied to SENSOR NAMES ONLY, never to targets: a target is a URL/hostname
// whose path may legally contain _ and ~, and backslash-escaping those
// injects visible backslashes into the URL and breaks the clickable link.
//
// Applied ONLY to the Markdown (google_chat/discord) builders — the
// Telegram (HTML) and SMTP (plain) paths carry the data verbatim.
// History: docs/DECISIONS.md → storm-summary-target-mention-safe.
func mdEscape(s string) string {
	return mdReplacer.Replace(s)
}

// mdReplacer is the single-pass table behind mdEscape: strings.Replacer
// applies all six mappings in one scan (no per-character intermediate
// allocations the old ReplaceAll loop made). Each replacement output carries
// a backslash, which is not itself a source character, so the single pass
// cannot re-escape its own output.
var mdReplacer = strings.NewReplacer(
	"*", "\\*",
	"_", "\\_",
	"~", "\\~",
	"`", "\\`",
	"[", "\\[",
	"]", "\\]",
)

func cardFor(oldState, state, name, target string, rttMs float64) string {
	target = alertTarget(target)
	// Escape the name (free text) only; the target is a URL/hostname and stays
	// verbatim so it renders and auto-links cleanly
	name = mdEscape(name)
	icon := statusIcon(state)
	if icon == "" {
		icon = "✅"
	}
	title := recoveryTitle(oldState, state)
	card := fmt.Sprintf("%s *pulsemon: %s*\n*Sensor*: %s\n*Target*: %s\n*State*: **%s**",
		icon, title, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n*Ping*: %d ms", int(rttMs+0.5))
	}
	return card
}

func cardForRe(state, name, target string, rttMs float64) string {
	target = alertTarget(target)
	name = mdEscape(name)
	icon := statusIcon(state)
	if icon == "" {
		icon = "✅"
	}
	card := fmt.Sprintf("%s *pulsemon: still %s (re-alert)*\n*Sensor*: %s\n*Target*: %s\n*State*: **%s** — no change, re-notifying",
		icon, state, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n*Ping*: %d ms", int(rttMs+0.5))
	}
	return card
}

// Discord uses Markdown (**bold**, no *italic* emphasis); the card is plain
// content. Same information, Discord-flavored. name/target are sanitized
// first: credentials stripped (F22) and mention tokens neutralized (F23).
func discordCard(oldState, state, name, target string, rttMs float64) string {
	// Name: mention-neutralized + emphasis-escaped (free text). Target:
	// mention-neutralized + credentials stripped, but VERBATIM (no mdEscape)
	// so the URL renders and auto-links cleanly
	name = mdEscape(discordMentionSafe(name))
	target = discordMentionSafe(alertTarget(target))
	icon := statusIcon(state)
	if icon == "" {
		icon = "✅"
	}
	title := recoveryTitle(oldState, state)
	card := fmt.Sprintf("%s **pulsemon: %s**\n**Sensor:** %s\n**Target:** %s\n**State:** %s", icon, title, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n**Ping:** %d ms", int(rttMs+0.5))
	}
	return card
}

func discordCardRe(state, name, target string, rttMs float64) string {
	name = mdEscape(discordMentionSafe(name))
	target = discordMentionSafe(alertTarget(target))
	icon := statusIcon(state)
	if icon == "" {
		icon = "✅"
	}
	card := fmt.Sprintf("%s **pulsemon: still %s (re-alert)**\n**Sensor:** %s\n**Target:** %s\n**State:** %s — no change, re-notifying", icon, state, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n**Ping:** %d ms", int(rttMs+0.5))
	}
	return card
}
