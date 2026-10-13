package main

import (
	"fmt"
	"html"
)

// Telegram alert cards. Telegram's parse mode is HTML (<b>bold</b>), so the
// card is plain-text with <b> emphasis — the same information as the Discord
// (Markdown) and Google Chat (asterisk) cards, Telegram-flavored.
//
// The provider's "URL" field is the bot endpoint
// (https://api.telegram.org/bot<TOKEN>/sendMessage); the chat_id is a
// separate setting (telegram_chat_id). Delivery is a single POST with
// {chat_id, text, parse_mode:"HTML"} to that endpoint — no SDK, no auth
// beyond the token already in the URL.
//
// All dynamic fields go through html.EscapeString before interpolation:
// sensor names can't contain < > (validSensorName), but HTTP targets are
// URLs and url.Parse (and thus validURL) happily accepts a query string
// with raw & (https://host.lan/health?service=a&check=1) and even raw
// markup in the path (https://host.lan/<b>bold</b> — verified on Go 1.26).
// Unescaped & in HTML parse mode can make the Telegram API reject the
// message with 400 "can't parse entities" (silently dropping the alert),
// and unescaped < > injects live markup into the card. &amp; / &lt; render
// identically to & / < in Telegram HTML mode, so escaping is zero-cost.
func telegramCard(oldState, state, name, target string, rttMs float64) string {
	icon := statusIcon(state)
	if icon == "" {
		icon = "✅"
	}
	title := recoveryTitle(oldState, state)
	card := fmt.Sprintf("%s <b>pulsemon: %s</b>\n<b>Sensor:</b> %s\n<b>Target:</b> %s\n<b>State:</b> %s",
		icon, html.EscapeString(title), html.EscapeString(name), html.EscapeString(target), html.EscapeString(state))
	if rttMs > 0 {
		card += fmt.Sprintf("\n<b>Ping:</b> %d ms", int(rttMs+0.5))
	}
	return card
}

func telegramCardRe(state, name, target string, rttMs float64) string {
	icon := statusIcon(state)
	if icon == "" {
		icon = "✅"
	}
	card := fmt.Sprintf("%s <b>pulsemon: still %s (re-alert)</b>\n<b>Sensor:</b> %s\n<b>Target:</b> %s\n<b>State:</b> %s — no change, re-notifying",
		icon, html.EscapeString(state), html.EscapeString(name), html.EscapeString(target), html.EscapeString(state))
	if rttMs > 0 {
		card += fmt.Sprintf("\n<b>Ping:</b> %d ms", int(rttMs+0.5))
	}
	return card
}
