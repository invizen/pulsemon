package main

import "fmt"

// Telegram alert cards. Telegram's parse mode is HTML (<b>bold</b>), so the
// card is plain-text with <b> emphasis — the same information as the Discord
// (Markdown) and Google Chat (asterisk) cards, Telegram-flavored.
//
// The provider's "URL" field is the bot endpoint
// (https://api.telegram.org/bot<TOKEN>/sendMessage); the chat_id is a
// separate setting (telegram_chat_id). Delivery is a single POST with
// {chat_id, text, parse_mode:"HTML"} to that endpoint — no SDK, no auth
// beyond the token already in the URL.
func telegramCard(oldState, state, name, target string, rttMs float64) string {
	icon := map[string]string{"up": "🟢", "warning": "🟡", "error": "🔴"}[state]
	if icon == "" {
		icon = "🟢"
	}
	title := recoveryTitle(oldState, state)
	card := fmt.Sprintf("%s <b>pulsemon: %s</b>\n<b>Sensor:</b> %s\n<b>Target:</b> %s\n<b>State:</b> %s", icon, title, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n<b>Ping:</b> %d ms", int(rttMs+0.5))
	}
	return card
}

func telegramCardRe(state, name, target string, rttMs float64) string {
	icon := map[string]string{"warning": "🟡", "error": "🔴"}[state]
	if icon == "" {
		icon = "🟢"
	}
	card := fmt.Sprintf("%s <b>pulsemon: still %s (re-alert)</b>\n<b>Sensor:</b> %s\n<b>Target:</b> %s\n<b>State:</b> %s — no change, re-notifying", icon, state, name, target, state)
	if rttMs > 0 {
		card += fmt.Sprintf("\n<b>Ping:</b> %d ms", int(rttMs+0.5))
	}
	return card
}
