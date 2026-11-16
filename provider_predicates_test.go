package main

// Swallow-bool legacy-contract wrappers (the GetSetting contract: a read
// failure is indistinguishable from "unset"). Test-suite surface only —
// production paths evaluate the *Get predicates in alerts.go/smtp.go;
// these twins live in _test.go so the production files carry only live
// code (m6 sweep).

import "pulsemon/internal/store"

func smtpHasURL(db *store.Store) bool { b, _ := smtpHasURLGet(db.GetSettingErr); return b }

func chatEnabled(db *store.Store) bool { b, _ := chatEnabledGet(db.GetSettingErr); return b }

func flagEnabled(kind string) func(db *store.Store) bool {
	g := flagEnabledGet(kind)
	return func(db *store.Store) bool { b, _ := g(db.GetSettingErr); return b }
}

func flagHasURL(kind string) func(db *store.Store) bool {
	g := flagHasURLGet(kind)
	return func(db *store.Store) bool { b, _ := g(db.GetSettingErr); return b }
}

func telegramHasURL(db *store.Store) bool { b, _ := telegramHasURLGet(db.GetSettingErr); return b }
