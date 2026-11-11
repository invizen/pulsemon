package main

// The session cookie Secure decision is pinned at mint and carried through
// sliding renewals (a renewal must not drop Secure).

import (
	"context"
	"testing"
	"time"
)

func TestCookieSecurePinAcrossRenewal(t *testing.T) {
	a := NewAuthState(newTestDB(t))
	if err := a.AddUserMode(context.Background(), "admin", "secretpw", true); err != nil {
		t.Fatal(err)
	}
	age := func(tok string) {
		a.mu.Lock()
		s := a.sessions[tok]
		s.cookieIssued = time.Now().Add(-authSessionTTL)
		a.sessions[tok] = s
		a.mu.Unlock()
	}

	secureTok, ok := a.CreateSession(context.Background(), "admin", "secretpw", true)
	if !ok {
		t.Fatal("CreateSession(secure) failed")
	}
	plainTok, ok := a.CreateSession(context.Background(), "admin", "secretpw", false)
	if !ok {
		t.Fatal("CreateSession failed")
	}
	age(secureTok)
	age(plainTok)

	if due, pin, _ := a.CookieRenewalDue(secureTok); !due || !pin {
		t.Fatalf("Secure-minted session lost its pin: due=%v pin=%v", due, pin)
	}
	if due, pin, _ := a.CookieRenewalDue(plainTok); !due || pin {
		t.Fatalf("plain session wrongly reported a Secure pin: due=%v pin=%v", due, pin)
	}
}
