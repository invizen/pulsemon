package main

import (
	"errors"
	"net/http"
	"path/filepath"
	"pulsemon/internal/store"
	"strings"
	"testing"
	"time"
)

// TestBindServeWithRetryFailsFastWhenNotRetrying pins the inverted-branch
// fix: on normal startup (!retry) the FIRST bind failure (port conflict,
// EACCES on :443) must be fatal immediately. The pre-fix code gated the
// fatal on time.Now().After(deadline), so an immediate failure was retried
// for a full 30s before dying — despite the comment saying "fail fast".
//
// bindFatal is stubbed to PANIC (not just record): the real log.Fatal exits
// the process, so a recording stub would return control to the retry loop
// and spin it forever.
func TestBindServeWithRetryFailsFastWhenNotRetrying(t *testing.T) {
	orig := bindFatal
	bindFatal = func(msg string) { panic(msg) }
	t.Cleanup(func() { bindFatal = orig })

	start := time.Now()
	var msg string
	func() {
		defer func() { msg, _ = recover().(string) }()
		bindServeWithRetry(false, ":9299", func() error {
			return errors.New("bind: address already in use")
		})
	}()
	if msg == "" {
		t.Fatal("expected a fatal on the first bind failure in non-retry mode")
	}
	if !strings.Contains(msg, "address already in use") {
		t.Fatalf("fatal message %q must carry the bind error", msg)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("non-retry mode must fail fast, took %v", elapsed)
	}
}

// TestBindServeWithRetryDiesAtDeadline pins the zombie fix: in re-exec mode
// (retry), a bind that never succeeds must be fatal at the deadline. The
// pre-fix code logged "listener stopped" and returned normally, leaving the
// process alive as a headless zombie — probe worker running, DB open, no
// listener, no self-recovery. (bindFatal stubbed to panic, same reason as
// above.)
func TestBindServeWithRetryDiesAtDeadline(t *testing.T) {
	origFatal := bindFatal
	origDeadline := reexecBindDeadline
	bindFatal = func(msg string) { panic(msg) }
	reexecBindDeadline = 700 * time.Millisecond
	t.Cleanup(func() { bindFatal = origFatal; reexecBindDeadline = origDeadline })

	attempts := 0
	start := time.Now()
	var msg string
	func() {
		defer func() { msg, _ = recover().(string) }()
		bindServeWithRetry(true, "TLS: :443", func() error {
			attempts++
			return errors.New("bind: address already in use")
		})
	}()
	if msg == "" {
		t.Fatal("expected a fatal at the deadline in re-exec mode")
	}
	if !strings.Contains(msg, "address already in use") {
		t.Fatalf("fatal message %q must carry the bind error", msg)
	}
	if attempts < 2 {
		t.Fatalf("re-exec mode must retry the bind, got %d attempts", attempts)
	}
	if elapsed := time.Since(start); elapsed < 600*time.Millisecond {
		t.Fatalf("gave up before the deadline: %v", elapsed)
	}
}

// TestBindServeWithRetrySucceedsAfterRetries pins the re-exec happy path:
// the parent releases the port after a couple of attempts, the bind
// succeeds, and no fatal fires.
func TestBindServeWithRetrySucceedsAfterRetries(t *testing.T) {
	orig := bindFatal
	bindFatal = func(msg string) { t.Errorf("unexpected fatal: %s", msg) }
	t.Cleanup(func() { bindFatal = orig })

	attempts := 0
	bindServeWithRetry(true, ":9299", func() error {
		attempts++
		if attempts < 3 {
			return errors.New("bind: address already in use")
		}
		return nil
	})
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3 (two failures then success)", attempts)
	}
}

// TestBindServeWithRetryNormalExits pins the success paths: a successful
// serve (nil) and a clean shutdown (http.ErrServerClosed) both return
// without a fatal — normal startup and shutdown are unchanged.
func TestBindServeWithRetryNormalExits(t *testing.T) {
	orig := bindFatal
	bindFatal = func(msg string) { t.Errorf("unexpected fatal: %s", msg) }
	t.Cleanup(func() { bindFatal = orig })

	bindServeWithRetry(false, ":9299", func() error { return nil })
	bindServeWithRetry(true, ":9299", func() error { return http.ErrServerClosed })
}

// TestFix_m2_UnreadableTLSPairIsFatal pins the m2 fix: a TLS pair that is
// CONFIGURED (env) but unreadable must go fatal (via certFatal) — the old
// behavior (WARNING + serve plain HTTP) silently ran plaintext when the
// operator believed TLS was on.
func TestFix_m2_UnreadableTLSPairIsFatal(t *testing.T) {
	t.Setenv("PULSEMON_CERT", "/nonexistent/cert.pem")
	t.Setenv("PULSEMON_KEY", "/nonexistent/key.pem")
	t.Setenv("PULSEMON_ALLOW_PLAINTEXT_FALLBACK", "")

	fatals := make(chan string, 1)
	oldCert, oldBind := certFatal, bindFatal
	// The stubs must NOT return: the real log.Fatal exits the process, so a
	// returning stub would let the listener's retry loop keep going and
	// fire the REAL fatal (restored by cleanup) 500ms later. select {}
	// mimics the non-returning semantics.
	certFatal = func(msg string) { fatals <- msg; select {} }
	bindFatal = func(msg string) { fatals <- msg; select {} } // must NOT be reached
	t.Cleanup(func() { certFatal, bindFatal = oldCert, oldBind })

	db, err := store.NewStore(filepath.Join(t.TempDir(), "m2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	startListener(newHTTPServer(http.NewServeMux()), db)

	select {
	case msg := <-fatals:
		if !strings.Contains(msg, "/nonexistent/cert.pem") {
			t.Fatalf("fatal %q must name the missing cert", msg)
		}
		if !strings.Contains(msg, "PULSEMON_ALLOW_PLAINTEXT_FALLBACK") {
			t.Fatalf("fatal %q must mention the opt-out env", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("configured-but-unreadable TLS pair did not go fatal")
	}
}

// TestFix_m2_PlaintextFallbackEnv pins the opt-out: with
// PULSEMON_ALLOW_PLAINTEXT_FALLBACK=1 a configured-but-unreadable pair
// warns and falls through to the plain-HTTP listener (no certFatal).
// PULSEMON_ADDR points at an invalid port so the plain listener fails
// fast via bindFatal and the test leaves no listener behind.
func TestFix_m2_PlaintextFallbackEnv(t *testing.T) {
	t.Setenv("PULSEMON_CERT", "/nonexistent/cert.pem")
	t.Setenv("PULSEMON_KEY", "/nonexistent/key.pem")
	t.Setenv("PULSEMON_ALLOW_PLAINTEXT_FALLBACK", "1")
	t.Setenv("PULSEMON_ADDR", "127.0.0.1:99999") // invalid port: fails even as root

	binds := make(chan string, 1)
	oldCert, oldBind := certFatal, bindFatal
	certFatal = func(msg string) { t.Errorf("unexpected certFatal: %s", msg) }
	// select {} after the send: a returning stub would let the retry loop
	// call bindFatal again (now the real one) and kill the test process.
	bindFatal = func(msg string) { binds <- msg; select {} }
	t.Cleanup(func() { certFatal, bindFatal = oldCert, oldBind })

	db, err := store.NewStore(filepath.Join(t.TempDir(), "m2b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	startListener(newHTTPServer(http.NewServeMux()), db)

	select {
	case msg := <-binds:
		if !strings.Contains(msg, "Listen (127.0.0.1:99999)") {
			t.Fatalf("bindFatal %q, want the plain-HTTP listen attempt", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PULSEMON_ALLOW_PLAINTEXT_FALLBACK=1 did not fall through to the plain-HTTP listener")
	}
}
