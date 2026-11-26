package main

import (
	"crypto/tls"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"pulsemon/internal/store"
	"strconv"
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
		bindServeWithRetry(false, make(chan struct{}), ":9299", func() error {
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
		bindServeWithRetry(true, make(chan struct{}), "TLS: :443", func() error {
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
	bindServeWithRetry(true, make(chan struct{}), ":9299", func() error {
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

	bindServeWithRetry(false, make(chan struct{}), ":9299", func() error { return nil })
	bindServeWithRetry(true, make(chan struct{}), ":9299", func() error { return http.ErrServerClosed })
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

	// The cert check (and its fatal) is now SYNCHRONOUS in startListener
	// (MAJOR-11), so the blocking certFatal stub parks startListener's own
	// goroutine — run it detached and watch the channel from here.
	detachedSrv, _ := newHTTPServer(http.NewServeMux())
	go startListener(detachedSrv, db, make(chan struct{}))

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

	boundSrv, _ := newHTTPServer(http.NewServeMux())
	startListener(boundSrv, db, make(chan struct{}))

	select {
	case msg := <-binds:
		if !strings.Contains(msg, "Listen (127.0.0.1:99999)") {
			t.Fatalf("bindFatal %q, want the plain-HTTP listen attempt", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("PULSEMON_ALLOW_PLAINTEXT_FALLBACK=1 did not fall through to the plain-HTTP listener")
	}
}

// TestBindServeWithRetryHonorsShutdown is the MAJOR-11 stop pin: a
// re-exec child stuck in the bind-retry loop (parent still holding the
// port) that receives a shutdown must RETURN CLEANLY — pre-fix the loop
// ignored stop and kept going to the 45s deadline, where bindFatal's
// os.Exit(1) skipped runServer's deferred db.Close() mid-shutdown.
func TestBindServeWithRetryHonorsShutdown(t *testing.T) {
	origFatal := bindFatal
	bindFatal = func(msg string) { panic(msg) }
	t.Cleanup(func() { bindFatal = origFatal })

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		bindServeWithRetry(true, stop, ":9299", func() error {
			return errors.New("bind: address already in use")
		})
	}()
	// Let a couple of retry cycles elapse, then shut down.
	time.Sleep(120 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not stop the bind retry loop")
	}
}

// TestStartListenerConfiguresServerBeforeServeGoroutine is the MAJOR-11
// mutation-race pin (source-shape): srv.Shutdown reads srv.Addr and
// srv.TLSConfig, so every `srv.* =` assignment in startListener must sit
// OUTSIDE the serve goroutine's function literal — inside it, the write
// races the concurrent shutdown read. A behavioral race test cannot see
// this deterministically (the race only fires on the interleaving), so the
// pin parses the AST: zero srv.* assignments inside any FuncLit, at least
// one outside (positive control: the pin is not vacuous).
func TestStartListenerConfiguresServerBeforeServeGoroutine(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "startListener" {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatal("startListener not found in main.go")
	}
	srvAssign := func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == "srv"
	}
	inFuncLit, total := 0, 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if fl, ok := n.(*ast.FuncLit); ok {
			ast.Inspect(fl, func(m ast.Node) bool {
				if as, ok := m.(*ast.AssignStmt); ok {
					for _, lhs := range as.Lhs {
						if srvAssign(lhs) {
							inFuncLit++
						}
					}
				}
				return true
			})
			return false
		}
		if as, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range as.Lhs {
				if srvAssign(lhs) {
					total++
				}
			}
		}
		return true
	})
	if total == 0 {
		t.Fatal("no srv.* assignments found in startListener — pin is vacuous")
	}
	if inFuncLit > 0 {
		t.Fatalf("%d srv.* assignment(s) inside the serve goroutine — they race srv.Shutdown", inFuncLit)
	}
}

// TestTLSServeAdvertisesHTTP2 is the MAJOR-11 ALPN pin, end to end: the
// real startListener path (env pair + stored port) must negotiate "h2"
// with an h2-capable client. Pre-fix, listenTLS wrapped the listener in
// tls.NewListener + srv.Serve with NextProtos left empty, so ALPN never
// advertised h2 and every dashboard tab rode multiple HTTP/1.1
// connections for its 5s polls.
func TestTLSServeAdvertisesHTTP2(t *testing.T) {
	certPEM, keyPEM, _ := makeTestCert(t, "rsa")
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	// A free port for the TLS listener.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	db, err := store.NewStore(filepath.Join(t.TempDir(), "h2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.InitSchema(); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting("listener_https_port", strconv.Itoa(port)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PULSEMON_CERT", certPath)
	t.Setenv("PULSEMON_KEY", keyPath)

	srv, _ := newHTTPServer(http.NewServeMux())
	stop := make(chan struct{})
	defer close(stop)
	startListener(srv, db, stop)

	deadline := time.Now().Add(5 * time.Second)
	var conn *tls.Conn
	for {
		var c net.Conn
		var err error
		c, err = tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		if err == nil {
			conn = c.(*tls.Conn)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("TLS listener never came up on port %d: %v", port, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("ALPN negotiated %q, want h2 (without it the dashboard is forced onto HTTP/1.1)", got)
	}
}
