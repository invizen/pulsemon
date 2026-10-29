package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// listenAddr is the HTTP listen address. Override with PULSEMON_ADDR — a full
// "host:port" (e.g. ":9299" for all interfaces on 9299, "127.0.0.1:9299" for
// localhost only, or "10.0.0.5:9299" for a specific interface). Port 8080 was
// the original default but is heavily claimed on homelab boxes (Traefik,
// Pi-hole, reverse proxies); 9299 is the new default.
func listenAddr() string {
	if a := os.Getenv("PULSEMON_ADDR"); a != "" {
		return a
	}
	return ":9299"
}

// dbPathFromEnv returns the database path: PULSEMON_DB if set, else the
// platform default (the Docker /data volume on Linux, %ProgramData%\Pulsemon
// on Windows — see defaultDBPath in main_linux.go / main_windows.go).
func dbPathFromEnv() string {
	if p := os.Getenv("PULSEMON_DB"); p != "" {
		return p
	}
	return defaultDBPath()
}

// certPaths returns the TLS certificate/key pair to serve HTTPS with, or
// ("", "") for plain HTTP. Both PULSEMON_CERT and PULSEMON_KEY must be set
// together — a cert without a key (or vice versa) is a misconfiguration
// worth failing on at startup, not a half-working listener.
// certFatal is the failure path for a TLS misconfiguration (partial env
// config, a configured-but-unreadable pair, an in-place-but-unloadable
// pair); stubbed in tests so log.Fatalf (which exits) does not kill the
// test process.
var certFatal = func(msg string) { log.Fatal(msg) }

func certPaths() (string, string) {
	cert := os.Getenv("PULSEMON_CERT")
	key := os.Getenv("PULSEMON_KEY")
	if cert == "" && key == "" {
		return "", "" // plain HTTP
	}
	if cert == "" || key == "" {
		certFatal("CRITICAL: PULSEMON_CERT and PULSEMON_KEY must be set together")
	}
	return cert, key
}

// dispatchKind is the outcome of dispatching os.Args.
type dispatchKind int

const (
	dRunServer dispatchKind = iota
	dExit0
	dExit1
	dExit2
)

// dispatch parses the command line and executes any non-server command.
// Only dRunServer means "fall through and start the HTTP server". Keeping it
// out of main() makes the arg handling testable (see cli_test.go); the one
// side effect that must live in main is os.Exit, so the caller exits with the
// kind's status.
func dispatch(args []string) dispatchKind {
	if len(args) <= 1 {
		return dRunServer
	}
	switch args[1] {
	case "update":
		// runUpdate returns its exit code instead of calling os.Exit
		// itself (os.Exit skips deferred cleanup of the downloaded temp
		// file); main() exits with the mapped status.
		switch runUpdate(args[2:]) {
		case 0:
			return dExit0
		case 2:
			return dExit2
		default:
			return dExit1
		}
	case "-healthz", "--healthz":
		return runHealthcheck()
	case "-healthz-http", "--healthz-http":
		// The HTTP form of the healthcheck (K2): verifies the RUNNING
		// server answers /api/healthz, not just that the store opens.
		return runHealthcheckHTTP()
	case "restart":
		// Apply a config that needs a fresh process (listener/TLS).
		return runRestartCommand()
	case "auth-user":
		// Dashboard accounts: pulsemon auth-user add|remove|list [NAME]
		return runAuthUser(args[2:])
	case "sign":
		// Release-signing maintainer tool: pulsemon sign genkey|release.
		// Not part of the update path; run on the trusted release host.
		switch runSignRelease(args[2:]) {
		case 0:
			return dExit0
		default:
			return dExit1
		}
	case "-v", "-version", "--version", "version":
		fmt.Println("pulsemon", Version)
		return dExit0
	}
	// Anything else must be a known flag. Unknown flags (pulsemon -invalid,
	// pulsemon --foo) previously fell through to a normal server start — the
	// operator's typo silently booted a dashboard instead of surfacing an
	// error.
	if strings.HasPrefix(args[1], "-") {
		fmt.Fprintf(os.Stderr, "pulsemon: unknown flag %q\n\n", args[1])
		fmt.Fprint(os.Stderr, "Usage:\n  pulsemon            start the monitor + dashboard\n  pulsemon update [check|rollback|watchdog|VERSION] [--restart]  self-update (check only, roll back the last update, or pin a version); --restart also restarts the service\n  pulsemon auth-user add <user> [<password>]   create a dashboard account (first account enables auth); no <password> (or --password-stdin) reads it from stdin\n  pulsemon auth-user remove <user>       delete a dashboard account\n  pulsemon auth-user list                list dashboard accounts\n  pulsemon -healthz        verify the store is usable\n  pulsemon -healthz-http   verify the RUNNING server answers /api/healthz (container healthcheck)\n  pulsemon -version        print the build version and exit\n")
		if os.Getenv("PULSEMON_TEST_NOFATAL") == "" {
			os.Exit(1)
		}
		return dExit1
	}
	return dRunServer
}

// runHealthcheck opens the store via NewDB so the pragmas (busy_timeout,
// WAL, foreign_keys) apply — a bare sql.Open runs with a 0 ms busy_timeout
// and fails with SQLITE_BUSY the instant a probe write or WAL checkpoint is
// in flight, which would crash-loop a container. NewDB's SELECT 1 already
// verifies reachability; the COUNT additionally proves the schema exists.
func runHealthcheck() dispatchKind {
	db, err := NewDB(dbPathFromEnv())
	if err != nil {
		log.Printf("healthz: open: %v", err)
		return dExit1
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors").Scan(&n); err != nil {
		log.Printf("healthz: query: %v", err)
		return dExit1
	}
	return dExit0
}

// runHealthcheckHTTP is the HTTP form of the container healthcheck (K2): the plain -healthz flag only opens the store, so a
// wedged HTTP server (listener dead, handler panic-loop) still reports
// "healthy" to the container runtime. This flag does a real GET against the
// running server's /api/healthz and exits 0 ONLY when the pulsemon healthz
// payload comes back, polling every configured (scheme, port) candidate the
// same way the updater does (once a cert is installed the plain port is
// deliberately not bound). TLS verification is skipped for the same reason
// the updater skips it: the question is "is the server answering", not "is
// the certificate trusted" — a self-signed homelab cert must pass.
func runHealthcheckHTTP() dispatchKind {
	db, err := NewDB(dbPathFromEnv())
	if err != nil {
		log.Printf("healthz-http: open: %v", err)
		return dExit1
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sensors").Scan(&n); err != nil {
		log.Printf("healthz-http: query: %v", err)
		return dExit1
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	for _, t := range healthzTargets(db) {
		resp, gerr := client.Get(t + "/api/healthz")
		if gerr != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && healthzPayloadOK(string(body)) {
			return dExit0
		}
	}
	log.Printf("healthz-http: no configured endpoint answered /api/healthz with the pulsemon payload")
	return dExit1
}

// tlsKeyPairOK pre-validates the cert+key pair the listener is about to
// serve. tls.LoadX509KeyPair reads both files and parses the key — so an
// encrypted or corrupt key is caught HERE, at startup, with a clear
// message, instead of surfacing mid-handshake from ServeTLS after the
// 30s bind-retry window.
func tlsKeyPairOK(cert, key string) error {
	_, err := tls.LoadX509KeyPair(cert, key)
	return err
}

// newHTTPServer builds the production HTTP server: the read/idle timeouts
// and header cap that protect the listener from slowloris-style abuse.
//
// There is deliberately NO server-level WriteTimeout: POST /api/update
// (self-update) runs up to ~60s (download + verify + install) and a
// server write deadline would cut it off mid-install. See
// docs/HANDOFF-esthero.md for the note and the middleware-shaped
// alternative if a global write cap is ever wanted.
//
// Factored out of runServer so a test can pin the exact values.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

// reexecBindDeadline bounds a re-exec child's bind retries. The parent's
// shutdown is structurally bounded at 30s (the 10s probe-worker + 15s
// alert-drain + 5s HTTP-drain backstops in runServer); 45s covers that
// worst case with margin so a slow parent release never loses the race.
// A var (not const) so tests can shorten it.
var reexecBindDeadline = 45 * time.Second

// bindFatal is the failure path for a bind that will not succeed; stubbed
// in tests so log.Fatalf (which exits) does not kill the test process.
// (Same pattern as certFatal.)
var bindFatal = func(msg string) { log.Fatal(msg) }

// bindServeWithRetry runs bind — which serves the server on a fresh
// listener and blocks until it stops — and retries failed BINDS while a
// re-exec parent may still hold the port. A successful serve and a clean
// shutdown (http.ErrServerClosed) are both normal exits. Any other error:
// fail immediately when not re-exec'ing (a port conflict or permission
// error will not resolve on its own), or at the deadline when re-exec'ing.
// A re-exec child that cannot bind must die loudly — a supervisor
// restarts it — rather than return and leave the process alive as a
// headless zombie with a probe worker but no listener.
func bindServeWithRetry(retry bool, label string, bind func() error) {
	deadline := time.Now().Add(reexecBindDeadline)
	for {
		err := bind()
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return
		}
		if !retry || time.Now().After(deadline) {
			bindFatal("Listen (" + label + "): " + err.Error())
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// startListener starts the HTTP (and, when a TLS pair is in place,
// HTTPS) listener in the background and wires its fatal errors to
// log.Fatalf (same behavior as the old inline goroutine).
//
// HTTPS is served on the configured TLS port; the plain-HTTP port is
// NOT bound when TLS is active — the dashboard is reachable only over
// TLS. This is deliberate: a box that uploaded a cert must not stay
// reachable in plaintext on the old port.
//
// When PULSEMON_RESTARTING is set (we are the child of a re-exec), the
// bind may fail for up to ~30s while the parent still holds the port;
// bindServeWithRetry retries it until reexecBindDeadline instead of
// dying (and dies loudly if the parent never releases).
func startListener(srv *http.Server, db *DB) {
	cfg := loadListenerCfg(db)
	retry := os.Getenv("PULSEMON_RESTARTING") == "1"

	go func() {
		if cfg.certPath != "" {
			// A CONFIGURED pair must be servable. Silently serving
			// plaintext when the operator believes TLS is on is the
			// worse failure, so an unreadable pair is fatal — unless the
			// operator opts back into the old warn-and-fallback behavior
			// (an install that stages certs after first boot) with
			// PULSEMON_ALLOW_PLAINTEXT_FALLBACK=1.
			var missing string
			if _, err := os.Stat(cfg.certPath); err != nil {
				missing = cfg.certPath + ": " + err.Error()
			} else if _, err := os.Stat(cfg.keyPath); err != nil {
				missing = cfg.keyPath + ": " + err.Error()
			}
			if missing != "" {
				if os.Getenv("PULSEMON_ALLOW_PLAINTEXT_FALLBACK") == "1" {
					log.Printf("WARNING: TLS is configured (%s) but %s is not readable; PULSEMON_ALLOW_PLAINTEXT_FALLBACK=1 — serving plain HTTP until it is in place", cfg.source, missing)
				} else {
					certFatal("CRITICAL: TLS is configured (" + cfg.source + ") but " + missing + " — fix the files, or set PULSEMON_ALLOW_PLAINTEXT_FALLBACK=1 to serve plain HTTP in the meantime")
					return
				}
			} else if err := tlsKeyPairOK(cfg.certPath, cfg.keyPath); err != nil {
				// A pair is in place but unusable (encrypted key,
				// corrupt cert, mismatched pair). Fail fast with the
				// reason instead of looping or serving plaintext.
				certFatal(fmt.Sprintf("TLS: %s + %s are in place but cannot be loaded: %v", cfg.certPath, cfg.keyPath, err))
				return
			} else {
				srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
				addr := httpsAddrFor(cfg.httpsPort)
				log.Println("Starting server on " + addr + " (TLS, cert " + cfg.source + ")")
				bindServeWithRetry(retry, "TLS: "+addr, func() error {
					return listenTLS(srv, addr, cfg.certPath, cfg.keyPath)
				})
				return
			}
		}
		addr := listenAddr()
		srv.Addr = addr // listener is created explicitly below; keep srv.Addr in sync
		log.Println("Starting server on " + addr)
		bindServeWithRetry(retry, addr, func() error {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}
			defer ln.Close() // no leaked socket on a retry after a failed serve
			errCh := make(chan error, 1)
			go func() { errCh <- srv.Serve(ln) }()
			return <-errCh
		})
	}()
}

// listenTLS binds and serves TLS on a fresh listener; returns when the
// server is shut down. The listener is always closed so a retry after a
// failed serve does not leak a socket.
func listenTLS(srv *http.Server, addr, cert, key string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	srv.Addr = addr
	// m10: ServeTLS(ln, cert, key) loads the pair ONCE,
	// so a renewed cert (dashboard TLS upload, acme.sh cron) needed a process
	// restart. GetCertificate re-reads the files when their mtime changes, so
	// the renewal takes effect at the next handshake.
	srv.TLSConfig.GetCertificate = hotReloadCert(cert, key)
	tlsLn := tls.NewListener(ln, srv.TLSConfig)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(tlsLn) }()
	return <-errCh
}

// hotReloadCert returns a tls.Config.GetCertificate that serves the pair at
// (certPath, keyPath), re-loading it whenever either file's mtime changes.
// A failed reload (half-written file, transient mismatch) keeps the LAST
// GOOD pair instead of failing every handshake, and records the (broken)
// mtimes so it is NOT re-parsed + re-logged on every handshake for as long
// as the files stay broken — the reload is retried only when a file's mtime
// changes again. The initial load failure surfaces as a handshake error (the
// pair was already validated by tlsKeyPairOK before serve starts, so this
// only bites on a genuinely broken file at runtime).
func hotReloadCert(certPath, keyPath string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	var (
		mu     sync.Mutex
		cached *tls.Certificate
		certMT time.Time
		keyMT  time.Time
	)
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		var cMT, kMT time.Time
		if fi, err := os.Stat(certPath); err == nil {
			cMT = fi.ModTime()
		}
		if fi, err := os.Stat(keyPath); err == nil {
			kMT = fi.ModTime()
		}
		mu.Lock()
		defer mu.Unlock()
		if cached != nil && cMT.Equal(certMT) && kMT.Equal(keyMT) {
			return cached, nil
		}
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			if cached != nil {
				// Record the (broken) mtimes so the next handshakes take the
				// fast cached path instead of re-parsing + re-logging on every
				// handshake for as long as the files stay broken. The reload is
				// retried only when a file's mtime changes again.
				certMT, keyMT = cMT, kMT
				log.Printf("tls: cert reload from %s/%s failed (%v) — keeping the previous pair", certPath, keyPath, err)
				return cached, nil
			}
			return nil, err
		}
		cached = &pair
		certMT, keyMT = cMT, kMT
		return cached, nil
	}
}

// authUserUsage is the single usage string for `pulsemon auth-user` (the
// add forms: <user> <pass> is the legacy argv form; <user> alone or with
// --password-stdin reads the password from stdin).
const authUserUsage = "usage: pulsemon auth-user add <username> [<password>|--password-stdin] | remove <username> | list"

// authAddArgs is the parsed `auth-user add` argument set.
type authAddArgs struct {
	user      string
	pass      string
	fromStdin bool // password comes from stdin (one line)
	err       error
}

// parseAuthAddArgs accepts the three add forms:
//
//	add <user> <pass>           legacy (password in argv — insecure, warned)
//	add <user>                  password from stdin (one line)
//	add <user> --password-stdin  password from stdin (one line)
//
// Anything else is a usage error (dExit2 at the call site).
func parseAuthAddArgs(args []string) authAddArgs {
	usage := errors.New("usage: pulsemon auth-user add <username> [<password>|--password-stdin]")
	stdinFlag := false
	rest := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--password-stdin" {
			stdinFlag = true
			continue
		}
		rest = append(rest, a)
	}
	switch len(rest) {
	case 1:
		// No password in argv: it comes from stdin. The explicit flag is
		// accepted too (redundant, but explicit intent is good).
		return authAddArgs{user: rest[0], fromStdin: true}
	case 2:
		if stdinFlag {
			return authAddArgs{err: usage} // <user> <pass> + flag is ambiguous
		}
		return authAddArgs{user: rest[0], pass: rest[1]}
	default:
		return authAddArgs{err: usage}
	}
}

// readPasswordLine reads one line from r, stripping the trailing newline
// (and CR). An empty result is an error up front: it would otherwise hit
// the weak-password gate with a confusing message.
func readPasswordLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", errors.New("empty password on stdin")
	}
	return line, nil
}

// runAuthUser manages dashboard accounts from the host:
//
//	pulsemon auth-user add <username> <password>      (legacy; password in argv)
//	pulsemon auth-user add <username>                 (password from stdin, one line)
//	pulsemon auth-user add <username> --password-stdin (password from stdin, one line)
//	pulsemon auth-user remove <username>
//	pulsemon auth-user list
//
// add on an open (no-users) dashboard is what enables authentication.
// remove is refused for the last remaining user — `auth-user remove` on
// the final account errors, and the "disable authentication" action in the
// dashboard (which removes all users) is the explicit off-switch.
//
// The 3-arg form keeps the password in argv (visible in `ps` and shell
// history), so it warns; the stdin forms are the recommended path. When
// the stdin forms read from a TTY they warn that the input will be echoed
// (x/term is not a dependency, so there is no echo suppression).
func runAuthUser(args []string) dispatchKind {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, authUserUsage)
		return dExit2
	}
	db, err := NewDB(dbPathFromEnv())
	if err != nil {
		log.Printf("auth-user: open: %v", err)
		return dExit1
	}
	defer db.Close()
	// The users table is created by InitSchema (the server runs it on
	// startup); run it here too so the CLI works on a store that has
	// never had a server boot (idempotent).
	if err := db.InitSchema(); err != nil {
		log.Printf("auth-user: schema: %v", err)
		return dExit1
	}
	a := NewAuthState(db)
	switch args[0] {
	case "add":
		p := parseAuthAddArgs(args[1:])
		if p.err != nil {
			fmt.Fprintln(os.Stderr, p.err.Error())
			return dExit2
		}
		if p.fromStdin {
			// A pipe/file stdin (the normal case) is read silently; a TTY
			// would echo — say so, since there is no echo suppression
			// (x/term is not a dependency).
			if fi, serr := os.Stdin.Stat(); serr == nil && fi.Mode()&os.ModeCharDevice != 0 {
				fmt.Fprintln(os.Stderr, "warning: reading the password from the terminal; it will be echoed")
			}
			line, rerr := readPasswordLine(os.Stdin)
			if rerr != nil {
				fmt.Fprintln(os.Stderr, "auth-user add: password from stdin:", rerr)
				return dExit1
			}
			p.pass = line
		} else {
			fmt.Fprintln(os.Stderr, "warning: the password is visible in `ps` and shell history — prefer `pulsemon auth-user add <username>` (password from stdin) or `--password-stdin`")
		}
		if err := a.AddUser(p.user, p.pass); err != nil {
			fmt.Fprintln(os.Stderr, "auth-user add:", err)
			return dExit1
		}
		if n, _ := db.UserCount(); n == 1 {
			fmt.Println("Dashboard authentication is now ENABLED —", p.user, "can log in at the dashboard URL.")
		} else {
			fmt.Println("User added:", p.user)
		}
		return dExit0
	case "remove":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: pulsemon auth-user remove <username>")
			return dExit2
		}
		if err := a.RemoveUser(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "auth-user remove:", err)
			return dExit1
		}
		if n, _ := db.UserCount(); n == 0 {
			fmt.Println("Dashboard authentication is now DISABLED — no users remain.")
		} else {
			fmt.Println("User removed:", args[1])
		}
		return dExit0
	case "list":
		users, err := db.ListUsers()
		if err != nil {
			log.Printf("auth-user list: %v", err)
			return dExit1
		}
		if len(users) == 0 {
			fmt.Println("No dashboard users — authentication is disabled.")
			return dExit0
		}
		for _, u := range users {
			fmt.Println(u.Username)
		}
		return dExit0
	default:
		fmt.Fprintf(os.Stderr, "unknown auth-user action %q\n%s\n", args[0], authUserUsage)
		return dExit2
	}
}

// migrateAuthBootstrapped marks legacy installs as bootstrapped so the
// setup-mode gate (authGate) only applies to genuinely fresh installs.
//
// v0.3.10 incident: an install that predates the setup-mode gate and ran
// with auth off — zero users, no auth_bootstrapped flag — is indistinguishable
// from a fresh install, and upgrading it locked the dashboard to the
// bootstrap surface (prod zenweb). The discriminator is probe history: a
// legacy install has rows in probes; a fresh install has none. A legacy
// install keeps its documented "auth off = fully open" behavior; a fresh
// install stays in setup mode until the first account exists.
//
// Idempotent: once a user exists or the flag is set, it is a no-op.
func migrateAuthBootstrapped(db *DB) {
	n, err := db.UserCount()
	if err != nil || n > 0 {
		return
	}
	if db.GetSetting("auth_bootstrapped") == "1" {
		return
	}
	var probes int
	if err := db.QueryRow("SELECT COUNT(*) FROM probes").Scan(&probes); err != nil || probes == 0 {
		return
	}
	if err := db.SetSetting("auth_bootstrapped", "1"); err != nil {
		log.Printf("WARNING: failed to set auth_bootstrapped flag: %v", err)
		return
	}
	log.Println("Legacy install (probe history, no accounts): keeping auth off — dashboard stays fully open")
}

func main() {
	// Self-update, healthcheck, and version are dispatched before the server
	// starts; unknown flags are rejected there (see dispatch). The data dir
	// is ensured in runServer (the only path that opens the DB), NOT here —
	// a `-version`/`update`/`healthz` invocation must work on a host where
	// the default data dir can't be created (non-root, /data absent);
	// fatalling at process start broke the whole CLI surface (v0.3.20 verification catch).
	switch dispatch(os.Args) {
	case dExit0:
		return
	case dExit1:
		os.Exit(1)
	case dExit2:
		os.Exit(2)
	}

	// Platform entry point: a signal-driven loop on Linux, the Windows service
	// control manager on Windows. Both funnel into runServer (main_linux.go /
	// main_windows.go).
	runMain()
}

// runServer starts the DB, probe worker, and HTTP server, then blocks until
// stop is closed, then performs the clean shutdown sequence. It is the single
// server body shared by every runtime: the Linux signal path and the Windows
// service path both close `stop` to trigger the identical shutdown.
func runServer(stop <-chan struct{}) {
	// Ensure the platform data dir exists before the DB opens. On Linux this
	// also refuses a RELATIVE PULSEMON_DB (F15) — a hard startup error,
	// because a relative path would put the DB (and its secrets) in the
	// process's working directory. This lives here (not in main) so the
	// -version/update/healthz CLI dispatch works on hosts where the default
	// data dir can't be created.
	if err := ensureDataDir(); err != nil {
		log.Fatalf("pulsemon: %v", err)
	}

	db, err := NewDB(dbPathFromEnv())
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()

	if err := db.InitSchema(); err != nil {
		log.Fatalf("Failed to init schema: %v", err)
	}

	// Legacy-install migration (v0.3.10 incident): pre-setup-mode installs
	// that ran with auth off must stay fully open — see
	// migrateAuthBootstrapped.
	migrateAuthBootstrapped(db)

	if err := db.SeedSensors(); err != nil {
		log.Printf("Warning: failed to seed sensors: %v", err)
	}

	pw := NewProbeWorker(db)
	ctx, cancel := context.WithCancel(context.Background())
	// Track the worker so shutdown can wait for it: Run returns only after
	// every per-sensor probe loop has exited (see ProbeWorker.Run), which is
	// the guarantee that no probe write is in flight when we close the DB.
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		pw.Run(ctx)
	}()

	server := NewServer(db, pw)
	// authGate re-checks the enabled state (user count) per request: a
	// host `pulsemon auth-user add/remove` must take effect on the very
	// next request without a restart.
	srv := newHTTPServer(server.authGate())
	startListener(srv, db)

	<-stop
	log.Println("Shutting down...")

	// 1. Stop the HTTP server FIRST: the listener closes immediately, and
	// every ACTIVE handler (dashboard polls, settings tests, sensor edits)
	// drains up to 5s while the DB is still open and the probe worker is
	// still alive. The server used to stop LAST: a handler slower than the 5s drain budget — an SMTP test
	// against a hanging server runs up to ~25s (10s dial + 15s conn
	// deadline), a webhook test up to its 10s client timeout, a plain DB
	// read blocked on a write lock just as easily — kept running past the
	// deferred db.Close() below and answered with "sql: Database is
	// closed". Stopping the worker/alerts first was never a dependency of
	// any handler: they read the DB (open until the very end) and the
	// in-memory stats cache (frozen once the worker stops, still
	// readable).
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	// log.Printf (NOT Fatalf): a shutdown error must not exit before the
	// deferred db.Close() runs — an aborted Close can leave the WAL in a
	// state the next boot has to recover from.
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
	log.Println("Server exited")

	// 2. Stop background probing so no new probe writes start, and wait for
	// in-flight probes to finish (Run blocks until its sensor loops exit).
	cancel()
	select {
	case <-workerDone:
		log.Println("Probe worker stopped")
	case <-time.After(10 * time.Second):
		// Probes are cancellable (the loop ctx threads through doProbe into
		// DNS + the transport), so a cancelled worker returns well within
		// this budget even for a 30s-timeout sensor mid-probe. If it ever
		// fires, a goroutine is stuck beyond its ctx — the DB close below
		// would abort an in-flight write, so log it loudly.
		log.Println("WARNING: probe worker did not stop in 10s; in-flight probes may be aborted")
	}

	// 3. Abort in-flight webhook POSTs. Without this, a delivery stuck in a
	// network blip keeps its connection open until the client's 10s timeout
	// and holds process exit that long; with stopCtx cancelled, it aborts at
	// the next read instead.
	pw.StopAlerts()

	// 4. Drain in-flight alert deliveries BEFORE the deferred db.Close: an
	// alert fired on the final probe tick is a fire-and-forget goroutine
	// whose first act is a settings read — without this, Close() lands mid
	// delivery and the alert dies. In-flight POSTs are already aborted by
	// StopAlerts, so this drain is effectively immediate; the 15s is a
	// backstop only.
	pw.DrainAlerts(15 * time.Second)
	log.Println("Alert deliveries drained")
}
