package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"pulsemon/internal/store"
	"strconv"
	"strings"
)

// Listener / TLS configuration.
//
// HTTP: PULSEMON_ADDR env (install-time, operator choice) or ":9299". The
// dashboard does NOT manage the HTTP port.
//
// HTTPS: served on the "listener_https_port" settings row (default 443),
// bound to the same host as PULSEMON_ADDR. When a cert/key pair is in
// place the dashboard serves HTTPS ONLY on that port — the HTTP port is
// not bound, so nothing is ever reachable in plaintext.
//
// TLS cert/key resolution order:
//  1. PULSEMON_CERT + PULSEMON_KEY env (install-time; both required)
//  2. <data>/tls/cert.pem + key.pem (written by the dashboard's
//     Settings → TLS upload; lives in the data volume so it survives
//     container rebuilds)
//
// A pair that is merely ABSENT (not configured) is fine: plain HTTP.
// A pair that is CONFIGURED (PULSEMON_CERT) but unreadable now FAILS the
// process at startup (certFatal in startListener): silently serving
// plaintext when the operator believes TLS is on is the worse failure.
// An install that stages certs after first boot can keep the old
// warn-and-serve-plaintext behavior with PULSEMON_ALLOW_PLAINTEXT_FALLBACK=1.
// A pair that is in place AND unparseable/mismatched also fails startup.
//
// The runtime-specific restart logic (requestRestart / runRestartCommand)
// lives in listener_linux.go / listener_windows.go — each OS respawns the
// process differently (systemctl / container SIGTERM / re-exec vs the
// Windows SCM).

const defaultHTTPSPort = 443

type listenerCfg struct {
	httpsPort int
	certPath  string // "" = plain HTTP only
	keyPath   string
	source    string // "env" | "dashboard" | ""
}

// loadListenerCfg resolves the listener configuration from env + settings.
// db may be nil (pre-DB contexts); env is always read first.
func loadListenerCfg(db *store.Store) listenerCfg {
	c := listenerCfg{httpsPort: defaultHTTPSPort}
	if db == nil {
		return c
	}
	if p := db.GetSetting("listener_https_port"); p != "" {
		if n, err := parsePort(p); err == nil {
			c.httpsPort = n
		}
	}
	if envCert, envKey := certPaths(); envCert != "" {
		c.certPath, c.keyPath, c.source = envCert, envKey, "env"
		return c
	}
	dir := tlsDir(db)
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if fileExists(cert) && fileExists(key) {
		c.certPath, c.keyPath, c.source = cert, key, "dashboard"
	}
	return c
}

// tlsDir is where the dashboard stores uploaded TLS material: inside the
// data dir (the one volume that always exists and persists).
func tlsDir(db *store.Store) string {
	return filepath.Join(filepath.Dir(dbPathFromEnv()), "tls")
}

// parsePort validates a listener port: 1..65535.
func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not a port: %q", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port out of range: %d", n)
	}
	return n, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// httpsAddrFor derives the TLS listen address from PULSEMON_ADDR (same
// host, HTTPS port): ":80" → ":443", "127.0.0.1:8080" → "127.0.0.1:443",
// "[::1]:8080" → "[::1]:443".
//
// SplitHostPort (NOT a naive LastIndex) so an IPv6 host keeps exactly one
// pair of brackets: JoinHostPort double-wraps a host that already carries
// brackets, and "[[::1]]:443" is an invalid address.
func httpsAddrFor(httpsPort int) string {
	addr := listenAddr()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Bare port or unbracketed IPv6: fall back to the last-colon split,
		// which is right for every form net.Listen accepts.
		host = ""
		if i := strings.LastIndex(addr, ":"); i >= 0 && i+1 < len(addr) {
			host = addr[:i]
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(httpsPort))
}

// restartOutcome is what a restart request produced: the process restarted
// (or is about to), or a hint the operator must run (containers / services).
type restartOutcome struct {
	restarted bool
	hint      string
}
