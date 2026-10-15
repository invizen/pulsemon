//go:build linux

package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

// defaultDBPath is the Linux data location: the Docker /data volume (the one
// persistent mount the container gets).
func defaultDBPath() string {
	return "/data/pulsemon.db"
}

// ensureDataDir prepares the data dir and hardens its permissions. The dir
// holds the SQLite DB (bcrypt hashes) and the settings table with plaintext
// webhook/Telegram/SMTP secrets, so it must be owner-only: umask 0o077 for
// everything this process creates from here on (the DB, -wal/-shm, the
// dashboard TLS files), 0o700 for the dir itself, and an in-place upgrade
// pass for pre-existing world-readable installs.
//
// It acts on the directory of the DB ACTUALLY in use (dbPathFromEnv, i.e.
// PULSEMON_DB when set): an operator who points PULSEMON_DB elsewhere keeps
// that dir hardened, and the platform default dir is only created/touched
// when the default is in effect.
func ensureDataDir() {
	_ = syscall.Umask(0o077)
	dbPath := dbPathFromEnv()
	_ = os.MkdirAll(filepath.Dir(dbPath), 0o700)
	hardenDataDir(dbPath)
}

// hardenDataDir tightens the directory of the given DB path in place: 0700
// on the dir, 0600 on the DB and its WAL sidecars (derived from the actual
// path, so a non-default base name is covered too). A missing -wal/-shm is
// normal (WAL not active); a chmod failure (e.g. the dir is owned by
// another user) is logged, never fatal — the server must still start.
func hardenDataDir(dbPath string) {
	dir := filepath.Dir(dbPath)
	if err := os.Chmod(dir, 0o700); err != nil {
		log.Printf("data dir: chmod %s: %v (continuing)", dir, err)
		return
	}
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			log.Printf("data dir: chmod %s: %v (continuing)", p, err)
		}
	}
}

// icmpHint is the /api/healthz hint shown when no ICMP transport could open.
func icmpHint() string {
	return "ICMP socket unavailable: this uid is outside net.ipv4.ping_group_range and CAP_NET_RAW is not granted. Fix: sudo sysctl -w net.ipv4.ping_group_range=\"0 65535\" (persist via /etc/sysctl.d/90-pulsemon-ping.conf) and restart pulsemon — or grant CAP_NET_RAW. See `journalctl -u pulsemon` for the exact error."
}

// runMain is the Linux entry point: block on SIGINT/SIGTERM, then run the
// server (which shuts down cleanly once the stop channel is closed). The
// signal is bridged to a chan struct{} because runServer is shared with the
// Windows service path (which has no signals — the SCM closes the channel).
func runMain() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	stop := make(chan struct{})
	go func() {
		<-sig
		close(stop)
	}()
	runServer(stop)
}
