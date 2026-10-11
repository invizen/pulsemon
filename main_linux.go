//go:build linux

package main

import (
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

// ensureDataDir is a no-op on Linux in the normal Docker case (the /data
// volume already exists; MkdirAll on an existing dir returns nil). It also
// makes a bare-metal Linux run that lacks /data fail with a clear MkdirAll
// error rather than a cryptic SQLite open error.
func ensureDataDir() {
	_ = os.MkdirAll(filepath.Dir(defaultDBPath()), 0o755)
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
