package main

import (
	"syscall"
	"testing"
)

// TestDgramSocketCloexec locks the SOCK_CLOEXEC flag on the datagram ICMP
// socket. F_GETFD returns the FD_CLOEXEC bit when the flag is set on the fd;
// the old code (plain SOCK_DGRAM, no CLOEXEC) fails this. The guard matters
// defensively: any future subprocess would otherwise inherit a raw ICMP fd.
//
// Skipped (not failed) on a host without the unprivileged datagram socket —
// there the raw transport is active and this fd simply isn't created.
func TestDgramSocketCloexec(t *testing.T) {
	tt, err := newDgramTransport()
	if err != nil {
		t.Skipf("datagram ICMP socket unavailable on this host (raw transport would be used): %v", err)
	}
	defer tt.close()

	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(tt.fd), syscall.F_GETFD, 0)
	if errno != 0 {
		t.Fatalf("F_GETFD on socket fd %d: %v", tt.fd, errno)
	}
	if int(flags)&syscall.FD_CLOEXEC == 0 {
		t.Fatalf("datagram socket fd %d is missing FD_CLOEXEC — it would be inherited across fork/exec", tt.fd)
	}
}
