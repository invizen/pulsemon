package main

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

// The REAL unprivileged-ICMP path on Linux: a SOCK_DGRAM socket with
// IPPROTO_ICMP, gated by net.ipv4.ping_group_range (NOT CAP_NET_RAW).
// This is the socket type the `ping` binary uses when run unprivileged.
func TestUnprivilegedICMPDatagram(t *testing.T) {
	fmt.Printf("uid=%d euid=%d\n", os.Getuid(), os.Geteuid())

	if b, err := os.ReadFile("/proc/sys/net/ipv4/ping_group_range"); err == nil {
		fmt.Printf("ping_group_range: %s\n", string(b))
	}

	// socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		fmt.Printf("SOCK_DGRAM ICMP socket: FAILED: %v\n", err)
		return
	}
	fmt.Printf("SOCK_DGRAM ICMP socket: OK (fd=%d)\n", fd)
	syscall.Close(fd)
}
