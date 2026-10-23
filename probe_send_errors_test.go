package main

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// ---------------------------------------------------------------- C3

func TestFix_C3_PerTargetSendErrorsAreNotEngineFailures(t *testing.T) {
	for name, err := range map[string]error{
		"ENETUNREACH":      syscall.ENETUNREACH,
		"EHOSTUNREACH":     syscall.EHOSTUNREACH,
		"EPERM(netfilter)": syscall.EPERM,
		"EACCES":           syscall.EACCES,
		"wrapped":          &os.SyscallError{Syscall: "sendto", Err: syscall.ENETUNREACH},
	} {
		if isBrokenSendErr(err) {
			t.Errorf("%s classified as engine-broken; it is a per-target loss", name)
		}
	}
	for name, err := range map[string]error{
		"EBADF":         syscall.EBADF,
		"ENOTSOCK":      syscall.ENOTSOCK,
		"ErrClosed":     net.ErrClosed,
		"wrapped EBADF": &os.SyscallError{Syscall: "sendto", Err: syscall.EBADF},
	} {
		if !isBrokenSendErr(err) {
			t.Errorf("%s should be engine-broken", name)
		}
	}
}

func TestFix_C3_PingPerTargetErrorDoesNotTouchGlobalCounter(t *testing.T) {
	probeErrCount.Store(0)
	e := &Engine{send: func(net.IP, uint16) error { return syscall.ENETUNREACH }}
	res := e.Ping(context.Background(), net.ParseIP("10.255.255.1").To4(), 50*time.Millisecond)
	if !res.Lost || res.Broken {
		t.Fatalf("res = %+v, want Lost && !Broken", res)
	}
	if n := probeErrCount.Load(); n != 0 {
		t.Fatalf("probeErrCount = %d after a per-target send error, want 0", n)
	}
	e2 := &Engine{send: func(net.IP, uint16) error { return syscall.EBADF }}
	res = e2.Ping(context.Background(), net.ParseIP("10.255.255.2").To4(), 50*time.Millisecond)
	if !res.Lost || !res.Broken || probeErrCount.Load() != 1 {
		t.Fatalf("EBADF: res=%+v count=%d, want Lost && Broken && count 1", res, probeErrCount.Load())
	}
	probeErrCount.Store(0)
}

func TestFix_C3_OtherSensorsErrorsDoNotChangeStatus(t *testing.T) {
	db := fcDB(t)
	fcSensor(t, db, "a", "a", "active")
	now := time.Now()
	for i := 0; i < 4; i++ { // 4 straight losses => error
		fcProbe(t, db, "a", now.Add(time.Duration(i-5)*time.Second), nil)
	}
	pw := NewProbeWorker(db)
	probeErrCount.Store(7) // another sensor/engine bumped the global counter
	defer probeErrCount.Store(0)
	c := sensorConfig{id: "a", downAfter: 2, lossWarn: 25}
	if got := pw.deriveStatus(c, "up"); got != "error" {
		t.Fatalf("derived %q with an unrelated global counter bump, want error", got)
	}
}

func TestFix_C3_BrokenProbeKeepsErrorAndFlagsWarning(t *testing.T) {
	pw := NewProbeWorker(nil)
	c := sensorConfig{id: "a", downAfter: 2, lossWarn: 25, probeBroken: true}
	if got := pw.deriveStatus(c, "error"); got != "error" {
		t.Errorf("broken probe on an error sensor derived %q, want error (no fake partial recovery)", got)
	}
	if got := pw.deriveStatus(c, "up"); got != "warning" {
		t.Errorf("broken probe on an up sensor derived %q, want warning", got)
	}
}
