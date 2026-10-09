package main

import (
	"net"
	"runtime"
	"testing"
	"time"
)

// TestPingTimerLifecycle locks the Ping timeout path against a mock
// transport (no real ICMP): a reply still returns the RTT, a blackholed
// target still times out as a loss with no Error, the pending map drains
// (no slot leak per probe), and the goroutine count settles — the fix
// (time.NewTimer + defer Stop instead of time.After) must not change any
// of Ping's observable behavior while removing the timer.
func TestPingTimerLifecycle(t *testing.T) {
	// Mock engine: one reply that lands 30ms after send, everything else
	// blackholed. (Late binding via ePtr: the send closure runs after e
	// exists, so it can reach e.deliver without a circular init.)
	var ePtr *Engine
	e := &Engine{
		send: func(dst net.IP, seq uint16) error {
			if dst.Equal(net.ParseIP("10.9.9.9").To4()) {
				go func() {
					time.Sleep(30 * time.Millisecond)
					ePtr.deliver(seq, net.ParseIP("10.9.9.9").To4())
				}()
			}
			return nil
		},
		mode: "mock",
	}
	ePtr = e

	t.Run("reply returns RTT and drains pending", func(t *testing.T) {
		res := e.Ping(net.ParseIP("10.9.9.9").To4(), 500*time.Millisecond)
		if res.Lost {
			t.Fatal("expected a reply, got loss")
		}
		if res.Error != nil {
			t.Fatalf("unexpected error: %v", res.Error)
		}
		if res.RTT < 20*time.Millisecond || res.RTT > 2*time.Second {
			t.Fatalf("RTT = %v, want ~30ms", res.RTT)
		}
		if n := len(pending); n != 0 {
			t.Fatalf("pending map not drained after reply: %d entries", n)
		}
	})

	t.Run("timeout is a clean loss, no Error, drains pending", func(t *testing.T) {
		res := e.Ping(net.ParseIP("10.8.8.8").To4(), 120*time.Millisecond)
		if !res.Lost {
			t.Fatal("expected loss for blackholed target")
		}
		if res.Error != nil {
			t.Fatalf("timeout must be a clean loss (no send error), got: %v", res.Error)
		}
		if n := len(pending); n != 0 {
			t.Fatalf("pending map not drained after timeout: %d entries", n)
		}
	})

	t.Run("no goroutine or timer churn across 100 probes", func(t *testing.T) {
		base := runtime.NumGoroutine()
		for i := 0; i < 100; i++ {
			// 20ms timeout: every probe here times out (no reply path for
			// 10.7.7.7), so 100 abandoned timeout paths in a row.
			if res := e.Ping(net.ParseIP("10.7.7.7").To4(), 20*time.Millisecond); !res.Lost {
				t.Fatalf("probe %d: expected loss", i)
			}
		}
		// Let any leaked goroutines surface.
		time.Sleep(300 * time.Millisecond)
		if n := len(pending); n != 0 {
			t.Fatalf("pending map leaked %d entries after 500 probes", n)
		}
		now := runtime.NumGoroutine()
		if now > base+5 {
			t.Errorf("goroutine churn: %d -> %d after 100 probes", base, now)
		}
	})
}
