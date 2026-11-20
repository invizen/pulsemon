package main

// EngineMode/EngineDead are the healthz-visible ICMP transport state. They
// must be SAFE to read BEFORE the shared engine has initialized (a /api/healthz
// poll can land before the probe worker's startup warm-up) and must flip to
// "dead" once the one-shot open has failed. Both take only the read lock, so
// they never participate in the init.
// History: docs/DECISIONS.md → testing-benchmark-gaps

import "testing"

func TestEngineModeDeadBeforeSharedEngine(t *testing.T) {
	// Reset the one-shot state so this test observes the pre-init contract
	// regardless of what any earlier test in the process did.
	sharedEngineMu.Lock()
	origInst, origErr := sharedEngineInst, sharedEngineErr
	sharedEngineInst, sharedEngineErr = nil, nil
	sharedEngineMu.Unlock()
	t.Cleanup(func() {
		sharedEngineMu.Lock()
		sharedEngineInst, sharedEngineErr = origInst, origErr
		sharedEngineMu.Unlock()
	})

	// Pre-init: no engine, no error.
	if got := EngineMode(); got != "" {
		t.Fatalf("EngineMode() before init = %q, want \"\" (engine not started)", got)
	}
	if EngineDead() {
		t.Fatal("EngineDead() before init = true, want false (no open attempted yet)")
	}

	// Simulate a failed one-shot open (both transports down): dead, and the
	// mode stays "" (there is no live engine to report a mode for).
	sharedEngineMu.Lock()
	sharedEngineErr = errNoIcmpTransport
	sharedEngineMu.Unlock()
	if !EngineDead() {
		t.Fatal("EngineDead() after a failed open = false, want true (stable dead condition for healthz)")
	}
	if got := EngineMode(); got != "" {
		t.Fatalf("EngineMode() after a failed open = %q, want \"\" (no live engine to report)", got)
	}
}
