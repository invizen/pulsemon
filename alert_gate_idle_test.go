package main

import (
	"sync"
	"testing"
	"time"
)

// setAlertGateIdle shrinks the consumer's idle-exit window for the
// duration of a test (2026-10-23 external review F7).
func setAlertGateIdle(t *testing.T, d time.Duration) {
	t.Helper()
	old := alertGateIdle
	alertGateIdle = d
	t.Cleanup(func() { alertGateIdle = old })
}

// gateEntry reports whether id currently has an alert gate registered.
func gateEntry(pw *ProbeWorker, id string) bool {
	pw.alertMu.Lock()
	defer pw.alertMu.Unlock()
	_, ok := pw.alertOrderGates[id]
	return ok
}

// waitGateGone polls until id's gate is gone. In these tests Remove is
// never called, and the ONLY thing that drops the entry is the consumer
// itself — as its last act, under alertMu, immediately before returning
// — so a gone entry proves the consumer goroutine has exited.
func waitGateGone(t *testing.T, pw *ProbeWorker, id string, deadline time.Duration) {
	t.Helper()
	by := time.Now().Add(deadline)
	for time.Now().Before(by) {
		if !gateEntry(pw, id) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("gate for %q still registered after %s (consumer did not exit on idle)", id, deadline)
}

// TestAlertGateIdleExits is the F7 regression test: the old "for job :=
// range ch" consumer lived forever — Remove drops the map entry, the
// channel is never closed (a closed-channel send would panic an in-flight
// sendWebhook), so one goroutine leaked per deleted sensor for the
// process lifetime. Now the consumer reaps itself after alertGateIdle
// with an empty queue, and in this test (no Remove call) the ONLY thing
// that can drop the entry is the exiting consumer.
func TestAlertGateIdleExits(t *testing.T) {
	setAlertGateIdle(t, 30*time.Millisecond)
	pw := NewProbeWorker(nil)

	pw.enqueueAlert("s1", func() {})
	waitGateGone(t, pw, "s1", 2*time.Second)
}

// TestAlertGateIdleRecycles: a quiet sensor's consumer is recycled, and
// the NEXT alert re-creates the gate and is delivered — idle exit must
// not make the sensor deaf.
func TestAlertGateIdleRecycles(t *testing.T) {
	setAlertGateIdle(t, 30*time.Millisecond)
	pw := NewProbeWorker(nil)

	got := make(chan int, 8)
	pw.enqueueAlert("s1", func() { got <- 1 })
	select {
	case v := <-got:
		if v != 1 {
			t.Fatalf("job 1 delivered as %d", v)
		}
	case <-time.After(time.Second):
		t.Fatal("job 1 not delivered")
	}
	waitGateGone(t, pw, "s1", 2*time.Second)

	pw.enqueueAlert("s1", func() { got <- 2 })
	select {
	case v := <-got:
		if v != 2 {
			t.Fatalf("job 2 delivered as %d", v)
		}
	case <-time.After(time.Second):
		t.Fatal("job 2 not delivered after gate recycle (sensor went deaf)")
	}
}

// TestAlertGateBusyKeepsConsumer: a job queued behind a blocked one must
// keep the consumer alive across an idle fire — the exit check only
// passes on an EMPTY queue, so a non-empty queue at fire time resets the
// timer and both jobs get delivered, in order.
func TestAlertGateBusyKeepsConsumer(t *testing.T) {
	setAlertGateIdle(t, 30*time.Millisecond)
	pw := NewProbeWorker(nil)

	release := make(chan struct{})
	got := make(chan int, 4)
	pw.enqueueAlert("s1", func() { <-release; got <- 1 })
	pw.enqueueAlert("s1", func() { got <- 2 })

	// Let the idle timer fire at least once while job 1 blocks with job 2
	// queued (the consumer is inside job(), not in its select — the fired
	// timer value is drained by the post-job reset).
	time.Sleep(150 * time.Millisecond)
	close(release)

	for i := 1; i <= 2; i++ {
		select {
		case v := <-got:
			if v != i {
				t.Fatalf("delivery %d = %d (out of order)", i, v)
			}
		case <-time.After(time.Second):
			t.Fatalf("job %d not delivered (consumer reaped a non-empty queue?)", i)
		}
	}
}

// TestAlertGateSendAfterIdleExit: a send that lands AFTER the consumer
// has exited must create a fresh gate and be delivered. The locked
// enqueue (F7) makes "send into an orphaned buffer" impossible: the map
// read and the send are one critical section, and the consumer's
// exit check runs under the same lock.
func TestAlertGateSendAfterIdleExit(t *testing.T) {
	setAlertGateIdle(t, 30*time.Millisecond)
	pw := NewProbeWorker(nil)

	pw.enqueueAlert("s1", func() {})
	waitGateGone(t, pw, "s1", 2*time.Second)

	got := make(chan int, 1)
	pw.enqueueAlert("s1", func() { got <- 7 })
	select {
	case v := <-got:
		if v != 7 {
			t.Fatalf("job delivered as %d", v)
		}
	case <-time.After(time.Second):
		t.Fatal("post-exit send was orphaned (dropped alert)")
	}
}

// TestAlertGateFIFOOrder: the F4 invariant under the new consumer shape —
// a sensor's alerts are delivered strictly in launch order, even when the
// enqueue fills the 8-slot buffer.
func TestAlertGateFIFOOrder(t *testing.T) {
	setAlertGateIdle(t, 30*time.Millisecond)
	pw := NewProbeWorker(nil)

	const n = 8
	got := make(chan int, n)
	var wg sync.WaitGroup
	for i := 1; i <= n; i++ {
		i := i
		wg.Add(1)
		pw.enqueueAlert("s1", func() {
			got <- i
			wg.Done()
		})
	}
	for i := 1; i <= n; i++ {
		select {
		case v := <-got:
			if v != i {
				t.Fatalf("delivery %d = %d (FIFO order broken)", i, v)
			}
		case <-time.After(time.Second):
			t.Fatalf("job %d not delivered", i)
		}
	}
	wg.Wait()
}
