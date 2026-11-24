package main

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
)

// These pins lock the poll-response float contract (external review
// finding #4, 2026-11-24): RTTs are float32 in the series and widened to
// float64 for JSON. A bare widening carries float32 quantization noise
// (12.34 becomes 12.34000015258789) — digits the measurement cannot
// support, ~90 of them per sensor per 5s poll, compressing poorly under
// gzip. Every response-exit site must round to 1µs (0.001 ms) so the
// wire carries clean values. Decisioning math (loss counts, status
// derivation) reads the RAW series, never these fields.

// TestRTTToPtrRoundsWideningNoise pins the helper at the exact values the
// finding names: the widened noise is gone, the 1µs resolution survives,
// and lost (NaN) still maps to nil.
func TestRTTToPtrRoundsWideningNoise(t *testing.T) {
	if got := rttToPtr(float32(12.34)); got == nil || *got != 12.34 {
		t.Fatalf("rttToPtr(float32(12.34)) = %v, want 12.34 — the float32 widening noise (12.34000015258789) must not reach the wire", ptrStr(got))
	}
	if got := rttToPtr(float32(15.67)); got == nil || *got != 15.67 {
		t.Fatalf("rttToPtr(float32(15.67)) = %v, want 15.67", ptrStr(got))
	}
	// 1µs resolution survives: 12.3446 ms rounds to 12.345, not 12.34.
	if got := rttToPtr(float32(12.3446)); got == nil || *got != 12.345 {
		t.Fatalf("rttToPtr(float32(12.3446)) = %v, want 12.345 (1µs resolution must survive the rounding)", ptrStr(got))
	}
	if got := rttToPtr(float32(math.NaN())); got != nil {
		t.Fatalf("rttToPtr(NaN) = %v, want nil (lost)", *got)
	}
}

func ptrStr(p *float64) string {
	if p == nil {
		return "nil"
	}
	return strconv.FormatFloat(*p, 'g', -1, 64)
}

// TestComputeSensorStatsRTTWireValuesAreClean is the poll-path pin: every
// RTT field of a computed SensorStats — RTTLast, RTTMin/Max/Avg, the 30
// Recent values, HourRTTAvg, and all 60 hour buckets — carries 1µs-clean
// values, and the MARSHALED JSON contains no widening-noise digits.
func TestComputeSensorStatsRTTWireValuesAreClean(t *testing.T) {
	now := int64(1767225600) // fixed instant; all entries fall inside the hour
	const lo, hi = 12.34, 15.67 // both inexact in float32 — the noise case
	entries := make([]probeEntry, 0, 60)
	for i := 59; i >= 0; i-- {
		// Newest entry (i=0) is `lo`; alternate lo/hi.
		v := lo
		if (59-i)%2 == 1 {
			v = hi
		}
		entries = append(entries, probeEntry{ts: now - int64(i)*60, rtt: float32(v)})
	}
	st := computeSensorStats(entries, now, 60, 0)
	if st == nil {
		t.Fatal("computeSensorStats returned nil for 60 entries")
	}

	check := func(name string, got *float64, allowed ...float64) {
		t.Helper()
		if got == nil {
			t.Fatalf("%s = nil, want one of %v", name, allowed)
		}
		for _, a := range allowed {
			if *got == a {
				return
			}
		}
		t.Errorf("%s = %v, want a 1µs-clean value in %v (the float32 widening noise reached the wire)", name, *got, allowed)
	}
	check("RTTLast", st.RTTLast, lo, hi)
	check("RTTMin", st.RTTMin, lo, hi)
	check("RTTMax", st.RTTMax, lo, hi)
	// avg of the alternation: (lo+hi)/2 in float64 over the raw widened
	// values, rounded to 1µs.
	if st.RTTAvg == nil || *st.RTTAvg != 14.005 {
		t.Fatalf("RTTAvg = %v, want 14.005 (rounded mean of the widened lo/hi values)", ptrFloat(st.RTTAvg))
	}
	if st.HourRTTAvg == nil || *st.HourRTTAvg != 14.005 {
		t.Fatalf("HourRTTAvg = %v, want 14.005", ptrFloat(st.HourRTTAvg))
	}
	for i, r := range st.Recent {
		if r == nil {
			t.Fatalf("Recent[%d] = nil, want a value (no lost probes seeded)", i)
		}
		if *r != lo && *r != hi {
			t.Fatalf("Recent[%d] = %v, want a 1µs-clean value (got widening noise)", i, *r)
		}
	}
	for i, h := range st.Hour {
		if h == nil {
			continue // a bucket with no reply is legitimately nil
		}
		if *h != lo && *h != hi {
			t.Fatalf("Hour[%d] = %v, want a 1µs-clean value (got widening noise)", i, *h)
		}
	}

	// The wire itself: marshal and hunt for the noise digits.
	body, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(body)
	for _, noise := range []string{"12.3400001", "15.669999", "0000152", "9999694"} {
		if strings.Contains(s, noise) {
			t.Errorf("poll JSON carries float32 widening noise (%q found) — the response is inflated with digits the measurement cannot support", noise)
		}
	}
	if !strings.Contains(s, "12.34") || !strings.Contains(s, "15.67") {
		t.Errorf("poll JSON missing the clean values: %s", s)
	}
}

// TestComputeSensorStatsRoundingKeepsDecisioningIntact pins the safety
// half: the rounding touches only the display fields. Loss counting and
// the totals come from the RAW series and must be exact.
func TestComputeSensorStatsRoundingKeepsDecisioningIntact(t *testing.T) {
	now := int64(1767225600)
	entries := []probeEntry{
		{ts: now - 120, rtt: float32(12.34444)},
		{ts: now - 60, rtt: float32(math.NaN())}, // lost
		{ts: now, rtt: float32(0.1)},
	}
	st := computeSensorStats(entries, now, 3, 1)
	if st == nil {
		t.Fatal("nil stats")
	}
	if st.Total != 3 || st.LostCount != 1 {
		t.Fatalf("Total/LostCount = %d/%d, want 3/1 (rounding must not touch the decisioning counts)", st.Total, st.LostCount)
	}
	// 1/3 loss — the percentage is a count ratio, not an RTT: it is NOT
	// rounded (its digits are informative), and must stay full-precision.
	// (Tolerance: 1/3*100 and 100/3 can differ by a ulp in rounding order.)
	if got, want := st.LossPct, 100.0/3.0; got < want-1e-9 || got > want+1e-9 {
		t.Fatalf("LossPct = %v, want the ~1/3 ratio (percentages are count math, not float32 noise)", got)
	}
	if st.LossPct == 33.333 {
		t.Fatal("LossPct was rounded to 1µs (33.333) — only RTT values are rounded, never count ratios")
	}
	// The 0.1 ms reply: inexact in float32 (0.10000000149011612), clean on
	// the wire.
	if st.RTTLast == nil || *st.RTTLast != 0.1 {
		t.Fatalf("RTTLast = %v, want 0.1", ptrFloat(st.RTTLast))
	}
}

func ptrFloat(p *float64) string {
	if p == nil {
		return "nil"
	}
	return strconv.FormatFloat(*p, 'g', -1, 64)
}
