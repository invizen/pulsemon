package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestParseRetryAfter pins the Retry-After parsing behind the 2026-10-19
// review M8 fix: integer seconds, HTTP-date relative to now, capped at
// maxAlertRetryAfter, and 0 (use the fixed schedule) for anything else.
func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"7", 7 * time.Second},
		{" 3 ", 3 * time.Second},
		{"-5", 0},
		{"86400", maxAlertRetryAfter},
		{now.Add(20 * time.Second).Format(http.TimeFormat), 20 * time.Second},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
		{"soon", 0},
	}
	for _, c := range cases {
		if got := parseRetryAfter(c.in, now); got != c.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestPostJSONHonorsRetryAfter: a 429 carrying Retry-After must delay the
// next attempt by at least that long, even when the fixed schedule is
// shorter — the old code re-hit a rate-limited provider on the fixed 2s/10s
// regardless (2026-10-19 review M8). A 5xx keeps the fixed delay.
func TestPostJSONHonorsRetryAfter(t *testing.T) {
	withPlainTransport(t, func() {
		old := alertRetryDelays
		alertRetryDelays = []time.Duration{5 * time.Millisecond, 5 * time.Millisecond}
		defer func() { alertRetryDelays = old }()
		pw := NewProbeWorker(nil)

		var mu sync.Mutex
		var hits []time.Time
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits = append(hits, time.Now())
			n := len(hits)
			mu.Unlock()
			if n == 1 {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		if err := pw.postJSON(srv.URL, map[string]interface{}{"text": "x"}); err != nil {
			t.Fatalf("429 then 200 should succeed: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(hits) != 2 {
			t.Fatalf("hits = %d, want 2", len(hits))
		}
		if gap := hits[1].Sub(hits[0]); gap < 950*time.Millisecond {
			t.Fatalf("retry after 429 came %v later, want >= ~1s (Retry-After: 1)", gap)
		}
	})
}
