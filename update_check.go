package main

import (
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// updateCheckResult is the cached outcome of a GitHub releases lookup.
// It is served from memory for updateCheckTTL to avoid hammering the
// GitHub API on every poll cycle.
type updateCheckResult struct {
	Running   string `json:"running"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	URL       string `json:"url"`
	CheckedAt string `json:"checked_at"`
	// Cached is true when the response was served from the last known
	// result while the GitHub check was failing (stale-but-useful), as
	// opposed to a fresh-lookup success.
	Cached bool `json:"cached,omitempty"`
}

var (
	// updateCheckMu guards the four state vars below ONLY — it is never
	// held across the network fetch. The fetch itself is single-flighted
	// by updateCheckFlight: concurrent cache misses coalesce into ONE
	// upstream call (the old mutex-across-fetch serialized every poll
	// behind one 10s miss AND raced updateCheckAttemptAt, whose throttle
	// read happened before the lock).
	updateCheckMu     sync.Mutex
	updateCheckCached *updateCheckResult
	updateCheckAt     time.Time
	// updateCheckAttemptAt is the time of the last fetchRelease ATTEMPT
	// (success or failure). It drives the ?refresh=1 throttle: unlike
	// updateCheckAt (the last SUCCESS, which ages the stale entry and never
	// advances on a failure), a failed attempt must also count, or an outage
	// would let ?refresh=1 keep forcing GitHub calls.
	updateCheckAttemptAt time.Time
	updateCheckTTL       = 30 * time.Minute
	// updateCheckRefreshMinInterval is the minimum time between two GitHub
	// fetches forced by ?refresh=1. Without it, an authenticated user (or
	// anyone on the LAN when auth is off) can spam the check: every
	// ?refresh=1 bypasses the 30-min cache and forces a fetch, walking
	// straight into GitHub's 60 req/hour unauthenticated limit. A refresh
	// younger than this is ignored and served from the cache like a normal
	// poll. 60s keeps an explicit "check now" useful while bounding forced
	// calls to one per minute.
	updateCheckRefreshMinInterval = 60 * time.Second
	// How long a failed check suppresses new GitHub calls. Without this,
	// every 5s dashboard poll during an outage re-hits the API and walks
	// into a secondary rate limit, making the failure sticky.
	updateCheckFailed  bool
	updateCheckFailTTL = 1 * time.Minute

	updateCheckFlight singleflight.Group
)

// handleUpdateCheck reports whether a newer release is available on
// GitHub. It reuses fetchRelease + newerRelease from update.go so the
// version-comparison logic stays in one place.
//
// Caching: successes are served from memory for updateCheckTTL; failures
// are suppressed for updateCheckFailTTL, and while suppressed the last
// known result is served as stale instead of erroring — a transient GitHub
// outage must not blank the version pill or hammer the API. With no cached
// result at all, a failure is a 503. Only a fresh success overwrites the
// cached result (the stale response carries cached:true).
//
// ?refresh=1 forces a fresh lookup, but only when the last fetch attempt
// was at least updateCheckRefreshMinInterval ago; a fresher refresh is
// ignored and served from the cache like a normal poll, so the endpoint
// cannot be used to hammer the GitHub API.
//
// Locking: updateCheckMu guards state only (microseconds); responses are
// written outside it, and concurrent misses coalesce on the singleflight
// fetch, so a slow upstream blocks at most one goroutine per flight —
// cached-hit polls sail past untouched.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	refresh := r.URL.Query().Get("refresh") == "1"

	updateCheckMu.Lock()
	if refresh && time.Since(updateCheckAttemptAt) < updateCheckRefreshMinInterval {
		refresh = false
	}
	var res updateCheckResult
	if updateCheckCached != nil {
		res = *updateCheckCached
		age := time.Since(updateCheckAt)
		switch {
		case !refresh && !updateCheckFailed && age < updateCheckTTL:
			updateCheckMu.Unlock()
			respondWithJSON(w, http.StatusOK, res)
			return
		case !refresh && updateCheckFailed && age < updateCheckFailTTL:
			res.Cached = true
			updateCheckMu.Unlock()
			respondWithJSON(w, http.StatusOK, res)
			return
		}
	}
	updateCheckMu.Unlock()

	// Miss (or an honored refresh): coalesce on ONE upstream fetch. The
	// flight updates state under the lock at attempt and completion; the
	// returned outcome is what every joining caller serves.
	v, _, _ := updateCheckFlight.Do("latest", func() (any, error) {
		updateCheckMu.Lock()
		updateCheckAttemptAt = time.Now()
		updateCheckMu.Unlock()

		client := &http.Client{Timeout: 10 * time.Second}
		rel, err := fetchRelease(client, "latest")

		updateCheckMu.Lock()
		defer updateCheckMu.Unlock()
		if err != nil {
			// The raw error can name upstream URLs, the resolver, or proxy
			// config — details belong in the log, not the response body
			// (same contract as respondInternal).
			log.Printf("update check: %v", err)
			if updateCheckCached != nil {
				updateCheckFailed = true // updateCheckAt unchanged: it ages the stale entry
				out := *updateCheckCached
				out.Cached = true
				return out, nil
			}
			return nil, nil // no cache to fall back on: caller answers 503
		}
		latest := rel.TagName
		out := updateCheckResult{
			Running:   Version,
			Latest:    latest,
			Available: newerRelease(latest, Version),
			URL:       "https://github.com/invizen/pulsemon/releases/tag/" + url.PathEscape(latest),
			CheckedAt: time.Now().UTC().Format(time.RFC3339),
		}
		updated := out
		updateCheckCached = &updated
		updateCheckAt = time.Now()
		updateCheckFailed = false
		return out, nil
	})

	if v == nil {
		respondWithError(w, http.StatusServiceUnavailable, "update check failed (upstream unreachable); try again later")
		return
	}
	respondWithJSON(w, http.StatusOK, v.(updateCheckResult))
}
