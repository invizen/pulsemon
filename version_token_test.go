package main

// fetchRelease URL-path guard: normal tags (incl. pre-release) pass, traversal
// and whitespace/control junk fail (and fetchRelease surfaces a clean error).

import (
	"net/http"
	"strings"
	"testing"
)

// TestValidVersionToken locks the fetchRelease URL-path guard: normal tags
// (incl. pre-release) pass, traversal and whitespace/control junk fail.
func TestValidVersionToken(t *testing.T) {
	ok := []string{"v0.2.2", "v1.0", "v10.20.30", "v1.2.3-rc1", "v1.2.3+build5"}
	bad := []string{"", "v", "0.2.2", "v../evil", "v0.2 2", "v0.2.2\n", "v" + strings.Repeat("9", 50), "v0.2.2; rm"}
	for _, s := range ok {
		if !validVersionToken(s) {
			t.Errorf("validVersionToken(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validVersionToken(s) {
			t.Errorf("validVersionToken(%q) = true, want false", s)
		}
	}
}

// TestFetchReleaseRejectsBadVersion proves fetchRelease surfaces a clean
// error (not a nil-req panic) for a malformed pinned version.

// TestFetchReleaseRejectsBadVersion proves fetchRelease surfaces a clean
// error (not a nil-req panic) for a malformed pinned version.
func TestFetchReleaseRejectsBadVersion(t *testing.T) {
	cases := []string{"v../evil", "v0.2 2", "v\n"}
	for _, v := range cases {
		rel, err := fetchRelease(http.DefaultClient, v)
		if err == nil {
			t.Errorf("fetchRelease(%q) = %+v, want error", v, rel)
		}
	}
}

// TestUpdateCheckStaleOnFailure pins the negative-caching behavior: once a
// good result is cached, a failing GitHub lookup serves the stale result
// with cached:true instead of 503, and the failure is suppressed for
// updateCheckFailTTL (no repeated upstream hits).
