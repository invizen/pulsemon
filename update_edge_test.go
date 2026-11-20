package main

// Pins for the 2026-11-20 review finding #21 (updater buffering, redaction,
// request-decode):
//
//   (a) verifyDownloadedAsset streams the digest ONCE via fileSHA256 — a
//     multi-hundred-MiB asset must not be read into RAM (the old code did
//     os.ReadFile + two in-memory sha256.Sum256 passes);
//   (b) a .sig/.sha256 FETCH failure is redacted from the 502 body (the
//     error text embeds upstream asset URLs / DNS / proxy detail —
//     log-only), while verification VERDICTS (SHA mismatch, bad signature)
//     stay surfaced verbatim because they are operator-actionable;
//   (c) the request body is decoded UNCONDITIONALLY — a chunked body
//     (ContentLength -1) is no longer silently dropped, and a malformed
//     body is a 400 BEFORE any field is consulted, so a truncated body can
//     never partially apply allow_downgrade.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// (a) The streaming path must produce the exact digest the in-memory
// reference does. (Peak memory is the implementation contract: fileSHA256
// copies through a 32 KiB buffer, so the fixture size is deliberately
// multi-chunk — a 512 MiB fixture would be absurd in a unit test.)
func TestVerifyDownloadedAsset_StreamsSinglePassDigest(t *testing.T) {
	_, priv, _ := sigTestSetup(t)
	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	shaHex := hex.EncodeToString(sum[:])

	tmp := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(tmp, payload, 0o755); err != nil {
		t.Fatal(err)
	}
	srv := serveSig(t, signManifest(t, priv, "v9.9.9", targetAsset(), payload))

	got, err := verifyDownloadedAsset(srv.Client(), releaseSelection{
		sigURL: srv.URL, sha: shaHex, tag: "v9.9.9", asset: targetAsset(),
	}, tmp)
	if err != nil {
		t.Fatalf("signed release rejected by the streaming path: %v", err)
	}
	if got != shaHex {
		t.Fatalf("digest = %q, want %q (streamed hash must equal the in-memory reference)", got, shaHex)
	}
}

// (b) The .sig asset is served by a DEAD upstream (connection dropped):
// the fetch error text unavoidably carries the dead server's
// 127.0.0.1:PORT address, which must NOT appear in the 502 body.
func TestUpdateAPIVerifyFetchFailureRedacted(t *testing.T) {
	dead := deadUpstream()
	t.Cleanup(dead.Close)
	sigTestSetup(t) // trusted key embedded (irrelevant — the fetch fails first)

	bin := []byte("fake pulsemon binary payload\n")
	real := sha256.Sum256(bin)
	realHex := hex.EncodeToString(real[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		rel := ghRelease{
			TagName: "v9.9.9",
			Assets: []releaseAsset{
				{Name: targetAsset(), BrowserDownloadURL: "http://" + r.Host + "/releases/bin", Digest: "sha256:" + realHex},
				{Name: targetAsset() + ".sig", BrowserDownloadURL: dead.URL + "/releases/bin.sig"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rel)
	})
	mux.HandleFunc("/releases/bin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(bin)
	})
	gh := httptest.NewServer(mux)
	t.Cleanup(gh.Close)

	oldBase, oldVer := releaseBase, Version
	releaseBase, Version = gh.URL+"/releases", "v0.0.1"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })

	srv := updateServer(t)
	h := setupUpdateHarness(t, false)

	rec := postUpdate(t, srv, "")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "127.0.0.1") {
		t.Fatalf("502 body leaks upstream address detail: %q", body)
	}
	if !strings.Contains(body, "signature") {
		t.Fatalf("502 body lost its actionable verdict: %q", body)
	}
	if got, _ := os.ReadFile(h.exePath); string(got) != "old binary" {
		t.Fatalf("binary was swapped on a fetch failure: %q", got)
	}
}

// (b) contrast: a verification VERDICT (signature valid, advertised digest
// wrong) is operator-actionable and must REMAIN visible in the 502 body —
// redaction applies to fetch failures only.
func TestUpdateAPIVerifyVerdictStillSurfaced(t *testing.T) {
	srv := updateServer(t)
	_ = setupUpdateHarness(t, false)
	base, _ := serveRelease(t, "v9.9.9", "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	oldBase, oldVer := releaseBase, Version
	releaseBase, Version = base, "v0.0.1"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })

	rec := postUpdate(t, srv, "")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "SHA-256 MISMATCH") {
		t.Fatalf("SHA verdict no longer surfaced verbatim: %q", rec.Body.String())
	}
}

// (c) A chunked body reports ContentLength -1. The pin v0.0.1 has no
// /releases/tags/v0.0.1 on the fake server, so a DECODED pin is a 502 —
// while the old `ContentLength > 0` gate dropped the body and answered
// up-to-date (200) for the served v1.0.0 latest. The 502 is the proof the
// chunked body was read.
func TestUpdateAPIChunkedBodyHonored(t *testing.T) {
	srv := updateServer(t)
	_ = setupUpdateHarness(t, false)
	base, _ := serveRelease(t, "v1.0.0", "")
	oldBase, oldVer := releaseBase, Version
	releaseBase, Version = base, "v9.9.9"
	t.Cleanup(func() { releaseBase, Version = oldBase, oldVer })

	req := httptest.NewRequest("POST", "/api/update", strings.NewReader(`{"version":"v0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1 // chunked: no Content-Length on the wire
	rec := httptest.NewRecorder()
	srv.handleUpdate(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("chunked pin: code = %d, want 502 (pin decoded; the old gate dropped it and would answer 200 up-to-date): %s",
			rec.Code, rec.Body.String())
	}
}

// (c) Truncated JSON: a decoder that applies fields as it parses would
// leave AllowDowngrade=true behind. It must be a 400 with NOTHING
// consulted — no fetch, no install, no restart.
func TestUpdateAPIMalformedBodyRejectedBeforeFlags(t *testing.T) {
	srv := updateServer(t)
	h := setupUpdateHarness(t, false)

	rec := postUpdate(t, srv, `{"allow_downgrade":true,"version":"v1.2`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: code = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid JSON") {
		t.Fatalf("400 body lost its verdict: %q", rec.Body.String())
	}
	if got, _ := os.ReadFile(h.exePath); string(got) != "old binary" {
		t.Fatalf("binary was swapped on a malformed body: %q", got)
	}
	if len(h.restarted) != 0 {
		t.Fatalf("restarted = %v, want none", h.restarted)
	}
}
