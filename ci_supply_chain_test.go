package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// CI & supply-chain source pins (2026-11-25 external review MINOR-24):
// the workflow files and release.sh are the pipeline's trust chain, and a
// regression here (an un-run test suite, an unpinned tool, an unverified
// executable) has no Go behavioral surface — so they are pinned at source
// level, the same way the .iss is. readSource/stripGoComments come from
// windows_service_test.go (package main, runs on the Linux gate box).

// TestCIRunsAllFrontendPins: the CI `node --test` line must reference
// EVERY .test.mjs file in web/test/ — a new suite that is not added there
// ships invisible to PRs (MINOR-24: 3 of 4 suites were never run in CI).
func TestCIRunsAllFrontendPins(t *testing.T) {
	ci := readSource(t, ".github/workflows/ci.yml")
	line := ""
	for _, l := range strings.Split(ci, "\n") {
		if strings.Contains(l, "node --test") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("ci.yml must run `node --test` for the frontend pins")
	}
	entries, err := os.ReadDir("web/test")
	if err != nil {
		t.Fatalf("read web/test: %v", err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".test.mjs") {
			continue
		}
		n++
		if !strings.Contains(line, "web/test/"+e.Name()) {
			t.Errorf("ci.yml node --test line does not include web/test/%s — a frontend suite invisible to CI", e.Name())
		}
	}
	if n == 0 {
		t.Fatal("web/test/ contains no .test.mjs files (the pin has nothing to guard)")
	}
}

// TestCIPinsGovulncheck: CI must install a pinned govulncheck, never
// @latest — an unpinned scanner changes its tool AND its database between
// runs, so two "identical" CI runs can disagree (release.sh already pins
// a version; CI now matches it).
func TestCIPinsGovulncheck(t *testing.T) {
	ci := readSource(t, ".github/workflows/ci.yml")
	if strings.Contains(ci, "govulncheck@latest") {
		t.Error("ci.yml must not install govulncheck@latest (unpinned scanner; release.sh pins a version)")
	}
	if m := regexp.MustCompile(`govulncheck@v[0-9]+\.[0-9]+\.[0-9]+`).FindString(ci); m == "" {
		t.Error("ci.yml must install a pinned govulncheck (govulncheck@vX.Y.Z)")
	}
}

// TestReleaseScriptRunsFullRaceSuite: release.sh must run the FULL race
// suite across ALL packages — the old `go test -count=1 .` shipped
// untested internal/store code and never ran the race detector on the
// release path.
func TestReleaseScriptRunsFullRaceSuite(t *testing.T) {
	sh := readSource(t, "release.sh")
	// Line-anchored: the progress echo mentions the same string, so a
	// bare Contains would pass on the echo while the command regresses.
	if m := regexp.MustCompile(`(?m)^go test -race -count=1 \./\.\.\.`).FindString(sh); m == "" {
		t.Error("release.sh must RUN `go test -race -count=1 ./...` (the old single-package, race-free form skipped internal/store and -race)")
	}
}

// TestInnoSetupHashPinned: the Windows release workflow must verify the
// downloaded Inno Setup installer's SHA-256 BEFORE executing it — an
// unverified /SILENT execute of a third-party .exe is a supply-chain hole
// in an otherwise fully pinned pipeline.
func TestInnoSetupHashPinned(t *testing.T) {
	wf := readSource(t, ".github/workflows/windows-release.yml")
	if m := regexp.MustCompile(`[a-f0-9]{64}`).FindString(wf); m == "" {
		t.Fatal("windows-release.yml must carry a 64-hex SHA-256 for the Inno Setup installer")
	}
	if !strings.Contains(wf, "Get-FileHash") {
		t.Error("windows-release.yml must compute the installer's hash with Get-FileHash")
	}
	if !strings.Contains(wf, "-ne $expectedSha256") {
		t.Error("windows-release.yml must compare the computed hash against the pinned one (and throw on mismatch)")
	}
	// Anchor the order check to the INSTALLER download (the build step
	// above also uses Get-FileHash for the exe sidecar — the first
	// occurrence in the file is not the one under test).
	dl := strings.Index(wf, "Invoke-WebRequest")
	gh, sp := -1, -1
	if dl >= 0 {
		gh = strings.Index(wf[dl:], "Get-FileHash")
		if gh >= 0 {
			gh += dl
		}
		sp = strings.Index(wf[dl:], "Start-Process")
		if sp >= 0 {
			sp += dl
		}
	}
	if dl < 0 || gh < 0 || sp < 0 || sp < gh {
		t.Errorf("order must be download (idx %d) -> Get-FileHash (idx %d) -> Start-Process (idx %d): verify BEFORE executing", dl, gh, sp)
	}
}
