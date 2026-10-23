package main

import (
	"os"
	"path/filepath"
	"testing"
)

// m9: the system locations beat $PATH, so a PATH entry cannot shadow systemctl.
// (resolveSystemctl, not the stubbable systemctlPath var.)
func TestFix_m9_SystemctlPathPrefersSystemLocations(t *testing.T) {
	fake := t.TempDir()
	if err := os.WriteFile(filepath.Join(fake, "systemctl"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
	got := resolveSystemctl()
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			if got != p {
				t.Fatalf("systemctlPath() = %q, want the system binary %q even with a shadowing PATH entry", got, p)
			}
			return
		}
	}
	t.Skip("no systemctl in the fixed system locations on this host")
}
