// Windows upgrade safety (2026-11-23, items 2+4) — source-level pins for
// installer/pulsemon.iss (the .iss itself is compile-gated by ISCC on the
// release workflow; these pins catch regressions of the two installer
// behaviors on the Linux gate box, same pattern as TestInstallerRegistersVSA).
//
// Run with: go test -run 'TestInstallerDashboardHealthzGated|TestInstallerPreStopDBBackup' .

package main

import (
	"regexp"
	"testing"
)

// Item 2: the installer must not open the dashboard before the service
// answers. The old behavior (ShellExec immediately after sc start) loaded
// a dead port ~4s before the service bound it, and the dashboard rendered
// its empty "no sensors" state - on an upgrade that reads as "the sensors
// were wiped" (nothing was lost). The fix: poll healthz (HealthzAlive) up
// to ~15s and open the browser only once the service answers.
func TestInstallerDashboardHealthzGated(t *testing.T) {
	iss := readSource(t, "installer/pulsemon.iss")

	if !regexp.MustCompile(`(?m)^function HealthzAlive`).MatchString(iss) {
		t.Fatal("installer/pulsemon.iss is missing the HealthzAlive() function (healthz poll before opening the dashboard)")
	}
	if !regexp.MustCompile(`Invoke-WebRequest[^)]*9299/api/healthz`).MatchString(iss) {
		t.Fatal("HealthzAlive() must probe http://localhost:9299/api/healthz")
	}
	// OpenDashboard must LOOP on HealthzAlive before the ShellExec open.
	// (Whole-file index ordering: the procedure body nests a `for` block,
	// so a `.*?end;` capture would stop at the loop's own end;.)
	procPos := regexp.MustCompile(`procedure OpenDashboard;`).FindStringIndex(iss)
	pollPos := regexp.MustCompile(`if HealthzAlive\(\) then`).FindStringIndex(iss)
	openPos := regexp.MustCompile(`ShellExec\('open'`).FindStringIndex(iss)
	if procPos == nil || pollPos == nil || openPos == nil {
		t.Fatal("OpenDashboard must poll HealthzAlive() before ShellExec('open')")
	}
	if !(procPos[0] < pollPos[0] && pollPos[0] < openPos[0]) {
		t.Fatal("OpenDashboard opens the browser BEFORE the healthz poll (the dead-port regression)")
	}
}

// Item 4: the installer must make a pre-upgrade safety copy of the DB
// (pulsemon.db.preupdate) while the service is STOPPED - both on the
// upgrade path (PrepareToInstall, before the .exe overwrite) and on the
// uninstall path (after the service is stopped). The self-update path
// makes the same copy from inside the running service (VACUUM INTO, see
// update.go); this pin covers the installer half.
func TestInstallerPreStopDBBackup(t *testing.T) {
	iss := readSource(t, "installer/pulsemon.iss")

	if !regexp.MustCompile(`(?m)^procedure BackupDatabasePreUpdate`).MatchString(iss) {
		t.Fatal("installer/pulsemon.iss is missing the BackupDatabasePreUpdate() procedure")
	}
	if !regexp.MustCompile(`FileCopy\(DataDir \+ '\\pulsemon\.db', DataDir \+ '\\pulsemon\.db\.preupdate', True\)`).MatchString(iss) {
		t.Fatal("BackupDatabasePreUpdate() must FileCopy pulsemon.db -> pulsemon.db.preupdate")
	}
	prepare := regexp.MustCompile(`(?s)function PrepareToInstall.*?end;`).FindString(iss)
	if prepare == "" {
		t.Fatal("function PrepareToInstall not found")
	}
	if !regexp.MustCompile(`BackupDatabasePreUpdate;`).MatchString(prepare) {
		t.Fatal("PrepareToInstall no longer makes the pre-upgrade DB backup (after the service stop)")
	}
	uninstall := regexp.MustCompile(`(?s)procedure CurUninstallStepChanged.*?end;`).FindString(iss)
	if uninstall == "" {
		t.Fatal("procedure CurUninstallStepChanged not found")
	}
	if !regexp.MustCompile(`BackupDatabasePreUpdate;`).MatchString(uninstall) {
		t.Fatal("the uninstall path no longer leaves a final consistent DB backup")
	}
}

// Item 3 (installer-adjacent wiring): BOTH self-update paths must make the
// pre-swap DB backup BEFORE installBinary swaps the binary. Source-level
// ordering pin (the behavior itself is pinned by update_preupdate_test.go).
func TestSelfUpdateBacksUpDBBeforeSwap(t *testing.T) {
	for _, file := range []string{"update_api.go", "update.go"} {
		src := readSource(t, file)
		b := regexp.MustCompile(`backupDatabasePreUpdate\(\)`).FindStringIndex(src)
		i := regexp.MustCompile(`installBinary\(tmp, exe, digest\)`).FindStringIndex(src)
		if b == nil {
			t.Fatalf("%s: backupDatabasePreUpdate() call missing from the update path", file)
		}
		if i == nil || i[0] < b[0] {
			t.Fatalf("%s: the binary swap (installBinary) runs BEFORE the pre-update DB backup - a data-losing swap would have no safety copy", file)
		}
	}
}
