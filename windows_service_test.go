package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// readSource reads a repo file relative to the package dir (the repo root —
// these pins verify the Windows service-identity shape at SOURCE level, so
// they run on the Linux gate box where the //go:build windows files never
// compile).
func readSource(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// stripGoComments removes // line and /* */ block comments, tracking string
// and rune literals and raw strings so comment markers INSIDE them survive.
// The pins must test CODE, not comment text (a comment mentioning
// "powershell" must not satisfy — or trip — a code-level assertion).
func stripGoComments(src string) string {
	var out strings.Builder
	i, n := 0, len(src)
	for i < n {
		c := src[i]
		switch {
		case c == '"' || c == '\'':
			q := c
			out.WriteByte(c)
			i++
			for i < n && src[i] != q {
				if src[i] == '\\' && i+1 < n {
					out.WriteByte(src[i])
					out.WriteByte(src[i+1])
					i += 2
					continue
				}
				out.WriteByte(src[i])
				i++
			}
			if i < n {
				out.WriteByte(src[i]) // closing quote
				i++
			}
		case c == '`':
			out.WriteByte(c)
			i++
			for i < n && src[i] != '`' {
				out.WriteByte(src[i])
				i++
			}
			if i < n {
				out.WriteByte(src[i]) // closing backtick
				i++
			}
		case c == '/' && i+1 < n && src[i+1] == '/':
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && src[i+1] == '*':
			i += 2
			for i+1 < n && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			i += 2
		default:
			out.WriteByte(c)
			i++
		}
	}
	return out.String()
}

// TestInstallerRegistersVSA pins the Windows service identity (H1): the
// installer must register the service as its own virtual service account
// (least privilege, no LocalSystem) and grant that account the data dir
// (DB writes) and the app dir (self-update swaps the .exe).
func TestInstallerRegistersVSA(t *testing.T) {
	iss := readSource(t, "installer/pulsemon.iss")
	// The sc CREATE invocation itself must carry the VSA (the manual-fallback
	// MsgBox text contains the same token, so count the create-line form —
	// with the trailing quote-plus — specifically).
	if !strings.Contains(iss, `' obj= "NT SERVICE\Pulsemon"' +`) {
		t.Error(`the sc create invocation must carry obj= "NT SERVICE\Pulsemon" (the VSA), not just the manual-fallback message`)
	}
	if n := strings.Count(iss, `NT SERVICE\Pulsemon:(OI)(CI)(M)`); n < 2 {
		t.Errorf("icacls must grant NT SERVICE\\Pulsemon (OI)(CI)(M) on the data dir AND the app dir (found %d grants, want >= 2)", n)
	}
	// /T is required on BOTH grants: without it, pre-existing files get no
	// VSA entry — the upgrade path (a LocalSystem-era DB) crash-loops, and
	// the copied .exe (copied before the app-dir grant runs) can't be
	// renamed by self-update.
	if !strings.Contains(iss, ` /T /inheritance:r /grant "NT SERVICE\Pulsemon:(OI)(CI)(M)"`) {
		t.Error("data-dir icacls must carry /T (apply the VSA grant to existing files, not just the dir)")
	}
	if !strings.Contains(iss, ` /T /grant "NT SERVICE\Pulsemon:(OI)(CI)(M)"`) {
		t.Error("app-dir icacls must carry /T (the .exe is copied before the grant runs)")
	}
	// Ordering: the data-dir ACLs run AFTER sc create — the VSA SID only
	// exists once the service is registered, so icacls cannot resolve
	// "NT SERVICE\Pulsemon" before that (fresh installs would ship an
	// unhardened data dir).
	createIdx := strings.Index(iss, `' obj= "NT SERVICE\Pulsemon"' +`)
	aclIdx := strings.Index(iss, "\n  GrantDataDirAcls;\n")
	if createIdx < 0 || aclIdx < 0 || aclIdx < createIdx {
		t.Error("GrantDataDirAcls must be called AFTER the sc create invocation (the VSA SID must exist first)")
	}
	if strings.Contains(iss, "LocalSystem") {
		t.Error("installer must not reference LocalSystem (the service no longer runs as it)")
	}
	if strings.Contains(iss, `NT AUTHORITY\SYSTEM:(OI)(CI)(F)`) {
		t.Error("installer must not grant SYSTEM full control of the data dir (the VSA is the service account)")
	}
}

// TestInstallerIsASCII pins the ISCC contract: the .iss is read as ANSI, so
// a non-ASCII byte (an em dash in a comment) is a code-page risk at release
// build time.
func TestInstallerIsASCII(t *testing.T) {
	b, err := os.ReadFile("installer/pulsemon.iss")
	if err != nil {
		t.Fatalf("read installer/pulsemon.iss: %v", err)
	}
	for i, c := range b {
		if c > 0x7F {
			t.Fatalf("installer/pulsemon.iss must be 100%% ASCII (ISCC reads it as ANSI); non-ASCII byte 0x%x at offset %d", c, i)
		}
	}
}

// TestWindowsRestartUsesNativeSCM pins the restart path (H3/M7): no
// PowerShell child process; the SCM is driven natively with minimal
// rights (windows.OpenSCManager / windows.OpenService per-call masks —
// never the ALL_ACCESS that x/sys's mgr.Connect() requests, which the
// VSA's DACL denies).
func TestWindowsRestartUsesNativeSCM(t *testing.T) {
	listener := stripGoComments(readSource(t, "listener_windows.go"))
	if strings.Contains(listener, "powershell") {
		t.Error("listener_windows.go must not shell out to powershell (native SCM only)")
	}
	if strings.Contains(listener, "Restart-Service") {
		t.Error("listener_windows.go must not reference Restart-Service in code (native SCM only)")
	}
	upd := stripGoComments(readSource(t, "update_windows.go"))
	if strings.Contains(upd, "powershell") {
		t.Error("update_windows.go must not shell out to powershell (native SCM only)")
	}
	if strings.Contains(upd, "svc/mgr") {
		t.Error("update_windows.go must not import svc/mgr (mgr.Connect() requests SC_MANAGER_ALL_ACCESS, which the VSA's DACL denies)")
	}
	if !strings.Contains(upd, "windows.OpenSCManager(") {
		t.Error("update_windows.go must drive the SCM via windows.OpenSCManager with a minimal mask")
	}
	if !strings.Contains(upd, "windows.OpenService(") {
		t.Error("update_windows.go must open the service via windows.OpenService with a per-call mask")
	}
}

// TestIcmpHintNoLocalSystem pins the operator-facing hint: the service no
// longer runs as Local System, and the raw fallback is unavailable to the
// virtual account.
func TestIcmpHintNoLocalSystem(t *testing.T) {
	src := readSource(t, "main_windows.go")
	if i := strings.Index(strings.ToLower(src), "local system"); i >= 0 {
		t.Error("main_windows.go must not reference 'Local System' (the service runs as NT SERVICE\\Pulsemon)")
	}
}

// TestDgramBootRetryHardened pins the boot retry: under the virtual account
// the raw fallback is unreachable (SOCK_RAW needs elevation), so the
// datagram retry is the effective last line for ICMP.
func TestDgramBootRetryHardened(t *testing.T) {
	src := stripGoComments(readSource(t, "ping_windows.go"))
	m := regexp.MustCompile(`dgramBootAttempts\s*=\s*(\d+)`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("ping_windows.go must define dgramBootAttempts")
	}
	n, _ := strconv.Atoi(m[1])
	if n < 10 {
		t.Errorf("dgramBootAttempts = %d, want >= 10 (the raw fallback is dead under the VSA)", n)
	}
	if !strings.Contains(src, "dgramBootRetryBase") {
		t.Error("ping_windows.go must define dgramBootRetryBase (growing boot retry)")
	}
}

// TestWindowsUpdateStaged pins the staged in-dashboard self-update design
// (2026-11-24, supersedes the in-service restart half of the old
// windows-recovery-restart design): the VSA CANNOT stop/start its own
// service — its START/STOP are integrity-denied despite the DACL grant
// (probed live from the service's own token on zendev) — and the dashboard
// update runs INSIDE the service process, so it STAGES the verified binary
// and hands the operator the restart. The in-service restart machinery
// (recovery-exit, pre-flight, exit code) is gone from the code; the
// installer's recovery action stays as a crash safety net; the external
// (elevated console) path keeps the synchronous stop→start.
func TestWindowsUpdateStaged(t *testing.T) {
	wd := stripGoComments(readSource(t, "update_windows.go"))
	// The in-service restart machinery must be GONE from the code.
	for _, gone := range []string{
		"selfRestartViaRecoveryFn",
		"recoveryActionConfiguredFn",
		"updateExitCode",
		"__restart-helper",
	} {
		if strings.Contains(wd, gone) {
			t.Errorf("update_windows.go code must not contain %s (the in-service restart is retired — the VSA cannot restart its own service)", gone)
		}
	}
	if strings.Contains(wd, "s.Start()") {
		t.Error("update_windows.go must not call s.Start() from the service token (SERVICE_START is integrity-denied)")
	}
	// The in-dashboard update must be staged: apiAutoRestart = false is set
	// in the Windows init, and performRestartWindows is the external path
	// only (synchronous stop→start via the seam).
	if !strings.Contains(wd, "apiAutoRestart = false") {
		t.Error("update_windows.go must set apiAutoRestart = false (the in-dashboard update stages the binary; the operator restarts the service)")
	}
	if !strings.Contains(wd, "restartWindowsServiceFn()") {
		t.Error("performRestartWindows must perform the synchronous stop→start via restartWindowsServiceFn (the external path)")
	}
	// The installer must STILL configure the recovery action — now a crash
	// safety net (a crashed service comes back automatically), not part of
	// the update flow.
	iss := readSource(t, "installer/pulsemon.iss")
	if !strings.Contains(iss, "failure") {
		t.Error("installer/pulsemon.iss must configure the service recovery action (sc failure ... actions= restart/...) — the crash safety net")
	}
	if !strings.Contains(iss, "restart/") {
		t.Error("the installer's recovery action must be 'restart the service' (actions= restart/...)")
	}
	// The dispatch table must NOT know the retired subcommand.
	if strings.Contains(stripGoComments(readSource(t, "main.go")), `"__restart-helper"`) {
		t.Error("main.go dispatch must not handle the retired __restart-helper subcommand")
	}
	// The watchdog's healthy path must run the data-integrity check,
	// passing the spawn-time bus (the post-restore restart must hit the
	// bus the service ran on — after the stop, re-detection reports "").
	// (runWatchdog lives in update_watchdog.go since the NIT-33 split.)
	upd := stripGoComments(readSource(t, "update_watchdog.go"))
	if !strings.Contains(upd, "verifySensorsIntactWatchdog(db, prev, dst, bus)") {
		t.Error("runWatchdog's healthy path must call verifySensorsIntactWatchdog with the spawn-time bus (the 'sensors wiped' guard must restart on the bus the service ran on, not a post-stop re-detection)")
	}
}

// TestWindowsStopToleratesAlreadyStopped pins the 1062 fix (CRITICAL-3,
// 2026-11-25): ControlService(Stop) on an already-stopped service
// returns ERROR_SERVICE_NOT_ACTIVE; stopWindowsServiceFn must treat that
// as success (the goal state) — otherwise a restart of a stopped service
// (the watchdog's post-rollback restart, an operator `pulsemon restart`
// after a crash) fails at the stop step before the start ever runs.
// Source-shape pin: the //go:build windows file never compiles on the
// Linux gate box.
func TestWindowsStopToleratesAlreadyStopped(t *testing.T) {
	src := stripGoComments(readSource(t, "update_windows.go"))
	if !strings.Contains(src, "windows.ERROR_SERVICE_NOT_ACTIVE") {
		t.Error("stopWindowsServiceFn must treat windows.ERROR_SERVICE_NOT_ACTIVE (1062) as success — stopping an already-stopped service is the goal state, and without this a restart of a stopped service fails before the start runs")
	}
}

// TestWindowsRollbackStopsServiceFirst pins the watchdog-rollback fix: on
// Windows the running service locks the .exe, so the rollback rename must
// stop the service first.
func TestWindowsRollbackStopsServiceFirst(t *testing.T) {
	src := stripGoComments(readSource(t, "update_rollback_windows.go"))
	stop := strings.Index(src, "stopWindowsServiceFn()")
	rename := strings.Index(src, "os.Rename")
	if stop < 0 || rename < 0 || stop > rename {
		t.Errorf("Windows rollback must call stopWindowsServiceFn (idx %d) BEFORE os.Rename (idx %d)", stop, rename)
	}
}

// funcBody returns the text of a top-level function from gofmt'd source:
// from its "func name(" line to the first column-0 closing brace.
func funcBody(src, name string) (string, bool) {
	marker := "func " + name + "("
	i := strings.Index(src, marker)
	if i < 0 {
		return "", false
	}
	j := strings.Index(src[i:], "\n}")
	if j < 0 {
		return "", false
	}
	return src[i : i+j+2], true
}

// TestServiceDetectionUsesSvcHelper pins MINOR-26 (2026-11-25 external
// review): service detection must use svc.IsWindowsService() — which
// checks session 0 AND the services.exe parent — not a bare
// ProcessIdToSessionId == 0 check. The session-0-only shape misclassifies
// Task Scheduler / WinRM / NSSM / CI-runner launches into the service
// path, where svc.Run fatals.
func TestServiceDetectionUsesSvcHelper(t *testing.T) {
	src := stripGoComments(readSource(t, "main_windows.go"))
	body, ok := funcBody(src, "isWindowsService")
	if !ok {
		// The var shape: isWindowsService is a func-typed var, not a func.
		i := strings.Index(src, "isWindowsService = func() bool")
		if i < 0 {
			t.Fatal("main_windows.go must define isWindowsService")
		}
		body = src[i:]
	}
	if !strings.Contains(body, "svc.IsWindowsService()") {
		t.Error("isWindowsService must call svc.IsWindowsService() (session 0 AND services.exe parent)")
	}
	if strings.Contains(src, "ProcessIdToSessionId") {
		t.Error("main_windows.go must not use a bare ProcessIdToSessionId == 0 check (it misclassifies non-SCM Session 0 launches)")
	}
}

// TestServiceReportsRunningOnlyWhenListening pins MINOR-26 (2026-11-25
// external review): Execute must report svc.Running to the SCM only after
// the server is actually listening (the onReady closure fires post-
// startListener). The old shape posted Running before runServer began —
// a DB/TLS init fatal then read as a RUNTIME crash, tripping the sc
// failure loop, while the startup config error was masked.
func TestServiceReportsRunningOnlyWhenListening(t *testing.T) {
	src := stripGoComments(readSource(t, "main_windows.go"))
	// Execute is a METHOD: func (h *pulsemonHandler) Execute(...) — anchor
	// on the full receiver form.
	i := strings.Index(src, "func (h *pulsemonHandler) Execute(")
	if i < 0 {
		t.Fatal("main_windows.go must define pulsemonHandler.Execute")
	}
	j := strings.Index(src[i:], "\n}")
	if j < 0 {
		t.Fatal("cannot find the end of pulsemonHandler.Execute")
	}
	body := src[i : i+j+2]
	readyIdx := strings.Index(body, "case <-ready:")
	runningIdx := strings.Index(body, "State: svc.Running")
	if readyIdx < 0 {
		t.Fatal("Execute must select on a ready signal before reporting Running")
	}
	if runningIdx < 0 || runningIdx < readyIdx {
		t.Errorf("Execute must post svc.Running (idx %d) ONLY after the server is listening (ready select at idx %d) — an init fatal must exit while StartPending", runningIdx, readyIdx)
	}
	if !strings.Contains(body, "runServer(stop, ") {
		t.Error("Execute must start runServer with the ready callback (runServer(stop, func() { close(ready) }))")
	}
	// main.go must fire the callback AFTER the listener is up.
	mg := stripGoComments(readSource(t, "main.go"))
	si := strings.Index(mg, "startListener(srv, db, stop)")
	oi := strings.Index(mg, "onReady()")
	if si < 0 || oi < 0 || oi < si {
		t.Errorf("main.go must call onReady() (idx %d) AFTER startListener (idx %d)", oi, si)
	}
}

// TestEnsureDataDirHardensNewDirs pins MINOR-26 (2026-11-25 external
// review): a newly created data dir must be ACL-hardened (icacls
// /inheritance:r + explicit grants) BEFORE the DB file is written — a
// fresh %ProgramData% dir inherits BUILTIN\Users:(RX), leaving bcrypt
// hashes and provider secrets readable by every local user on a portable
// run. Existing dirs keep the installer's/prior run's ACL (no re-icacls).
func TestEnsureDataDirHardensNewDirs(t *testing.T) {
	src := stripGoComments(readSource(t, "main_windows.go"))
	body, ok := funcBody(src, "ensureDataDir")
	if !ok {
		t.Fatal("main_windows.go must define ensureDataDir")
	}
	if !strings.Contains(body, `exec.Command("icacls", dir, "/inheritance:r"`) {
		t.Error("ensureDataDir must icacls a newly created dir with /inheritance:r (break the BUILTIN\\Users:(RX) inheritance)")
	}
	if !strings.Contains(body, `Administrators:(OI)(CI)F`) {
		t.Error("the hardened ACL must grant Administrators full control")
	}
	if !strings.Contains(body, `currentWindowsUser()`) {
		t.Error("the hardened ACL must grant the running user full control (the portable-run owner)")
	}
	// Ordering: the existing-dir early return comes BEFORE the icacls —
	// only NEWLY created dirs are hardened.
	statIdx := strings.Index(body, "os.Stat(dir)")
	icaIdx := strings.Index(body, "exec.Command(\"icacls\"")
	if statIdx < 0 || icaIdx < 0 || statIdx > icaIdx {
		t.Errorf("ensureDataDir must early-return for an existing dir (os.Stat at idx %d) BEFORE the icacls pass (idx %d)", statIdx, icaIdx)
	}
}

// TestNoDeadServiceChannelGlobals pins MINOR-26 (2026-11-25 external
// review): the package-level serviceStopCh/serviceDoneCh globals are dead
// (the handler's local channels do the work) and must not come back —
// package globals shared by a single service instance are a footgun the
// review flagged.
func TestNoDeadServiceChannelGlobals(t *testing.T) {
	src := stripGoComments(readSource(t, "main_windows.go"))
	for _, g := range []string{"serviceStopCh", "serviceDoneCh"} {
		if strings.Contains(src, g) {
			t.Errorf("main_windows.go must not define the dead %s global (the handler's local channels replace it)", g)
		}
	}
}
