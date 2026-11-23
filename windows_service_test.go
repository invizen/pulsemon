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
// PowerShell child process; the SCM is driven natively via
// golang.org/x/sys/windows/svc/mgr.
func TestWindowsRestartUsesNativeSCM(t *testing.T) {
	listener := stripGoComments(readSource(t, "listener_windows.go"))
	if strings.Contains(listener, "powershell") {
		t.Error("listener_windows.go must not shell out to powershell (native SCM only)")
	}
	if strings.Contains(listener, "Restart-Service") {
		t.Error("listener_windows.go must not reference Restart-Service in code (native SCM only)")
	}
	upd := stripGoComments(readSource(t, "update_windows.go"))
	if !strings.Contains(upd, "golang.org/x/sys/windows/svc/mgr") {
		t.Error("update_windows.go must import golang.org/x/sys/windows/svc/mgr")
	}
	if !strings.Contains(upd, "mgr.Connect()") {
		t.Error("update_windows.go must drive the SCM via mgr.Connect()")
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

// TestWindowsSelfRestartHelper pins the self-restart wiring: the update
// flow detaches a helper from the new binary BEFORE stopping the service
// (the helper is the only thing that can start it back), the helper waits
// for the stopped state before Start, and the dispatch table knows the
// subcommand.
func TestWindowsSelfRestartHelper(t *testing.T) {
	wd := stripGoComments(readSource(t, "update_windows.go"))
	if !strings.Contains(wd, `"__restart-helper"`) {
		t.Error("update_windows.go must spawn the __restart-helper subcommand")
	}
	if !strings.Contains(wd, "isWindowsService()") {
		t.Error("performRestartWindows must branch on isWindowsService()")
	}
	h := stripGoComments(readSource(t, "restart_helper_windows.go"))
	stopped := strings.Index(h, "svc.Stopped")
	start := strings.Index(h, "s.Start()")
	if stopped < 0 || start < 0 || stopped > start {
		t.Errorf("restart helper must observe svc.Stopped (idx %d) BEFORE s.Start() (idx %d)", stopped, start)
	}
	if !strings.Contains(stripGoComments(readSource(t, "main.go")), `"__restart-helper"`) {
		t.Error("main.go dispatch must handle the __restart-helper subcommand")
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
