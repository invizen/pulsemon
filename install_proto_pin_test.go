package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestInstallPubkeysProtoPin pins the 2026-11-20 finding (the
// release_pubkeys fetch was the only curl in install.sh without
// --proto '=https' --tlsv1.2) and the 2026-11-25 CRITICAL-1 fix: the pin's
// value must not contain shell quotes. Quotes inside a double-quoted
// scalar are literal characters, and the unquoted $PUBKEYS_PROTO
// expansion passes them to curl verbatim (quote removal applies only to
// quotes in the source text, never to expansion results) — the old shape
// made curl receive the arg '=https' and exit 2, aborting every
// production (https) install. The pin is applied via a case arm on the
// URL scheme (the PULSEMON_PUBKEYS_URL test hook serves file:// fixtures,
// which a hardcoded =https restriction would break), and the curl must
// consume it.
func TestInstallPubkeysProtoPin(t *testing.T) {
	b, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)

	// Structural: the https case arm sets the QUOTE-FREE token string and
	// the curl consumes it; the old broken shape (embedded single quotes)
	// must be absent.
	if !strings.Contains(s, `https://*) PUBKEYS_PROTO="--proto =https --tlsv1.2"`) {
		t.Error("install.sh: the https case arm no longer sets the proto pin")
	}
	if strings.Contains(s, `PUBKEYS_PROTO="--proto '=https' --tlsv1.2"`) {
		t.Error("install.sh: the proto pin value carries shell quotes — the unquoted $PUBKEYS_PROTO expansion passes them to curl verbatim")
	}
	if !strings.Contains(s, `curl -sfL $PUBKEYS_PROTO -o "$TMP/release_pubkeys"`) {
		t.Error("install.sh: the release_pubkeys curl no longer consumes $PUBKEYS_PROTO")
	}

	// Behavioral: run the real block (extracted verbatim from install.sh,
	// not a copy) under bash with a stub curl that dumps its argv, and pin
	// the exact argv tokens for both URL schemes.
	block, ok := protoPinBlock(s)
	if !ok {
		t.Fatal("install.sh: could not extract the PUBKEYS_PROTO block")
	}

	t.Run("https-argv", func(t *testing.T) {
		const url = "https://raw.githubusercontent.com/invizen/pulsemon/main/release_pubkeys"
		args, dir := protoArgv(t, block, url)
		want := []string{"-sfL", "--proto", "=https", "--tlsv1.2", "-o", filepath.Join(dir, "release_pubkeys"), url}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("https URL curl argv = %q, want %q", args, want)
		}
		for _, a := range args {
			if strings.ContainsAny(a, `'"`) {
				t.Errorf("argv token %q carries a shell quote — curl rejects it (unrecognized protocol)", a)
			}
		}
	})

	// Positive control: the file:// test hook must stay unrestricted, so
	// the fix cannot regress to a hardcoded pin outside the case arm.
	t.Run("file-argv", func(t *testing.T) {
		const url = "file:///tmp/pm-fx/pubkeys"
		args, dir := protoArgv(t, block, url)
		want := []string{"-sfL", "-o", filepath.Join(dir, "release_pubkeys"), url}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("file URL curl argv = %q, want %q (the PULSEMON_PUBKEYS_URL hook must stay unrestricted)", args, want)
		}
	})
}

// protoPinBlock extracts the PUBKEYS_PROTO case block verbatim from the
// install.sh text: from the `PUBKEYS_PROTO=""` line through the line that
// closes the curl's `|| { ... }` guard.
func protoPinBlock(s string) (string, bool) {
	lines := strings.Split(s, "\n")
	start := -1
	for i, l := range lines {
		if l == `PUBKEYS_PROTO=""` {
			start = i
			break
		}
	}
	if start < 0 {
		return "", false
	}
	for j := start; j < len(lines); j++ {
		if strings.Contains(lines[j], "exit 1; }") {
			return strings.Join(lines[start:j+1], "\n"), true
		}
	}
	return "", false
}

// protoArgv runs the extracted block under bash with a stub curl that
// records its argv NUL-separated, and returns the argv plus the TMP dir
// the block wrote into.
func protoArgv(t *testing.T, block, url string) ([]string, string) {
	t.Helper()
	dir := t.TempDir()
	argfile := filepath.Join(dir, "curl-args")
	script := "set -u\n" +
		"TMP='" + dir + "'\n" +
		"PUBKEYS_URL='" + url + "'\n" +
		"ARGS='" + argfile + "'\n" +
		"curl() { printf '%s\\0' \"$@\" > \"$ARGS\"; }\n" +
		block
	out, err := exec.Command("bash", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("bash -c failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(argfile)
	if err != nil {
		t.Fatalf("stub curl never ran (no argv file): %v", err)
	}
	args := strings.Split(string(data), "\x00")
	if len(args) > 0 && args[len(args)-1] == "" {
		args = args[:len(args)-1]
	}
	return args, dir
}

// TestInstallUnitQuotesPaths (NIT-31): the systemd unit template is an
// unquoted heredoc — ExecStart=/Environment= values containing a space
// (e.g. $HOME with a space) must land in the unit QUOTED, or systemd's
// ExecStart word-splitting breaks the service on any such install.
func TestInstallUnitQuotesPaths(t *testing.T) {
	src, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, `ExecStart=\"$BIN\"`) {
		t.Fatal("install.sh: ExecStart must be double-quoted (paths with spaces break systemd word-splitting)")
	}
	if !strings.Contains(s, `Environment=\"PULSEMON_DB=$PREFIX/data/pulsemon.db\"`) {
		t.Fatal("install.sh: the PULSEMON_DB Environment= line must be double-quoted (same space-in-path break)")
	}
}

// TestInstallHealthcheckGloboff (NIT-31): the post-install curl healthcheck
// must pass -g (--globoff) — a bracketed IPv6 host ([::1]:9299) is a curl
// glob pattern, and without -g the healthcheck fails for every IPv6 bind.
func TestInstallHealthcheckGloboff(t *testing.T) {
	src, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range strings.Split(string(src), "\n") {
		if strings.Contains(line, "api/healthz") && strings.HasPrefix(strings.TrimSpace(line), "if curl") {
			if !strings.Contains(line, "-g") {
				t.Fatalf("healthcheck curl lacks -g (bracketed IPv6 hosts are curl globs): %s", line)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("install.sh: the curl api/healthz healthcheck line was not found")
	}
}
