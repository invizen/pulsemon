package main

import (
	"os"
	"strings"
	"testing"
)

// TestInstallPubkeysProtoPin pins the 2026-11-20 finding: the
// release_pubkeys fetch was the only curl in install.sh without
// --proto '=https' --tlsv1.2. The pin is applied via a case arm on the
// URL scheme (the PULSEMON_PUBKEYS_URL test hook serves file://
// fixtures, which a hardcoded =https restriction would break), and the
// curl must consume it.
func TestInstallPubkeysProtoPin(t *testing.T) {
	b, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "https://*) PUBKEYS_PROTO=\"--proto '=https' --tlsv1.2\"") {
		t.Error("install.sh: the https case arm no longer sets the proto pin")
	}
	if !strings.Contains(s, `curl -sfL $PUBKEYS_PROTO -o "$TMP/release_pubkeys"`) {
		t.Error("install.sh: the release_pubkeys curl no longer consumes $PUBKEYS_PROTO")
	}
}
