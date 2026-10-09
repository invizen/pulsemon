package main

import "testing"

// withCertEnv sets the PULSEMON_CERT/KEY env vars (empty = unset) and
// returns a cleanup that restores the prior state.
func withCertEnv(t *testing.T, cert, key string) {
	t.Helper()
	t.Setenv("PULSEMON_CERT", cert)
	t.Setenv("PULSEMON_KEY", key)
}

func TestCertPathsPlainHTTP(t *testing.T) {
	withCertEnv(t, "", "")
	c, k := certPaths()
	if c != "" || k != "" {
		t.Fatalf("expected plain-HTTP (empty pair), got %q %q", c, k)
	}
}

func TestCertPathsBothSet(t *testing.T) {
	withCertEnv(t, "/c.pem", "/k.pem")
	c, k := certPaths()
	if c != "/c.pem" || k != "/k.pem" {
		t.Fatalf("expected /c.pem /k.pem, got %q %q", c, k)
	}
}

// A partial TLS env config must fail the process, not degrade to
// plaintext. certFatal is stubbed so log.Fatal does not exit the test.
func TestCertPathsPartialIsFatal(t *testing.T) {
	called := false
	old := certFatal
	certFatal = func(string) { called = true }
	t.Cleanup(func() { certFatal = old })

	for _, tc := range []struct {
		name, cert, key string
	}{
		{"cert-only", "/c.pem", ""},
		{"key-only", "", "/k.pem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			withCertEnv(t, tc.cert, tc.key)
			certPaths()
			if !called {
				t.Fatal("expected partial TLS config to hit certFatal, did not")
			}
		})
	}
}
