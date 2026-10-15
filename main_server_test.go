package main

import (
	"net/http"
	"testing"
	"time"
)

// m1: pin the production server timeouts — slowloris protection
// (read/idle/header caps) WITHOUT a server-level WriteTimeout, which
// would cut off the ~60s POST /api/update self-update stream.
func TestNewHTTPServerTimeouts(t *testing.T) {
	h := http.NewServeMux()
	srv := newHTTPServer(h)

	if srv.Handler != h {
		t.Fatalf("Handler = %v, want the given handler", srv.Handler)
	}
	if srv.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 5s", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", srv.ReadTimeout)
	}
	if srv.IdleTimeout != 120*time.Second {
		t.Errorf("IdleTimeout = %v, want 120s", srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes != 64<<10 {
		t.Errorf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, 64<<10)
	}
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout = %v, want 0 (POST /api/update runs ~60s)", srv.WriteTimeout)
	}
}
