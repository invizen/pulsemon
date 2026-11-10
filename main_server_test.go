package main

import (
	"net/http"
	"testing"
	"time"
)

// m1: pin the production server timeouts — slowloris protection
// (read/idle/header caps) plus a server-level WriteTimeout that bounds a
// client that never reads its response. The ~60s POST /api/update self-update
// is the one slow writer; it extends its own deadline (see handleUpdate), so
// the 30s server default does not cut it off mid-install.
func TestNewHTTPServerTimeouts(t *testing.T) {
	h := http.NewServeMux()
	srv := newHTTPServer(h)

	if srv.Handler != h {
		t.Fatalf("Handler = %v, want the given handler", h)
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
	if srv.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %v, want 30s (handleUpdate extends its own deadline to 90s)", srv.WriteTimeout)
	}
}
