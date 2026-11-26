package main

import (
	"net/http"
	"testing"
	"time"
)

// m1: pin the production server timeouts — slowloris protection
// (read/idle/header caps) plus a server-level WriteTimeout that bounds a
// client that never reads its response. The slow writers (the ~60s POST
// /api/update, a max-timeout 30s sensor ping, a settings test on a hanging
// relay) each extend their own deadline (see handleUpdate), so the 30s
// server default does not cut them off.
func TestNewHTTPServerTimeouts(t *testing.T) {
	h := http.NewServeMux()
	srv, _ := newHTTPServer(h)

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
		t.Errorf("WriteTimeout = %v, want 30s (the slow handlers extend their own deadlines)", srv.WriteTimeout)
	}
}
