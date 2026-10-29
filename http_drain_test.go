//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestProbeHTTPDrainsOnlyReusableConnections locks the finding-6 fix:
// probeHTTP drains the response body ONLY to let the transport reuse a
// keep-alive connection, and only up to drainBodyCap. An HTTPS probe forces
// a fresh TLS handshake per probe (req.Close = true, for cert freshness,
// M5), so its connection is discarded anyway — draining it is pure waste (a
// 5s HTTPS sensor on a heavy UI like Proxmox/Nextcloud used to pull ~1 MB
// per probe). The fix drains only when the final connection is kept
// (!resp.Request.Close) and caps the drain at 64 KB.
//
// Each subtest serves a 1 MB body from a server whose SEND buffer is bounded
// (SO_SNDBUF=64KB) so the "bytes the server wrote" counter tracks what the
// CLIENT actually read, not what fit in an autotuned (multi-MB) socket
// buffer. A pre-fix 1 MB drain writes ~1 MB; the fixed probe writes far less
// (measured ~90-196 KB: the 64 KB cap plus the bounded send buffer).
//
// Linux-only: the SO_SNDBUF bounding is a Linux socket option; on other
// platforms the autotuned buffer makes the byte count unreliable, so the
// test is excluded from the build there (the fix itself is portable).
func TestProbeHTTPDrainsOnlyReusableConnections(t *testing.T) {
	const bodySize = 1 << 20    // 1 MB
	const maxWanted = 512 << 10 // 512 KB: a pre-fix 1 MB drain writes ~bodySize

	// boundedSendListener sets SO_SNDBUF small so a write blocks once the
	// client stops reading — making the written-bytes counter track the
	// client's reads instead of the autotuned socket buffer.
	boundedSendListener := func(t *testing.T) net.Listener {
		t.Helper()
		lc := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 64*1024)
				})
			},
		}
		ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		return ln
	}

	run := func(t *testing.T, useTLS bool) {
		t.Helper()
		var written atomic.Int64
		body := bytes.Repeat([]byte("x"), bodySize)
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(bodySize))
			w.WriteHeader(http.StatusOK)
			const chunk = 8 << 10
			for off := 0; off < bodySize; {
				n := chunk
				if off+n > bodySize {
					n = bodySize - off
				}
				wn, err := w.Write(body[off : off+n])
				written.Add(int64(wn))
				off += wn
				if err != nil {
					return // client stopped reading (closed) — stop writing
				}
			}
		})
		var srv *httptest.Server
		if useTLS {
			srv = &httptest.Server{
				Config:   &http.Server{Handler: h},
				Listener: boundedSendListener(t),
				TLS:      &tls.Config{Certificates: []tls.Certificate{testSelfSigned(t, time.Now().Add(48*time.Hour))}},
			}
			srv.StartTLS()
		} else {
			srv = &httptest.Server{
				Config:   &http.Server{Handler: h},
				Listener: boundedSendListener(t),
			}
			srv.Start()
		}
		defer srv.Close()

		r := probeHTTP(context.Background(), srv.URL, 10*time.Second)
		if r.Lost {
			t.Fatalf("probe marked loss, want 200 up: err=%v", r.Err)
		}
		if n := written.Load(); n >= maxWanted {
			t.Errorf("server wrote %d of %d bytes — the probe drained a body whose connection is discarded (HTTPS) or beyond the 64 KB cap (HTTP); want < %d", n, bodySize, maxWanted)
		}
	}

	t.Run("https-no-drain", func(t *testing.T) { run(t, true) })
	t.Run("http-capped-drain", func(t *testing.T) { run(t, false) })
}
