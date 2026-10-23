package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// F12 (2026-10-23 external review): probeHTTP reported Elapsed = full
// request time. For HTTPS that includes M5's per-probe fresh TLS
// handshake, while HTTP rides the pooled keep-alive conn — so an HTTPS
// sensor's latency read 2-3x an HTTP sensor's for the same server, and
// the two were not comparable. The reported RTT is now measured from the
// final connection's establishment (httptrace.GotConn) to the response
// headers.

// slowHandshakeConn delays the server's FIRST read of a connection. The
// TLS server cannot complete the handshake until it has read the
// ClientHello, so the client-side handshake takes at least `delay`.
type slowHandshakeConn struct {
	net.Conn
	delay time.Duration
	once  sync.Once
}

func (c *slowHandshakeConn) Read(b []byte) (int, error) {
	c.once.Do(func() { time.Sleep(c.delay) })
	return c.Conn.Read(b)
}

// slowHandshakeListener wraps a TCP listener so every accepted
// connection reads through slowHandshakeConn.
type slowHandshakeListener struct {
	net.Listener
	delay time.Duration
}

func (l *slowHandshakeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &slowHandshakeConn{Conn: c, delay: l.delay}, nil
}

// TestProbeHTTPRTTExcludesHandshake pins the core of F12: a TLS
// handshake slowed to 500ms (via the server's first-read delay) must NOT
// show up in the reported Elapsed — the number is the server's response
// time after the connection is established, so an HTTPS sensor stays
// comparable to an HTTP sensor. M5's fresh handshake still happens
// (the wall time proves it); it just no longer inflates the metric.
func TestProbeHTTPRTTExcludesHandshake(t *testing.T) {
	cert := testSelfSigned(t, time.Now().Add(48*time.Hour))
	const handshakeDelay = 500 * time.Millisecond

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	// StartTLS wraps s.Listener in tls.NewListener — the slow listener
	// sits UNDER the TLS layer, so the server's first read (the
	// ClientHello) is delayed and the client-side handshake takes at
	// least handshakeDelay.
	srv.Listener = &slowHandshakeListener{Listener: ln, delay: handshakeDelay}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	start := time.Now()
	r := probeHTTP(context.Background(), srv.URL, 10*time.Second)
	wall := time.Since(start)

	if r.Lost {
		t.Fatalf("probe lost: %+v", r)
	}
	// Sanity: the handshake really was slow (the delay is in effect).
	if wall < handshakeDelay {
		t.Fatalf("wall time %v < handshake delay %v — the delay was not in effect", wall, handshakeDelay)
	}
	// The reported RTT excludes the 500ms handshake: it is the server's
	// response time (a few ms on loopback), far below the delay.
	if r.Elapsed >= handshakeDelay/2 {
		t.Errorf("reported Elapsed = %v, want < %v (the TLS handshake must not count toward the RTT)",
			r.Elapsed, handshakeDelay/2)
	}
}

// TestProbeHTTPRTTIsServerResponseTime pins the plain-HTTP half: the
// reported RTT is connection-established -> response headers, i.e. the
// server's response time. A handler that sleeps 300ms produces a
// reported RTT around 300ms (connection setup excluded).
func TestProbeHTTPRTTIsServerResponseTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Warm the pooled connection so the measured probe is handler delay
	// and nothing else.
	if r := probeHTTP(context.Background(), srv.URL, 5*time.Second); r.Lost {
		t.Fatalf("warm-up probe lost: %+v", r)
	}
	r := probeHTTP(context.Background(), srv.URL, 5*time.Second)
	if r.Lost {
		t.Fatalf("probe lost: %+v", r)
	}
	if r.Elapsed < 200*time.Millisecond || r.Elapsed > 1500*time.Millisecond {
		t.Errorf("reported Elapsed = %v, want ~300ms (server response time)", r.Elapsed)
	}
}
