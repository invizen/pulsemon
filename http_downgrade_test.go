package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Tests for the HTTPS->HTTP downgrade refusal (external review MINOR-15):
// the cleartext hop is refused in CheckRedirect BEFORE it is dialed, so a
// token in the URL's path/query never goes out in plaintext, and the probe
// still reports the same lost shape (3xx status + presented cert).

// TestHTTPSDowngradeRefusedBeforeDial is the end-to-end proof: a trusted
// HTTPS origin (self-signed cert matching the target host — accepted by
// verifyHTTPCert's self-signed match) 301s to a cleartext http URL carrying
// a token. The cleartext server must receive ZERO requests pre-fix it
// received one, with the token — and the probe must report loss with the
// 301 status and the presented cert intact.
func TestHTTPSDowngradeRefusedBeforeDial(t *testing.T) {
	const originHost = "downgrade-origin.example.test"
	cert := selfSignedTLSForHost(t, originHost)

	var clearReq int32
	clearSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&clearReq, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer clearSrv.Close()

	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, clearSrv.URL+"/clear?token=sekrit", http.StatusMovedPermanently)
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	origin.StartTLS()
	defer origin.Close()
	originPort := origin.Listener.Addr().(*net.TCPAddr).Port

	startFakeDNS(t, "10.99.99.50") // originHost resolves RFC1918: guard allows
	oldDialer := probeDialer
	probeDialer = loopbackDialer{} // pinned IP -> where the test servers live
	t.Cleanup(func() { probeDialer = oldDialer })

	// A fresh cert-read map so the origin probe forces one real handshake.
	certReadMu.Lock()
	oldMap := certReadTimes
	certReadTimes = make(map[string]time.Time)
	certReadMu.Unlock()
	t.Cleanup(func() {
		certReadMu.Lock()
		certReadTimes = oldMap
		certReadMu.Unlock()
	})

	// Probe the HOSTNAME (not the 127.0.0.1 literal): the cert is for
	// originHost, and the fake DNS + loopback dialer route it to the
	// in-process server — the same shape as production (host → checked IP).
	res := probeHTTP(context.Background(), fmt.Sprintf("https://%s:%d/", originHost, originPort), 5*time.Second)
	if !res.Lost {
		t.Fatalf("downgrade probe marked up, want loss: %+v", res)
	}
	if n := atomic.LoadInt32(&clearReq); n != 0 {
		t.Fatalf("cleartext http target received %d request(s) — the downgrade hop was dialed and the URL token went out in plaintext", n)
	}
	if res.Status == nil || *res.Status != http.StatusMovedPermanently {
		t.Fatalf("status = %v, want 301 (the redirect that was refused)", res.Status)
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "redirected to plain http") {
		t.Fatalf("err = %v, want the downgrade refusal", res.Err)
	}
	if res.CertExpiry == nil {
		t.Fatal("cert expiry missing — the presented cert must still be reported on the card")
	}
}

// TestCheckRedirectDowngradeClassification pins the classifier: an https
// origin redirected to http is refused with ErrUseLastResponse AND the
// downgrade flag set in the per-probe pins (same- and cross-host);
// same-scheme and upgrade hops leave the flag unset; a first request (no
// via) never matches the rule. IP literals keep the cross-host cases
// DNS-free.
func TestCheckRedirectDowngradeClassification(t *testing.T) {
	mk := func(rawurl string, pins *redirectPins) *http.Request {
		var ctx context.Context = context.Background()
		if pins != nil {
			ctx = context.WithValue(ctx, pinsKey{}, pins)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
		if err != nil {
			t.Fatalf("NewRequest(%s): %v", rawurl, err)
		}
		return r
	}
	cases := []struct {
		name    string
		from    string // the original request (via[0])
		to      string // the redirect target
		wantErr bool
	}{
		{"same-host https->http downgrade", "https://h.example:443/x", "http://h.example:80/x", true},
		{"cross-host https->http downgrade", "https://192.0.2.1:443/x", "http://192.0.2.2:80/x", true},
		{"same-host https->https", "https://h.example:443/x", "https://h.example:443/y", false},
		{"cross-host https->https (N4)", "https://192.0.2.1:443/x", "https://192.0.2.2:443/y", false},
		{"same-host http->https upgrade", "http://h.example:80/x", "https://h.example:443/x", false},
		{"same-host http->http", "http://h.example:80/x", "http://h.example:80/y", false},
	}
	for _, tc := range cases {
		pins := &redirectPins{m: make(map[string]net.IP)}
		err := httpClient.CheckRedirect(mk(tc.to, pins), []*http.Request{mk(tc.from, nil)})
		pins.mu.Lock()
		flag := pins.downgrade
		pins.mu.Unlock()
		if tc.wantErr {
			if err != http.ErrUseLastResponse {
				t.Fatalf("%s: CheckRedirect = %v, want ErrUseLastResponse", tc.name, err)
			}
			if !flag {
				t.Fatalf("%s: downgrade flag not set in the per-probe pins", tc.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: CheckRedirect = %v, want nil", tc.name, err)
		}
		if flag {
			t.Fatalf("%s: downgrade flag set on a non-downgrade hop", tc.name)
		}
	}
	// No via (a first request, never a redirect) must not match the
	// downgrade rule — the len(via) > 0 guard (IP literal: no DNS).
	pins := &redirectPins{m: make(map[string]net.IP)}
	if err := httpClient.CheckRedirect(mk("http://192.0.2.1:80/x", pins), nil); err != nil || pins.downgrade {
		t.Fatalf("no-via request: err=%v flag=%v, want nil + no flag", err, pins.downgrade)
	}
}
