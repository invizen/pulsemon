package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTP probe type. Unlike ICMP (a shared socket + reader goroutine that
// dispatches out-of-band replies), an HTTP probe is a plain request ->
// response: no socket lifecycle, no background reader, no sequence numbers.
// So it is a thin wrapper over net/http with a per-sensor deadline, and it
// reuses ping.go's resolveIPAddrWithTimeout for the resolved_ip diagnostic
// (a hung DNS lookup must become a loss row, not wedge the probe tick).

// probeHTTPTimeout is the client-level ceiling for a single HTTP probe. The
// per-sensor timeout bounds each request via context; this is a second,
// coarser backstop so a misbehaving handler (very large body, slow trickle)
// can never hold the probe goroutine past the sensor's own timeout.
const probeHTTPTimeout = 60 * time.Second

// maxHTTPRedirects caps how many redirects a probe will follow. A redirect
// chain is normal for real web apps (http→https, /→/app/login/), so the
// probe follows them and judges the FINAL status. The cap stops a
// misbehaving host from looping the probe; hitting it leaves the last 3xx as
// the terminal status (a loss), which is the honest outcome for a loop.
const maxHTTPRedirects = 5

// httpClient is shared by every HTTP sensor: the transport reuses
// keep-alive connections per host, so N sensors hitting one host pay one
// TCP+TLS handshake, not N. Per-host connection cap keeps a single chatty
// host from monopolizing the pool. Redirects are followed (up to
// maxHTTPRedirects) so a target that 301/302s to its real destination —
// the common case for a web UI behind a redirect — is judged on where it
// ends up, not the redirect itself.
var httpClient = &http.Client{
	Timeout: probeHTTPTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// via includes the original request, so len(via) is the number of
		// requests already made; the next one would be the (len+1)th.
		if len(via) > maxHTTPRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	},
	Transport: &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       10 * time.Minute,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

// httpProbeResult is one HTTP probe: the round-trip time, whether it counts
// as a loss (no response OR status outside 200-299), the HTTP status code
// when a response arrived (nil when it didn't), the resolved IP, the
// server certificate's expiry (nil for plain HTTP or when no handshake
// happened — including self-signed certs, which fail verification but still
// hand the cert over in the error), and any transport error.
//
// The cert expiry is INFORMATIONAL ONLY: it never affects Lost or status.
// A cert expiring in 3 days does not take the sensor down — it just earns
// an amber/red note on the card so the user renews it on purpose.
type httpProbeResult struct {
	Elapsed    time.Duration
	Lost       bool
	Status     *int
	IP         string
	CertExpiry *time.Time
	Err        error
}

// probeHTTP performs one GET against target and classifies it. Redirects are
// followed (capped at maxHTTPRedirects), and the FINAL status decides: 2xx =
// success, anything else — timeout, connection error, TLS verification
// failure, a terminal 3xx/4xx/5xx, or a redirect loop — is a loss (the same
// loss that drives the card's loss%, sparkline, and status state, exactly as
// an ICMP loss does).
func probeHTTP(target string, timeout time.Duration) httpProbeResult {
	// Resolve the host up front so the resolved_ip diagnostic is populated
	// the same way ICMP fills it (and a hung DNS becomes a loss row, not a
	// wedged tick). The request still runs under its own deadline below.
	var host string
	if u, err := url.Parse(target); err == nil {
		host = u.Hostname()
	}
	resolved := ""
	if host != "" {
		if ip, err := resolveIPAddrWithTimeout(context.Background(), host, 5*time.Second); err == nil {
			resolved = ip.IP.String()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		// Malformed URL. Validation at save time (validURL) should prevent
		// this; a loss row with the error is the honest fallback.
		return httpProbeResult{Lost: true, IP: resolved, Err: err}
	}
	start := time.Now()
	resp, err := httpClient.Do(req)
	el := time.Since(start)
	if err != nil {
		// A TLS verification failure (expired/self-signed) is still a
		// handshake: the server's cert is attached to the error, so the
		// card can show its expiry even though the probe is a loss.
		return httpProbeResult{Elapsed: el, Lost: true, IP: resolved, CertExpiry: certNotAfterFromErr(err), Err: err}
	}
	defer resp.Body.Close()
	// We only need the status line, not the body. Draining it would cost a
	// download per probe; releasing it here lets the transport reuse the
	// connection for the next probe.
	var certExp *time.Time
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		na := resp.TLS.PeerCertificates[0].NotAfter
		certExp = &na
	}
	code := resp.StatusCode
	up := code >= 200 && code <= 299
	return httpProbeResult{
		Elapsed:    el,
		Lost:       !up,
		Status:     &code,
		IP:         resolved,
		CertExpiry: certExp,
		Err:        nil,
	}
}

// certNotAfterFromErr walks a failed handshake's error chain for the
// server's leaf certificate and returns its NotAfter, or nil. Covers the
// two shapes net/http surfaces: tls.CertificateVerificationError carrying
// the full unverified chain (leaf first), and x509.UnknownAuthorityError
// carrying only the leaf. Plain transport errors (timeout, refused) return
// nil.
func certNotAfterFromErr(err error) *time.Time {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) && len(certErr.UnverifiedCertificates) > 0 {
		na := certErr.UnverifiedCertificates[0].NotAfter
		return &na
	}
	var unknown *x509.UnknownAuthorityError
	if errors.As(err, &unknown) && unknown.Cert != nil {
		na := unknown.Cert.NotAfter
		return &na
	}
	return nil
}

// validURL reports whether t is a usable HTTP/HTTPS target: an absolute URL
// with an http(s) scheme and a dotted or bracketed host. The dotted-host
// requirement matches validTarget's stance for ICMP (bare single-label
// hostnames are almost always typos) and is enforced on the host part.
func validURL(t string) bool {
	u, err := url.Parse(t)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	host := u.Hostname() // strips the port, keeps IPv6 brackets off
	if host == "" {
		return false
	}
	// A dotted host, a bracketed/IPv6 host, or a host with an EXPLICIT port
	// is accepted. The dotted-host rule otherwise rejects bare single-label
	// names ("router") that are almost always typos — but a port makes the
	// target deliberate and unambiguous (e.g. an internal server at
	// http://zensrv:8080), so a port overrides the dot requirement.
	if strings.Contains(host, ".") || strings.Contains(host, ":") || u.Port() != "" {
		return true
	}
	return false
}

// httpStatusText formats a status code for display ("503"), or "no response"
// when no response arrived at all (timeout / connection failure).
func httpStatusText(status *int) string {
	if status == nil {
		return "no response"
	}
	return fmt.Sprintf("%d", *status)
}
