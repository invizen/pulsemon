package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
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
//
// TLS: the transport sets InsecureSkipVerify so the handshake always
// succeeds and the server's presented certificates are handed back instead
// of being rejected at the TLS layer. probeHTTP then verifies them itself
// via verifyHTTPCert, which accepts a cert when it is trusted by the system
// roots OR genuinely self-signed with a hostname and validity matching the
// target. That is how self-signed homelab web UIs become monitorable without
// accepting every certificate.
//
// Redirect guard: a monitored public host can 302 the probe anywhere,
// including cloud metadata (169.254.169.254) or loopback services — the
// same pivot the webhook client refuses outright. Redirect hops are judged
// against the same never-reachable ranges (loopback, link-local,
// unspecified, multicast, plus the webhook blocklist). RFC1918/ULA redirect
// targets stay allowed on purpose: a LAN device redirecting to its LAN
// UI is the common legitimate case, and the initial target is
// admin-configured anyway. The INITIAL request is not guarded — it is the
// operator's own configured target; only hops the operator did not choose
// are vetted.
// redirectTargetAllowed judges a redirect hop for the probe client.
// Same-host hops (host == origHost, the host of the FIRST request in the
// chain) pass untouched: router.local/ → router.local/login is the shape of
// most real web UIs and the operator configured that host anyway. A
// cross-host hop is resolved and refused if ANY resolved address is in a
// never-monitorable range (loopback, link-local incl. cloud metadata
// 169.254.169.254, unspecified, multicast, or a webhook blockedSubnets
// range). RFC1918/ULA cross-host hops pass: LAN-to-LAN redirects are
// legitimate for monitoring.
//
// Known limitation (stated, not hidden): hostname resolution here has a
// TOCTOU window that the webhook path closes by pinning its dial to the
// checked IPs. The probe client cannot pin without a per-probe
// DialContext, and the attacker would already need sensor-create rights
// (or LAN access before any user exists). This raises the bar
// substantially, which is the point.
//
// Security-review note (deliberate, do NOT "fix" by blocking private ranges):
// Allowing RFC1918/ULA cross-host redirect hops is INTENTIONAL, not an
// oversight. The probe client performs no IP-range check on the INITIAL
// target at all — it is the operator's own configured sensor — so anyone who
// can create a sensor can already point a probe straight at
// http://192.168.1.1/reboot as the FIRST request. The redirect path grants no
// additional reach; it duplicates a capability the tool has by design, so it
// is not an SSRF relay. The guard's real job is already closed: it stops an
// EXTERNALLY-monitored public host from 302-ing the probe into cloud metadata
// (169.254.169.254), loopback, or reserved space — the pivot that matters.
// A blanket ip.IsPrivate() block here (as an external review proposed) would
// regress the pinned legitimate case — a public hostname served via
// split-horizon DNS to a LAN IP, or an external URL 302-ing to an internal
// dashboard — while shrinking the real attack surface by zero, because the
// initial-target path stays open by design. This is a single-operator LAN
// tool: the person who can create a sensor owns the whole LAN's monitoring
// surface. See TestRedirectTargetAllowed ("LAN redirect stays allowed").
func redirectTargetAllowed(host, origHost string) error {
	if host == "" {
		return errors.New("redirect with empty host")
	}
	if strings.EqualFold(host, origHost) {
		return nil // same-host hop: the operator's own target
	}
	judge := func(ip net.IP) error {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("redirect target %q resolves to a blocked address (%s)", host, ip)
		}
		for _, n := range blockedSubnets {
			if n.Contains(ip) {
				return fmt.Errorf("redirect target %q resolves to a reserved address (%s)", host, ip)
			}
		}
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return judge(ip)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("redirect target %q cannot be resolved: %v", host, err)
	}
	for _, ip := range ips {
		if err := judge(ip); err != nil {
			return err
		}
	}
	return nil
}

var httpClient = &http.Client{
	Timeout: probeHTTPTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// via includes the original request, so len(via) is the number of
		// requests already made; the next one would be the (len+1)th.
		if len(via) > maxHTTPRedirects {
			return http.ErrUseLastResponse
		}
		origHost := ""
		if len(via) > 0 {
			origHost = via[0].URL.Hostname()
		}
		if err := redirectTargetAllowed(req.URL.Hostname(), origHost); err != nil {
			return err
		}
		return nil
	},
	Transport: &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       10 * time.Minute,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	},
}

// verifyHTTPCert validates the certificate(s) the server presented after a
// successful (skip-verify) handshake. It accepts the cert when EITHER
// (a) it is trusted by the system roots, or
// (b) it is genuinely self-signed (issuer == subject) AND its hostname and
// validity hold for host. Everything else — a cert from an untrusted CA, an
// expired cert, or a cert whose names don't match host — is rejected, so
// "allow self-signed" never becomes "allow anything".
//
// host is the target's hostname (e.g. "10.0.0.5" or "router.local"). An IP
// literal is normalized so x509 matches it against IP SANs, not DNS names.
// A nil/empty presented slice (plain HTTP, or no certs) is accepted — there
// is nothing to verify.
func verifyHTTPCert(presented []*x509.Certificate, host string) error {
	if len(presented) == 0 {
		return nil
	}
	if host == "" {
		return errors.New("pulsemon: no target host to verify TLS certificate against")
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	leaf := presented[0]

	// The server presents the full chain: leaf first, then intermediates.
	// Chain building to a trusted root REQUIRES those intermediates even
	// when the root is in the system trust store — a standard TLS client
	// gets them for free from resp.TLS.PeerCertificates, but a manual
	// Verify() call must be handed them explicitly. Build the pool once and
	// use it for both branches below. (This is why a real CA-issued cert
	// must not be checked against system roots with an empty Intermediates
	// pool: the chain can't be completed and the cert reads untrusted.)
	inter := x509.NewCertPool()
	for _, c := range presented[1:] {
		inter.AddCert(c)
	}

	// (a) Trusted by the system roots, with the presented intermediates —
	// accept. Roots nil → the platform/system trust store. Real CDNs and
	// registrars often serve a cert for the www variant of a bare domain
	// (google.com → cert is www.google.com) or the other way around, so a
	// hostname mismatch is retried once with the other variant.
	triedHosts := []string{host}
	if len(host) > 0 && !strings.HasPrefix(host, "www.") {
		triedHosts = append(triedHosts, "www."+host)
	} else if strings.HasPrefix(host, "www.") {
		triedHosts = append(triedHosts, strings.TrimPrefix(host, "www."))
	}
	for _, hn := range triedHosts {
		optsA := x509.VerifyOptions{Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		optsA.DNSName = hn
		if _, err := leaf.Verify(optsA); err == nil {
			return nil
		}
	}

	// (b) Not system-trusted: accept only if self-signed AND its hostname +
	// validity hold for this target. Verifying the leaf against itself as a
	// root re-checks both without demanding a trusted issuing CA. Same
	// www-variant fallback as branch (a).
	if leaf.CheckSignatureFrom(leaf) == nil {
		roots := x509.NewCertPool()
		roots.AddCert(leaf)
		for _, hn := range triedHosts {
			optsB := x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			optsB.DNSName = hn
			if _, err := leaf.Verify(optsB); err == nil {
				return nil
			}
		}
	}
	return errors.New("pulsemon: TLS certificate is not trusted and is not a self-signed cert matching the target")
}

// drainBodyCap bounds how much of a response body probeHTTP will read so
// the transport can reuse the keep-alive connection. An UNREAD body makes
// net/http discard the connection — which would defeat the whole point of
// the shared client (one TCP+TLS handshake per host, not one per probe).
// 1MB is far above any real health endpoint's response; anything larger is
// discarded after the cap so a huge page costs one bounded read, not a
// full download.
const drainBodyCap = 1 << 20

// httpProbeResult is one HTTP probe: the round-trip time, whether it counts
// as a loss (no response OR status outside 200-299), the HTTP status code
// when a response arrived (nil when it didn't), the resolved IP, the
// server certificate's expiry (nil for plain HTTP or when no handshake
// happened), and any transport/verification error. Self-signed certs that
// match the target are accepted (see verifyHTTPCert), so an HTTPS probe to
// a self-signed homelab UI succeeds and the expiry is captured from the
// handshake; a cert that is neither system-trusted nor a valid self-signed
// match is a loss.
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
		// A transport-level failure: timeout, connection refused, DNS, or a
		// malformed TLS handshake. With InsecureSkipVerify the handshake
		// itself always completes and the peer's certs ride back on resp, so
		// a certificate problem no longer surfaces here — it is caught by
		// verifyHTTPCert below. certNotAfterFromErr stays as a safety net
		// for the rare handshake error that does carry a cert.
		return httpProbeResult{Elapsed: el, Lost: true, IP: resolved, CertExpiry: certNotAfterFromErr(err), Err: err}
	}

	// Capture the server's presented certs and their expiry, then close the
	// body. We only need the status line and the cert; draining (capped)
	// before close lets the transport reuse the keep-alive connection
	// instead of discarding it after an unread body.
	var presented []*x509.Certificate
	var certExp *time.Time
	if resp.TLS != nil {
		presented = resp.TLS.PeerCertificates
	}
	if len(presented) > 0 {
		na := presented[0].NotAfter
		certExp = &na
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainBodyCap))
	resp.Body.Close()

	// Now that the handshake has returned the peer's certificates, verify
	// them ourselves. This is where "allow self-signed" lives: a cert
	// trusted by the system roots OR a genuine self-signed cert matching the
	// target's host is accepted; anything else is a loss.
	if vErr := verifyHTTPCert(presented, host); vErr != nil {
		return httpProbeResult{Elapsed: el, Lost: true, IP: resolved, CertExpiry: certExp, Err: vErr}
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
	// http://nas:8080), so a port overrides the dot requirement.
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
