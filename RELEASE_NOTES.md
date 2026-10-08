## v0.1.36

A small security-hardening release from an external review round. Three
behavior changes: the login throttle can no longer be dodged with a rotated
`X-Forwarded-For` header, the login timing-equalization dummy is now
precomputed, and webhook URL validation rejects IETF-reserved and carrier-NAT
address ranges.

### Security

- **Login throttle ignores untrusted `X-Forwarded-For` by default.** The
  per-IP failure counter (7 failures in 60s → 5-minute lockout) used to key on
  the first `X-Forwarded-For` entry when present, so an attacker could rotate
  a spoofed header on every request and never trip the lockout — enabling
  unlimited password guessing. The throttle now keys on the **direct TCP
  peer** by default. If pulsemon sits behind a reverse proxy and you want
  attempts attributed to the real client, set the new
  `PULSEMON_TRUSTED_PROXIES` env var (comma-separated CIDRs or bare IPs, e.g.
  `127.0.0.1`); the header is read only when the connection's source address
  is in that list. A typo'd entry is logged and skipped — it can't break
  startup.
- **Precomputed login-timing dummy.** The dummy bcrypt hash that keeps
  unknown-user logins timing the same as wrong-password ones (so the
  username can't be guessed from response time) is now built once at
  startup from the configured bcrypt cost, instead of reformatted on every
  unknown-user lookup.
- **Webhook URL validation rejects reserved ranges.** Alert-destination
  URLs now reject IETF reserved-for-testing addresses (198.18.0.0/15) and
  carrier-grade NAT (100.64.0.0/10) in addition to loopback, link-local, and
  unspecified. Private (LAN) ranges stay allowed — a self-hosted relay in
  your own network remains a valid destination.

### Verified

- Full test suite passes under `-race`, `go vet` and `gofmt` clean.
- XFF rotation verified live: 8 login attempts each carrying a different
  spoofed `X-Forwarded-For` → the 8th is rejected with 429.

---

## v0.1.30

A focused HTTPS-sensor bugfix release: the certificate hostname check now
crosses the **www** boundary, so a sensor on a bare domain works when the
server presents a cert for the `www.` variant (and vice versa). This is the
fix behind "google.com / letsencrypt.org read not trusted" on the v0.1.29
fleet. No change to probe scheduling, status derivation, alert routing, or
the dashboard.

### HTTPS sensors: accept a www-variant certificate hostname

Real CDNs and registrars commonly serve a certificate for the **www**
variant of a bare domain, or the other way around. Google is the canonical
case: a request to `https://google.com` presents a certificate whose only
subject name is `www.google.com` — the bare `google.com` is not in the cert
at all. A standard TLS client accepts that, but the strict hostname check
in v0.1.29 did not, so the sensor read **error** ("not trusted") even
though `curl` reached the site fine.

`verifyHTTPCert` now retries the hostname check once against the other
**www** variant — when the target is a bare host it also tries
`www.<host>`, and when the target is a `www.` host it also tries the bare
host — in both the system-trusted and self-signed branches. The fallback
only crosses the `www.` boundary: an unrelated domain, a wrong host, an
expired cert, and a rogue-CA-signed cert are all still losses, exactly as
before.

> Note: this is a republish of the corrected v0.1.29 certificate work. If
> your box is on `v0.1.29` and `pulsemon update` reports "up to date," you
> are on the original (pre-fix) v0.1.29 build — run `pulsemon update
> v0.1.30` explicitly, or `./install.sh v0.1.30`.

---

## v0.1.29

A small HTTP-sensor hardening release: HTTPS probes now work out of the box
against self-signed endpoints, the probe's shared connection pool actually
keeps connections alive, and the dashboard's RTT labels now say "Resp" —
because an HTTP probe measures a response, not a ping. No change to probe
scheduling, status derivation, or alert routing.

### HTTPS sensors: accept self-signed certificates (hostname + expiry still enforced)

Most homelab web UIs serve a self-signed or private-CA certificate, which a
strict client treats as a verification failure — so an HTTPS sensor pointed
at them read **error** permanently, with no way to make it monitorable short
of installing the CA into the OS trust store.

HTTPS probes now accept a certificate when it is **either**:

- trusted by the system roots (unchanged behavior for public and properly
  chained certs), **or**
- **genuinely self-signed** (issuer == subject) *and* its hostname and
  validity period match the target.

Chain building uses the full certificate chain the server presents (leaf +
intermediates) against the system trust store, so public and CDN-fronted
certs verify the same way a standard TLS client does.

A common real-world case is handled too: many CDNs and registrars serve a
cert for the **www** variant of a bare domain (google.com presents a cert
whose names are `www.google.com`) or the reverse. When the target host
differs from the certificate's names only by the `www.` prefix, the check
is retried once with the other variant — so a sensor on `google.com` works
even though the presented cert literally names only `www.google.com`.
Unrelated domains still fail; the fallback only crosses the www boundary.

"Allow self-signed" deliberately does **not** become "allow anything": a
cert signed by an untrusted (rogue) CA, an **expired** cert, and a cert whose
names don't match the target are all still losses, exactly as before. The
inspector's certificate-expiry advisory keeps working on the same path.

### HTTP probes now reuse keep-alive connections

The shared probe client was configured to reuse one TCP+TLS connection per
host, but the response body was closed without being read — and net/http
discards a connection whose body wasn't consumed. In practice every probe
opened a fresh connection and paid a full TCP+TLS handshake, which the
original design explicitly set out to avoid. The body is now drained up to a
1 MB cap before the connection is released: small responses (the normal
health-endpoint case) hand the connection back to the pool, and a huge page
costs one bounded read instead of a full download.

### Dashboard: "Ping" → "Resp" for the response-time labels

An HTTP/HTTPS probe measures **TTFB** (DNS + TCP + TLS + first response
byte) — not an ICMP round trip — so the response time for a web sensor is
naturally higher than `ping` to the same host. The table column already
switched from "Ping" to "Resp" when HTTP sensors are visible; the three
remaining static labels now match: the inspector stat ("Resp last"), the
inspector graph ("Resp over time"), and the sort options ("Resp high→low /
Resp low→high"). The ICMP-only labels ("PING / ICMP" type option, PING
badges) are untouched.

### Verified

- Full test suite green with `-race`, `go vet` and `gofmt` clean, including
  new tests: valid self-signed cert accepted with expiry captured; expired
  self-signed rejected; self-signed with wrong hostname rejected;
  CA-signed-but-untrusted rejected (presented cert still captured for the
  advisory); a keep-alive regression test that three same-host probes share
  one server-side connection — confirmed to fail against the pre-fix code
  (3 distinct connections); and a chain-building regression test that a
  public CDN-fronted cert (leaf + intermediate to a trusted root) is
  accepted — confirmed to fail against the pre-fix code.
- Verified against live TLS servers: self-signed/valid → accept,
  self-signed/expired → reject, self-signed/wrong-host → reject,
  rogue-CA/valid+right-host → reject, public leaf+intermediate → accept.

---
