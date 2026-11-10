# pulsemon v1.1.0

## New: TCP / port sensor

A third sensor type, `tcp`, for everything that listens on a port but
isnt an HTTP endpoint: Postgres, SSH, SMTP, databases, game servers,
printers, NAS shares — the services ICMP "host is up" and HTTP "URL
answers" never looked at.

- Target grammar `host:port` — the port is required (1-65535); the host
  accepts the same shapes as PING targets (IPv4, dotted hostname, or a
  bare single-label LAN name). IPv4-only, like the rest of the product.
- The probe is a one-shot TCP connect: up when the port accepts a
  connection, RTT = connect time (DNS + handshake, the same TTFB stance
  as the HTTP sensor).
- Name resolution reuses the bounded, cached resolver from the ICMP
  path: a dead local resolver reads as a `dns_error` row ("DNS
  failure"), not "N hosts down" — one root cause, one sensor, not an
  N-sensor storm.
- Everything downstream is the same: loss/warning/error derivation,
  recovery + re-alerts, maintenance mode, 1h/24h graphs, Pulse Now,
  tags, clone.
- Save-time validation: a portless target (`10.0.0.5`) or an out-of-
  range port is rejected with a clear message.

## Also in this release

- README: the feature list now documents the HTTP and TCP sensors
  (it previously only mentioned ICMP).
- `docs/DECISIONS.md`: new `tcp-sensor` entry — rationale, the
  resolve-then-dial-IP design, and why the connect time is the RTT.

## Upgrading

Self-update (dashboard → Settings) or `docker compose up -d --build`.
Linux self-updates verify the ed25519 release signature (v0.4.0+
gate); both Linux assets in this release are signed.
