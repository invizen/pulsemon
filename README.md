# pulsemon

A single-container ICMP network sensor monitor for your homelab. One Go binary,
one SQLite file, one dark dashboard — built to monitor exactly what you care about
and says nothing until something changes.

```
pulsemon
```

## Features

- **ICMP ping monitoring** — single shared ping socket with per-probe sequence
  dispatch (accurate RTTs even under load). See *ICMP & privileges* below for
  the access model.
- **Single container** — static Go binary, `FROM scratch` image, SQLite storage
- **Sensors with multiple tags** — group and filter however you like
- **Per-sensor tuning** — interval, timeout, loss threshold, error-after count
- **Status derivation** — `up` / `warning` / `error` from the sensor's most
  recent probes (see *Alert behavior*)
- **1h / 24h latency graphs** with whole-ms display
- **Alerts** — Google Chat + Discord, fan-out to every enabled destination,
  re-alerts, one-click test from Settings
- **Alert controls** — routing (all / by tag / by sensor), re-alert interval
  (0 = alert once only), one-click **maintenance mode**
- **Dashboard** — card ⇄ table views, inspector with history, activity feed,
  optimized for 1080p and up
- **Authentication** — optional username/password gate (Settings →
  Authentication): create the first account to turn it on, add/remove more,
  change your password, or disable it (removes all accounts). Sessions last
  30 days; `/api/healthz` stays open for external monitors

## Requirements

- Docker (with Compose v2)
- Port 9299 free on the host (change in `compose.yaml`, or set `PULSEMON_ADDR`)

## Quick start

```bash
git clone https://github.com/invizen/pulsemon pulsemon && cd pulsemon
cp .env.example .env          # optional: put a Google Chat webhook URL in .env
chmod 600 .env
mkdir -p data && chmod 0777 data  # pre-create the data dir (see note below)
docker compose up -d --build
```

Open http://localhost:9299 and add sensors from the **new sensor** button.

> **First boot:** the database is created automatically on first run
> (`data/pulsemon.db`). Two demo sensors (`router`, `server`) are seeded
> automatically — paused, targeting `127.0.0.1` — because not every host
> has a router or server on the same network; edit their targets (or
> delete them) and resume. Seeding runs only on an empty database.
>
> **Why pre-create `data/`?** The container runs as uid 1000 (unprivileged).
> If the bind-mount source doesn't exist, Docker creates it **root-owned**
> and the container crash-loops with `Failed to open DB: unable to open
> database file`. Pre-creating the directory yourself (any ownership works —
> `chmod 0777` is the no-sudo option) avoids that. If it already happened,
> `sudo chown -R 1000:1000 data` fixes it.

## Bare install (no Docker, user-level systemd)

```bash
curl -sfL https://raw.githubusercontent.com/invizen/pulsemon/main/install.sh -o /tmp/pulsemon-install.sh
bash /tmp/pulsemon-install.sh              # latest release, or: bash /tmp/pulsemon-install.sh v0.1.7
```

The installer (no sudo required) downloads and **SHA-256-verifies** the
release binary, installs it to `~/pulsemon/`, writes a user-level
`pulsemon.service` (pointing at `~/pulsemon/data/pulsemon.db` via `PULSEMON_DB`),
adds `~/pulsemon` to `PATH` in `~/.bashrc` (guarded — re-running never
duplicates the line), and enables + starts the service. It tries
`sudo -n loginctl enable-linger` so pulsemon keeps running after you log out;
if that needs a password it tells you the one command to run.

```bash
pulsemon update            # self-update from any directory (v0.1.6+)
pulsemon update --restart  # install AND restart the running service, then verify healthz
pulsemon update check      # check only — exit 2 when a newer release exists
pulsemon update v0.1.7     # pin or roll back to a specific version
```

`pulsemon update` finds the running binary itself (`os.Executable`), verifies
the published SHA-256, and swaps it atomically — then prints the restart
command. After it runs: `systemctl --user restart pulsemon`.
`--restart` does that for you: it auto-restarts only when a live systemd
`pulsemon` service is confidently detected (user bus, or system bus when
running as root), then polls healthz and reports the outcome — so a
container or non-systemd host still just gets the restart hint (a bad new
version would otherwise take the monitor down).

## ICMP & privileges

pulsemon opens a single shared ICMP socket and dispatches replies by sequence
number (so RTTs stay accurate when many sensors probe at once). On Linux there
are two ways to send ICMP, and pulsemon tries them in order at startup:

1. **Datagram ping socket** (`socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`) —
   preferred. This is the socket the `ping` binary uses as an ordinary user.
   It needs **no root and no `CAP_NET_RAW`**; instead the process's uid must
   fall inside `net.ipv4.ping_group_range` (check with
   `sysctl net.ipv4.ping_group_range`). On Linux the kernel overwrites the
   ICMP identifier with a per-socket value and delivers only that socket's
   replies, so pulsemon dispatches by sequence + source IP on this path.
2. **Raw socket** (`SOCK_RAW` + `IPPROTO_ICMP`) via
   `icmp.ListenPacket("ip4:icmp", …)` — fallback. It requires **root or
   `CAP_NET_RAW`**, regardless of `ping_group_range`. Used automatically when
   the datagram socket isn't available.

Which one you're on is reported by `GET /api/healthz` as `"icmp_mode"`
(`"unprivileged-datagram"` or `"raw"`).

| Deployment | Result | How |
|---|---|---|
| Docker (default image) | ✅ unprivileged | The container runs as **uid 1000** (see `USER` in `Dockerfile`); the datagram socket works off `ping_group_range`. Pre-create the `data/` bind-mount dir (or `chown -R 1000:1000` it) — see Quick start. |
| Bare / systemd as a normal user | ✅ if in range | Works when the user's uid is inside `ping_group_range` (the datagram socket); otherwise it falls back to the raw socket, which needs `CAP_NET_RAW`/root. |

> **Why not just `"udp4"`?** x/net/icmp's `ListenPacket("udp4", …)` is **not**
> an unprivileged ICMP socket — it creates a plain UDP socket and cannot send
> echo requests. The unprivileged path is the `SOCK_DGRAM`/`IPPROTO_ICMP`
> socket above.

## Configuration

| Where | What |
|---|---|
| `.env` (or container env) | `GOOGLE_CHAT_WEBHOOK_URL` — Google Chat URL used when none is set in the dashboard |
| env | `PULSEMON_ADDR` — HTTP listen address, full `host:port` (e.g. `:9299`, `127.0.0.1:9299`). Default `:9299` (all interfaces). 8080 was the pre-0.1.19 default; 9299 avoids the dashboards/proxies that usually claim it. |
| env | `PULSEMON_CERT` + `PULSEMON_KEY` — optional TLS certificate and key file paths (PEM). Set **both** together to serve HTTPS; omit both for plain HTTP. **When a valid pair is in place, pulsemon serves HTTPS ONLY on `listener_https_port` (Dashboard → Settings, default `443`) and does NOT bind the `PULSEMON_ADDR` port at all** — there is no plaintext fallback while a pair is configured. ⚠️ **Non-root and Docker users MUST set `listener_https_port` to an unprivileged port (e.g. `8443`)**: the default 443 bind fails without root, and the server will not start. If the files are missing, pulsemon warns and serves plain HTTP on `PULSEMON_ADDR` (so a fresh clone with no `certs/` dir doesn't crash-loop; opt back into this with `PULSEMON_ALLOW_PLAINTEXT_FALLBACK=1`); if they exist but are corrupt or mismatched, startup fails — TLS is never silently degraded when a pair is in place. A self-signed or wildcard cert works for LAN use; use a real cert if the dashboard is reachable from outside. |
| env | `PULSEMON_TRUSTED_PROXIES` — optional comma-separated list of CIDRs (or bare IPs) of **immediate TCP peers** whose `X-Forwarded-For` header is trusted for login rate-limiting. By default `X-Forwarded-For` is **ignored** (the throttle keys on the direct TCP peer), so a spoofed/rotated header can't dodge the per-IP lockout. When pulsemon sits behind a reverse proxy (Caddy, nginx, …) and you want attempts attributed to the real client, set this to the proxy's IP(s), e.g. `127.0.0.1` or `192.168.1.0/24`. The header is only ever read when the connection's source address is in this list. |
| Dashboard → Settings | Alert destinations (Google Chat, Discord — each with its own URL and toggle), alert routing, re-alert interval, maintenance mode, TLS certificate, **Authentication** (create the first account, add/remove accounts, change password, disable) |
| Per sensor | Interval, timeout, loss %, error-after, tags |
| CLI | `pulsemon auth-user add <user> <pass>` — create a dashboard account (the FIRST account is what turns authentication on). `pulsemon auth-user remove <user>` — delete an account (the last one is refused; use the dashboard's "Disable Authentication" for that). `pulsemon auth-user list` — list accounts. Auth is opt-in; with no accounts the dashboard is open, as before. |

### Behind a reverse proxy

When pulsemon sits behind Caddy, Traefik, nginx, or similar:

- **`PULSEMON_TRUSTED_PROXIES`** — comma-separated CIDRs (or bare IPs) of the
  **immediate proxy peer**, e.g. `127.0.0.1` or `172.18.0.0/16` for a proxy
  container on a Docker network. **Required behind a proxy** so login
  throttling keys on the real client: pulsemon then reads `X-Forwarded-For`
  right to left and uses the rightmost address that is not itself a trusted
  proxy (entries further left are client-supplied and ignored). If it is
  **unset** behind a proxy, every client shares the proxy's IP — and its
  throttle budget — so **7 bad logins from anyone lock everyone out for 5
  minutes**. Throttling is per /24 (IPv4) or /64 (IPv6).
- **`PULSEMON_ALLOWED_HOSTS`** — optional setup-mode hardening. A
  comma-separated list of `host` or `host:port` names the dashboard is reached
  by (case-insensitive; an entry without a port matches any port). When set,
  creating the **first** account (fresh install, no users yet) is refused with
  `421` unless the request's `Host` header is listed — which closes the
  DNS-rebinding route by which a malicious web page could claim the first
  account through a LAN browser. Unset = any Host (the LAN-trust default).
  Has no effect once an account exists.
- The proxy must preserve the original `Host` header (Caddy and Traefik do by
  default) — the cross-origin check compares it with the browser's `Origin`.

### Alert behavior

Statuses are `up`, `warning`, and `error`. A sensor's status is derived from
its most recent probes, checked in this order:

- **up** — a sensor recovering from **error** whose newest probe succeeded
  (error → up on a single good reply); a brand-new sensor with 1
  successful probe; the last 2 probes both succeeded **and** loss over the
  last 8 probes is below the sensor's loss threshold (25% at the default);
  or a single recent loss amid sub-threshold stats (a blip — the LOSS
  metric and red sparkline bar show it). Recovery is checked first, so a
  sensor recovering from a long outage flips back quickly — it does not
  wait for the loss window to wash out.
- **error** — `error after` consecutive losses (2 at the default)
- **warning** — packet loss over the last 8 probes ≥ the sensor's loss
  threshold (25% at the default). loss_warn is the sole warning gate: a
  flapping sensor stays in warning on every tick — including
  2-straight-good ticks — while its 8-probe loss is at/above the threshold,
  and reads up once the window loss falls back under it. A single loss
  below the threshold does not warn. (`spike_mult` never affects status: it
  only tints dashboard sparkline bars — see below.)

- **Sparkline spike tint:** each sensor's 1-hour sparkline colors bars
  **amber** at/above `spike_mult ×` that sensor's own window-average RTT
  (per-sensor, 2–10, default 5 — "Spike ×" in the sensor modal), so a 6 ms
  blip on a 2 ms LAN link is visible even though it's nowhere near the
  absolute thresholds. Bars above **200 ms** stay **red** regardless.
  Display-only: the probe engine and status derivation never read it.

- New sensors default to: interval 60s, timeout 1000ms, loss warn 25%,
  error after 2. New and cloned sensors start **paused** so a fresh
  target can't fire alerts before you review it — resume it from the dashboard.
- **Fast re-check in error:** while a sensor's status is error it is probed
  every **30s** instead of the configured interval, until a probe brings it
  back to up, then it reverts to the configured interval. If the sensor's
  interval is already shorter than 30s, the error state keeps the sensor's
  own pace (it never polls faster than normal), so a total outage with many
  sensors down is bounded to ~2× the normal probe load — no ping storms.
- Alerts fire on **error transitions**: up → error, warning → error, and
  recovery (→ up). **Warning transitions (up ↔ warning) never alert** — loss
  flapping is shown in the dashboard, not pushed to you.
- While a sensor stays in error it re-alerts at the configured
  interval; set the interval to **0** to alert exactly once per outage
  (one "error" alert; the "recovered" alert still fires when it comes back).
- Alerts fan out to **every enabled destination** with a configured URL
  (Google Chat and Discord). A fresh install has none configured — nothing
  sends until you add a URL in Settings.
- **Maintenance mode** (Settings) silences all alerts without stopping
  probes; re-alert timers reset when it's turned off.

## API

The dashboard is a single-page app driven by a small JSON API:

```
GET    /api/sensors                list sensors (with tags)
POST   /api/sensors                create
GET    /api/sensors/{id}           one sensor
PATCH  /api/sensors/{id}           update (name, target, tags, tuning, state)
DELETE /api/sensors/{id}           delete (purges history)
POST   /api/sensors/{id}/clone     duplicate
POST   /api/sensors/{id}/ping      probe now
GET    /api/sensors/{id}/history?range=1h|24h
GET    /api/sensors/{id}/graph?range=1h|24h
GET    /api/tags                   tag → sensor-count map
DELETE /api/tags?tag=X             remove tag from all sensors
GET    /api/events                 activity feed
DELETE /api/events                 clear activity feed
GET    /api/settings               webhook + alert settings
PUT    /api/settings               update
POST   /api/settings/test          send a test alert
POST   /api/settings/tls           install the dashboard TLS certificate (restarts)
DELETE /api/settings/tls           remove the dashboard TLS certificate (restarts)
GET    /api/auth/status            auth enabled? current session valid? + username
POST   /api/auth/login             {"username": "...", "password": "..."} → session cookie (30d)
POST   /api/auth/logout            end the current session
GET    /api/auth/users             list accounts (session)
POST   /api/auth/users             {"username","password"} create an account (session; open while auth is off — bootstrap)
POST   /api/auth/users/{u}/password  change the CALLER's own password (session)
DELETE /api/auth/users/{u}         delete an account; the last one is refused (session)
POST   /api/auth/disable           remove ALL accounts — turns auth off (session)
GET    /api/healthz                liveness (always open, even with auth on)
```

When authentication is enabled (at least one account exists), every `/api/*`
route requires a session cookie (or is one of the auth endpoints above) and
returns 401 without one; `/api/healthz` stays open so external monitors keep
working. Passwords are stored as bcrypt hashes; sessions are in-memory (a
restart clears them). A legacy single-token install migrates automatically on
first boot: the stored token becomes the password of an `admin` account.

## Building without Docker

```bash
go build -o pulsemon .
PULSEMON_DB=./data/pulsemon.db ./pulsemon
```

## Project layout

```
api.go      REST API + sensor CRUD + settings + auth gate
probe.go    probe worker, status derivation, alerting, webhooks
ping.go     ICMP ping (shared socket: unprivileged datagram socket, raw fallback; seq dispatch)
db.go       SQLite schema, migrations, seed
main.go     entrypoint, -healthz flag, CLI subcommands
listener.go HTTP/HTTPS listener + restart orchestration
tls_settings.go   dashboard TLS certificate install (validate + store + restart)
auth.go     dashboard authentication (username/password, sessions, gate middleware)
web/        single-page dashboard (no build step)
Dockerfile  golang:1.26-alpine → FROM scratch
compose.yaml
```
