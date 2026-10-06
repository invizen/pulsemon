# zenmon

A single-container ICMP network sensor monitor for your homelab. One Go binary,
one SQLite file, one dark dashboard — built to replace Uptime Kuma with
something that pings exactly what you care about and says nothing until
something changes.

```
zenmon
```

## Features

- **ICMP ping monitoring** — single shared ping socket with per-probe sequence
  dispatch (accurate RTTs even under load). See *ICMP & privileges* below for
  the access model.
- **Single container** — static Go binary, `FROM scratch` image, SQLite storage
- **Sensors with multiple tags** — group and filter however you like
- **Per-sensor tuning** — interval, timeout, loss threshold, error-after count,
  latency-spike multiplier (informational)
- **Status derivation** — `up` / `warning` / `error` from the sensor's most
  recent probes (see *Alert behavior*)
- **1h / 24h latency graphs** with whole-ms display
- **Alerts** — Google Chat + Discord, fan-out to every enabled destination,
  re-alerts, one-click test from Settings
- **Alert controls** — routing (all / by tag / by sensor), re-alert interval
  (0 = alert once only), one-click **maintenance mode**
- **Dashboard** — card ⇄ table views, inspector with history, activity feed,
  optimized for 1080p and up

## Requirements

- Docker (with Compose v2)
- Port 9299 free on the host (change in `compose.yaml`, or set `ZENMON_ADDR`)

## Quick start

```bash
git clone https://github.com/invizen/zenmon zenmon && cd zenmon
cp .env.example .env          # optional: put a Google Chat webhook URL in .env
chmod 600 .env
mkdir -p data && chmod 0777 data  # pre-create the data dir (see note below)
docker compose up -d --build
```

Open http://localhost:9299 and add sensors from the **new sensor** button.

> **First boot:** the database is created automatically on first run
> (`data/zenmon.db`). Two demo sensors (`router`, `server`) are seeded
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
curl -sfL https://github.com/invizen/zenmon/releases/latest/download/install.sh -o /tmp/zenmon-install.sh
bash /tmp/zenmon-install.sh              # latest release, or: bash /tmp/zenmon-install.sh v0.1.7
```

The installer (no sudo required) downloads and **SHA-256-verifies** the
release binary, installs it to `~/zenmon/`, writes a user-level
`zenmon.service` (pointing at `~/zenmon/data/zenmon.db` via `ZENMON_DB`),
adds `~/zenmon` to `PATH` in `~/.bashrc` (guarded — re-running never
duplicates the line), and enables + starts the service. It tries
`sudo -n loginctl enable-linger` so zenmon keeps running after you log out;
if that needs a password it tells you the one command to run.

```bash
zenmon update            # self-update from any directory (v0.1.6+)
zenmon update --restart  # install AND restart the running service, then verify healthz
zenmon update check      # check only — exit 2 when a newer release exists
zenmon update v0.1.7     # pin or roll back to a specific version
```

`zenmon update` finds the running binary itself (`os.Executable`), verifies
the published SHA-256, and swaps it atomically — then prints the restart
command. After it runs: `systemctl --user restart zenmon`.
`--restart` does that for you: it auto-restarts only when a live systemd
`zenmon` service is confidently detected (user bus, or system bus when
running as root), then polls healthz and reports the outcome — so a
container or non-systemd host still just gets the restart hint (a bad new
version would otherwise take the monitor down).

## ICMP & privileges

zenmon opens a single shared ICMP socket and dispatches replies by sequence
number (so RTTs stay accurate when many sensors probe at once). On Linux there
are two ways to send ICMP, and zenmon tries them in order at startup:

1. **Datagram ping socket** (`socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`) —
   preferred. This is the socket the `ping` binary uses as an ordinary user.
   It needs **no root and no `CAP_NET_RAW`**; instead the process's uid must
   fall inside `net.ipv4.ping_group_range` (check with
   `sysctl net.ipv4.ping_group_range`). On Linux the kernel overwrites the
   ICMP identifier with a per-socket value and delivers only that socket's
   replies, so zenmon dispatches by sequence + source IP on this path.
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
| env | `ZENMON_ADDR` — HTTP listen address, full `host:port` (e.g. `:9299`, `127.0.0.1:9299`). Default `:9299` (all interfaces). 8080 was the pre-0.1.19 default; 9299 avoids the dashboards/proxies that usually claim it. |
| Dashboard → Settings | Alert destinations (Google Chat, Discord — each with its own URL and toggle), alert routing, re-alert interval, maintenance mode |
| Per sensor | Interval, timeout, loss %, error-after, spike multiplier (informational), tags |

### Alert behavior

Statuses are `up`, `warning`, and `error`. A sensor's status is derived from
its most recent probes, checked in this order:

- **up** — the last 2 probes both succeeded (a brand-new sensor with 1
  successful probe reads up). Checked first, so a sensor recovering from a
  long outage flips back to up on its 2nd good reply — it does not wait for
  the loss window to wash out.
- **error** — `error after` consecutive losses (4 at the default)
- **warning** — packet loss over the last 8 probes ≥ the sensor's loss
  threshold (25% at the default) — or any recent loss that is not up and
  not error. The spike multiplier is **informational** — shown in the
  dashboard, but it never changes status.

- New sensors default to: interval 15s, timeout 1000ms, loss warn 25%,
  error after 4, spike 3×. New and cloned sensors start **paused** so a fresh
  target can't fire alerts before you review it — resume it from the dashboard.
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
GET    /api/healthz                liveness
```

## Building without Docker

```bash
go build -o zenmon .
ZENMON_DB=./data/zenmon.db ./zenmon
```

## Project layout

```
api.go      REST API + sensor CRUD + settings
probe.go    probe worker, status derivation, alerting, webhooks
ping.go     ICMP ping (shared socket: unprivileged datagram socket, raw fallback; seq dispatch)
db.go       SQLite schema, migrations, seed
main.go     entrypoint, -healthz flag
web/        single-page dashboard (no build step)
Dockerfile  golang:1.26-alpine → FROM scratch
compose.yaml
```
