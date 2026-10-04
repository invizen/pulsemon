# zenmon

A single-container ICMP network sensor monitor for your homelab. One Go binary,
one SQLite file, one dark dashboard — built to replace Uptime Kuma with
something that pings exactly what you care about and says nothing until
something changes.

```
zenmon = zen (your fleet) + mon (itor)
```

## Features

- **ICMP ping monitoring** — single shared ping socket with per-probe sequence
  dispatch (accurate RTTs even under load). See *ICMP & privileges* below for
  the access model.
- **Single container** — static Go binary, `FROM scratch` image, SQLite storage
- **Sensors with multiple tags** — group and filter however you like
- **Per-sensor tuning** — interval, timeout, loss threshold, down-after count,
  latency-spike multiplier
- **Status derivation** — `up` / `degraded` / `down` from the sensor's most
  recent probes (see *Alert behavior*)
- **1h / 24h latency graphs** with whole-ms display
- **Google Chat alerts** — state transitions + re-alerts, configurable
- **Alert controls** — routing (all / by tag / by sensor), re-alert interval
  (0 = alert once only), degraded-only mute, one-click **maintenance mode**
- **Dashboard** — card ⇄ table views, inspector with history, activity feed,
  optimized for 1080p and up

## Requirements

- Docker (with Compose v2)
- Port 8080 free on the host (change in `compose.yaml`)

## Quick start

```bash
git clone <your-repo-url> zenmon && cd zenmon
cp .env.example .env          # optional: put a Google Chat webhook URL in .env
chmod 600 .env
docker compose up -d --build
```

Open http://localhost:8080 and add sensors from the **new sensor** button.

> **First boot:** the database is created automatically on first run
> (`data/zenmon.db`). If you want seeded example sensors, see `db.go`
> (`seedSensors`) — it runs only on an empty database.

## ICMP & privileges

zenmon opens a single shared ICMP socket and dispatches replies by sequence
number (so RTTs stay accurate when many sensors probe at once). On Linux there
are two ways to send ICMP:

- **Raw socket** (`SOCK_RAW` + `IPPROTO_ICMP`) — what zenmon uses **today** via
  `icmp.ListenPacket("ip4:icmp", …)`. It requires the process to be **root or
  to hold `CAP_NET_RAW`**, regardless of `ping_group_range`.
- **Datagram ping socket** (`socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`) — the
  socket the `ping` binary uses when run by an ordinary user. It does **not**
  need root or `CAP_NET_RAW`; instead the process's uid must fall inside
  `net.ipv4.ping_group_range` (check with
  `sysctl net.ipv4.ping_group_range`). This is the *intended* unprivileged
  path and is the fix being prototyped for an upcoming release.

How that plays out right now:

| Deployment | Works today? | How |
|---|---|---|
| Docker (default image) | ✅ | Container runs as **root**, so the raw socket succeeds. |
| Bare / systemd as a normal user | ⚠️ only if privileged | Works only if the user has `CAP_NET_RAW` or the process runs as root; otherwise the datagram socket (upcoming) or a widened `ping_group_range` is required. |

> **Why not just `"udp4"`?** x/net/icmp's `ListenPacket("udp4", …)` is **not**
> an unprivileged ICMP socket — it creates a plain UDP socket and cannot send
> echo requests. The unprivileged path is the `SOCK_DGRAM`/`IPPROTO_ICMP`
> socket above.

## Configuration

| Where | What |
|---|---|
| `.env` (or container env) | `GOOGLE_CHAT_WEBHOOK_URL` — default alert webhook |
| Dashboard → Settings | Webhook URL (overrides `.env`), alert routing, re-alert interval, maintenance mode, degraded-alert toggle |
| Per sensor | Interval, timeout, loss %, down-after, spike multiplier, tags |

### Alert behavior

- A sensor's status is derived from its **last `down after` probes** (4 at the default), checked in this order:
  - **down** — `down after` consecutive losses from the newest probe
  - **up** — the newest 2 probes both succeeded (a brand-new sensor with 1 successful probe reads up)
  - **degraded** — anything in between: a loss is in the recent window, but it's neither fully down nor 2 clean in a row
- New sensors default to: interval 15s, timeout 1000ms, loss warn 25%, down after 4, spike 3×. New and cloned sensors start **paused** so a fresh target can't fire alerts before you review it — resume it from the dashboard.
- Alerts fire on every **state transition** (including recovery).
- While a sensor stays in a bad state it re-alerts at the configured
  interval; set the interval to **0** to alert exactly once.
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
ping.go     ICMP ping (single shared raw socket, seq dispatch)
db.go       SQLite schema, migrations, seed
main.go     entrypoint, -healthz flag
web/        single-page dashboard (no build step)
Dockerfile  golang:1.26-alpine → FROM scratch
compose.yaml
```
