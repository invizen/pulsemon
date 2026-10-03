# zenmon

A single-container ICMP network sensor monitor for your homelab. One Go binary,
one SQLite file, one dark dashboard — built to replace Uptime Kuma with
something that pings exactly what you care about and says nothing until
something changes.

```
zenmon = zen (your fleet) + mon (itor)
```

## Features

- **ICMP ping monitoring** — unprivileged (no `CAP_NET_RAW`, no root)
- **Single container** — static Go binary, `FROM scratch` image, SQLite storage
- **Sensors with multiple tags** — group and filter however you like
- **Per-sensor tuning** — interval, timeout, loss threshold, down-after count,
  latency-spike multiplier
- **Status derivation** — `up` / `degraded` / `down` from a 60-probe window
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

## Configuration

| Where | What |
|---|---|
| `.env` (or container env) | `GOOGLE_CHAT_WEBHOOK_URL` — default alert webhook |
| Dashboard → Settings | Webhook URL (overrides `.env`), alert routing, re-alert interval, maintenance mode, degraded-alert toggle |
| Per sensor | Interval, timeout, loss %, down-after, spike multiplier, tags |

### Alert behavior

- A sensor's status is derived from its last 60 probes:
  - **down** — N consecutive losses (per-sensor `down after`, default 2)
  - **degraded** — loss % above `loss warn`, or latest ping > `spike ×` the 60-probe average
  - **up** — everything else
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
ping.go     unprivileged ICMP (single shared socket, seq dispatch)
db.go       SQLite schema, migrations, seed
main.go     entrypoint, -healthz flag
web/        single-page dashboard (no build step)
Dockerfile  golang:1.26-alpine → FROM scratch
compose.yaml
```
