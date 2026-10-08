# Multi-arch: TARGETARCH is set by BuildKit (amd64/arm64/...) when built via
# `docker buildx build --platform` or plain `docker build` on a matching host.
# Plain `docker compose up -d --build` on an amd64 box builds an amd64 image;
# on a Jetson/Pi it builds an arm64 image — no cross-tooling needed because
# pulsemon is pure Go (CGO_ENABLED=0).
FROM golang:1.26-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Stamp the running version for the dashboard (healthz -> header badge).
# Read from the VERSION file that ships in the repo (kept in sync with the
# latest release tag); falls back to "dev" if the file is missing.
RUN V=$(cat VERSION 2>/dev/null | head -1 | tr -d '[:space:]'); \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w -X main.Version=${V:-dev}" -o pulsemon .

FROM scratch
# The binary is fully static (CGO_ENABLED=0, modernc.org/sqlite is pure Go):
# no dynamic loader or libc is needed, and the web UI is compiled in via
# go:embed, so there is nothing else to ship.
COPY --from=builder /app/pulsemon /pulsemon
COPY --from=alpine:latest /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
WORKDIR /
ENV PULSEMON_DB=/data/pulsemon.db
EXPOSE 9299
# Run unprivileged. The ICMP path uses the datagram ping socket, which is
# gated by the host's ping_group_range (no CAP_NET_RAW / root needed). The
# /data volume must be writable by uid 1000 (the SQLite WAL needs write
# access to the directory, not just the file):  chown -R 1000:1000 <data dir>.
USER 1000:1000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s CMD ["/pulsemon", "-healthz"]
ENTRYPOINT ["/pulsemon"]
