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
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.Version=${V:-dev}" -o zenmon .

FROM scratch
COPY --from=builder /app/zenmon /zenmon
COPY --from=builder /app/web /web
COPY --from=alpine:latest /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=alpine:latest /lib/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1
WORKDIR /
ENV ZENMON_DB=/data/zenmon.db
EXPOSE 9299
# Run unprivileged. The ICMP path uses the datagram ping socket, which is
# gated by the host's ping_group_range (no CAP_NET_RAW / root needed). The
# /data volume must be writable by uid 1000 (the SQLite WAL needs write
# access to the directory, not just the file):  chown -R 1000:1000 <data dir>.
USER 1000:1000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s CMD ["/zenmon", "-healthz"]
ENTRYPOINT ["/zenmon"]
