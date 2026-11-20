# Multi-arch: TARGETARCH is set by BuildKit (amd64/arm64/...) when built via
# `docker buildx build --platform` or plain `docker build` on a matching host.
# Plain `docker compose up -d --build` on an amd64 box builds an amd64 image;
# on a Jetson/Pi it builds an arm64 image — no cross-tooling needed because
# pulsemon is pure Go (CGO_ENABLED=0).
# Go pin MUST track go.mod's `toolchain` line (today go1.27.4) EXACTLY, and
# CI pins the same version: a family pin here is a fourth place the toolchain
# can drift behind a Go security release, and GOTOOLCHAIN=auto inside the
# builder silently downloads a second toolchain per image build. Bump all four
# (go.mod toolchain, this FROM, ci.yml, windows-release.yml) together.
FROM golang:1.27.4-alpine AS builder
# WITHOUT this ARG declaration, BuildKit leaves
# ${TARGETARCH} EMPTY even for `docker buildx build --platform linux/arm64`,
# so the `:-amd64` fallback silently shipped an AMD64 binary in an arm64
# image (verified empirically). Declaring the ARG makes BuildKit populate it
# from the requested platform.
ARG TARGETARCH
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
# CA bundle comes from the BUILDER stage (golang:1.27.4-alpine), not from a
# separate alpine:3.20 pull: the pinned 3.20 tag is EOL (no more security
# updates to its ca-certificates), and a second image pull is an extra
# supply-chain surface that can drift / be tampered with. The builder is
# Alpine-based and already carries /etc/ssl/certs/ca-certificates.crt.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
WORKDIR /
ENV PULSEMON_DB=/data/pulsemon.db
EXPOSE 9299
# Run unprivileged. The ICMP path uses the datagram ping socket, which is
# gated by the host's ping_group_range (no CAP_NET_RAW / root needed). The
# /data volume must be writable by uid 1000 (the SQLite WAL needs write
# access to the directory, not just the file):  chown -R 1000:1000 <data dir>.
#
# NO /tmp and a non-writable / : anything that needs a temp file must use
# memory, which the store's DSN enforces with temp_store(MEMORY)
# (internal/store/store.go → dsnWithPragmas). Without it, a query that
# spills a temp B-tree (a big sort, a materialized CTE) fails with
# SQLITE_CANTOPEN. Do not "simplify" this image back to an alpine base
# without re-checking that pragma.
USER 1000:1000
# -healthz-http verifies the RUNNING server answers
# /api/healthz, not just that the store opens (a wedged listener would
# otherwise read "healthy" to the container runtime).
HEALTHCHECK --interval=30s --timeout=8s --retries=3 --start-period=10s CMD ["/pulsemon", "-healthz-http"]
ENTRYPOINT ["/pulsemon"]
