#!/usr/bin/env bash
# pulsemon installer — bare / user-level systemd install (no Docker, no sudo).
#
#   ./install.sh              install latest release
#   ./install.sh v0.1.7       install a specific version
#
# What it does (all idempotent — safe to re-run, e.g. after an update):
#   1. Downloads the release binary and verifies its SHA-256
#   2. Installs it to ~/pulsemon/pulsemon
#   3. Installs ~/.config/systemd/user/pulsemon.service (only if absent)
#   4. Adds ~/pulsemon to PATH in ~/.bashrc (guarded, no duplicates)
#   5. Enables + starts the service; enables linger (sudo, optional)
#
# The Docker path does not need this script — see the README Quick start.
set -euo pipefail

REPO="invizen/pulsemon"
PREFIX="${HOME}/pulsemon"
BIN="$PREFIX/pulsemon"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/pulsemon.service"
VERSION="${1:-latest}"
# PULSEMON_ADDR is a full "host:port" (e.g. ":9299", "127.0.0.1:9299"). The
# default matches the binary's own default (all interfaces on 9299).
PULSEMON_ADDR="${PULSEMON_ADDR:-:9299}"

# Map the host's machine type to the release asset's Go arch name, so the
# installer grabs the binary built for THIS machine instead of hardcoding
# amd64 (a Pi / Jetson / Apple-Silicon box would otherwise get x86_64).
case "$(uname -m)" in
  x86_64|amd64)   GOARCH="amd64" ;;
  aarch64|arm64)  GOARCH="arm64" ;;
  *)
    echo "pulsemon: unsupported architecture '$(uname -m)' — expected x86_64 or aarch64/arm64" >&2
    exit 1 ;;
esac
ASSET="pulsemon-linux-${GOARCH}"

if [ "$(id -u)" = "0" ]; then
  echo "pulsemon: do not run as root — pulsemon is designed to run unprivileged" >&2
  echo "       as the user it monitors (its uid must be inside ping_group_range)." >&2
  exit 1
fi

# --- preflight: ICMP socket availability ------------------------------------
# pulsemon's unprivileged ICMP path needs THIS user's gid inside
# net.ipv4.ping_group_range; otherwise it falls back to the raw socket, which
# needs CAP_NET_RAW. The kernel default is "1 0" (nobody); systemd >= 244
# (RHEL 9+, Fedora, Ubuntu/Debian) ships it wide via /usr/lib/sysctl.d/
# 50-default.conf, but RHEL 8 (systemd 239) does NOT. Check now, so the
# install fails loudly instead of the service running with silent no-pings.
PGG="$(sysctl -n net.ipv4.ping_group_range 2>/dev/null | tr '\t' ' ')"
if [ -n "$PGG" ]; then
  PGG_LO="$(echo "$PGG" | awk '{print $1}')"
  PGG_HI="$(echo "$PGG" | awk '{print $2}')"
  GID="$(id -g)"
  if [ "$GID" -ge "$PGG_LO" ] && [ "$GID" -le "$PGG_HI" ]; then
    echo "pulsemon: preflight ok — gid $GID is inside ping_group_range $PGG (unprivileged ICMP works)"
  else
    echo "pulsemon: preflight WARNING — this user's gid $GID is OUTSIDE net.ipv4.ping_group_range ($PGG)."
    echo "        The unprivileged ICMP socket will fail; pulsemon will fall back to the raw"
    echo "        socket, which needs CAP_NET_RAW (not granted by default for user services)."
    echo "        Until fixed, pulsemon will run but send NO pings and the dashboard will show"
    echo "        an 'ICMP unavailable' banner (healthz: status=degraded, icmp_mode=unavailable)."
    echo ""
    echo "        Fix now (needs sudo):"
    echo "          sudo sysctl -w net.ipv4.ping_group_range=\"0 65535\""
    echo "          echo 'net.ipv4.ping_group_range=0 65535' | sudo tee /etc/sysctl.d/90-pulsemon-ping.conf"
    echo "        Then re-run this installer."
    echo ""
    if [ -t 0 ]; then
      read -r -p "pulsemon: continue installing anyway? [y/N] " ans
      case "$ans" in
        y|Y|yes|YES) ;;
        *) echo "pulsemon: aborting — set ping_group_range first (see above)."; exit 1 ;;
      esac
    else
      echo "pulsemon: no interactive terminal — continuing (the dashboard banner will flag it)."
    fi
  fi
else
  echo "pulsemon: preflight: could not read net.ipv4.ping_group_range (sysctl missing?)."
fi

echo "pulsemon: installing ${VERSION} for user '$USER'"
mkdir -p "$PREFIX" "$PREFIX/data"

# --- 1. download + verify -----------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -sf "https://api.github.com/repos/$REPO/releases/latest" | \
    grep -m1 '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//')"
fi
[ -n "$VERSION" ] || { echo "pulsemon: could not resolve version" >&2; exit 1; }

BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -sfL -o "$TMP/$ASSET" "$BASE/$ASSET"
curl -sfL -o "$TMP/$ASSET.sha256" "$BASE/$ASSET.sha256" || {
  echo "pulsemon: release $VERSION has no published $ASSET.sha256 digest — refusing to install" >&2
  echo "        (an unverified binary is worse than no update; check github.com/$REPO/releases/$VERSION)" >&2
  exit 1; }
( cd "$TMP" && sha256sum -c "$ASSET.sha256" ) || {
  echo "pulsemon: SHA-256 verification FAILED — aborting" >&2; exit 1; }
echo "pulsemon: sha256 ok ($ASSET)"

# --- 2. install binary --------------------------------------------------------
install -m 0755 "$TMP/$ASSET" "$BIN"
echo "pulsemon: installed $BIN"

# --- 3. systemd user service (only if absent) ---------------------------------
if [ -f "$UNIT" ]; then
  echo "pulsemon: $UNIT already present — leaving it alone"
else
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT" <<EOF
[Unit]
Description=pulsemon network sensor monitor
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN
Environment=PULSEMON_DB=$PREFIX/data/pulsemon.db
Environment=PULSEMON_ADDR=$PULSEMON_ADDR
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
  echo "pulsemon: wrote $UNIT"
fi

# --- 4. PATH in ~/.bashrc (idempotent, guarded) --------------------------------
if grep -q 'pulsemon: keep the pulsemon binary on PATH' "$HOME/.bashrc" 2>/dev/null; then
  echo "pulsemon: PATH already set in ~/.bashrc"
else
  {
    echo ""
    echo "# pulsemon: keep the pulsemon binary on PATH"
    echo "export PATH=\"$PREFIX:\$PATH\""
  } >> "$HOME/.bashrc"
  echo "pulsemon: added $PREFIX to PATH in ~/.bashrc (open a new shell to pick it up)"
fi

# --- 5. enable + start + linger ------------------------------------------------
systemctl --user daemon-reload
systemctl --user enable pulsemon >/dev/null
systemctl --user restart pulsemon
sleep 1
if systemctl --user is-active --quiet pulsemon; then
  echo "pulsemon: service is running"
else
  echo "pulsemon: service failed to start — check: journalctl --user -u pulsemon" >&2
  exit 1
fi

# Linger so the service survives logout (needs sudo; optional, never fatal).
if loginctl show-user "$USER" 2>/dev/null | grep -q 'Linger=yes'; then
  echo "pulsemon: linger already enabled"
elif sudo -n loginctl enable-linger "$USER" 2>/dev/null; then
  echo "pulsemon: linger enabled"
else
  echo "pulsemon: note: could not enable linger without a sudo password."
  echo "       Run 'sudo loginctl enable-linger $USER' so pulsemon survives logout."
fi

# --- 6. health ----------------------------------------------------------------
sleep 3
# Derive the host:port to healthcheck from PULSEMON_ADDR:
#   ":9299"          -> localhost:9299  (all-interface bind)
#   "127.0.0.1:9299" -> 127.0.0.1:9299
#   "9299" (bare)    -> localhost:9299
case "$PULSEMON_ADDR" in
  :*)  HOST="localhost" ;;
  *:*) HOST="${PULSEMON_ADDR%:*}" ;;
  *)   HOST="localhost"; PULSEMON_ADDR=":$PULSEMON_ADDR" ;;
esac
PORT="${PULSEMON_ADDR##*:}"
if curl -sf "http://$HOST:$PORT/api/healthz" >/dev/null 2>&1; then
  echo "pulsemon: healthy — open http://$HOST:$PORT"
else
  echo "pulsemon: warning: service started but http://$HOST:$PORT is not answering yet."
  echo "       Check: journalctl --user -u pulsemon"
fi
