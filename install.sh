#!/usr/bin/env bash
# zenmon installer — bare / user-level systemd install (no Docker, no sudo).
#
#   ./install.sh              install latest release
#   ./install.sh v0.1.7       install a specific version
#
# What it does (all idempotent — safe to re-run, e.g. after an update):
#   1. Downloads the release binary and verifies its SHA-256
#   2. Installs it to ~/zenmon/zenmon
#   3. Installs ~/.config/systemd/user/zenmon.service (only if absent)
#   4. Adds ~/zenmon to PATH in ~/.bashrc (guarded, no duplicates)
#   5. Enables + starts the service; enables linger (sudo, optional)
#
# The Docker path does not need this script — see the README Quick start.
set -euo pipefail

REPO="invizen/zenmon"
PREFIX="${HOME}/zenmon"
BIN="$PREFIX/zenmon"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/zenmon.service"
VERSION="${1:-latest}"

if [ "$(id -u)" = "0" ]; then
  echo "zenmon: do not run as root — zenmon is designed to run unprivileged" >&2
  echo "       as the user it monitors (its uid must be inside ping_group_range)." >&2
  exit 1
fi

echo "zenmon: installing ${VERSION} for user '$USER'"
mkdir -p "$PREFIX" "$PREFIX/data"

# --- 1. download + verify -----------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -sf "https://api.github.com/repos/$REPO/releases/latest" | \
    grep -m1 '"tag_name"' | sed 's/.*"tag_name": *"//;s/".*//')"
fi
[ -n "$VERSION" ] || { echo "zenmon: could not resolve version" >&2; exit 1; }

BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -sfL -o "$TMP/zenmon-linux-amd64" "$BASE/zenmon-linux-amd64"
curl -sfL -o "$TMP/zenmon-linux-amd64.sha256" "$BASE/zenmon-linux-amd64.sha256" || {
  echo "zenmon: release $VERSION has no published sha256 digest — refusing to install" >&2
  echo "        (an unverified binary is worse than no update; check github.com/$REPO/releases/$VERSION)" >&2
  exit 1; }
( cd "$TMP" && sha256sum -c zenmon-linux-amd64.sha256 ) || {
  echo "zenmon: SHA-256 verification FAILED — aborting" >&2; exit 1; }
echo "zenmon: sha256 ok"

# --- 2. install binary --------------------------------------------------------
install -m 0755 "$TMP/zenmon-linux-amd64" "$BIN"
echo "zenmon: installed $BIN"

# --- 3. systemd user service (only if absent) ---------------------------------
if [ -f "$UNIT" ]; then
  echo "zenmon: $UNIT already present — leaving it alone"
else
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT" <<EOF
[Unit]
Description=zenmon network sensor monitor
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN
Environment=ZENMON_DB=$PREFIX/data/zenmon.db
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
  echo "zenmon: wrote $UNIT"
fi

# --- 4. PATH in ~/.bashrc (idempotent, guarded) --------------------------------
if grep -q 'zenmon: keep the zenmon binary on PATH' "$HOME/.bashrc" 2>/dev/null; then
  echo "zenmon: PATH already set in ~/.bashrc"
else
  {
    echo ""
    echo "# zenmon: keep the zenmon binary on PATH"
    echo "export PATH=\"$PREFIX:\$PATH\""
  } >> "$HOME/.bashrc"
  echo "zenmon: added $PREFIX to PATH in ~/.bashrc (open a new shell to pick it up)"
fi

# --- 5. enable + start + linger ------------------------------------------------
systemctl --user daemon-reload
systemctl --user enable zenmon >/dev/null
systemctl --user restart zenmon
sleep 1
if systemctl --user is-active --quiet zenmon; then
  echo "zenmon: service is running"
else
  echo "zenmon: service failed to start — check: journalctl --user -u zenmon" >&2
  exit 1
fi

# Linger so the service survives logout (needs sudo; optional, never fatal).
if loginctl show-user "$USER" 2>/dev/null | grep -q 'Linger=yes'; then
  echo "zenmon: linger already enabled"
elif sudo -n loginctl enable-linger "$USER" 2>/dev/null; then
  echo "zenmon: linger enabled"
else
  echo "zenmon: note: could not enable linger without a sudo password."
  echo "       Run 'sudo loginctl enable-linger $USER' so zenmon survives logout."
fi

# --- 6. health ----------------------------------------------------------------
sleep 3
if curl -sf localhost:8080/api/healthz >/dev/null 2>&1; then
  echo "zenmon: healthy — open http://localhost:8080"
else
  echo "zenmon: warning: service started but http://localhost:8080 is not answering yet."
  echo "       Check: journalctl --user -u zenmon"
fi
