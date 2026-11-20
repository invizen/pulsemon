#!/usr/bin/env bash
# pulsemon installer — bare / user-level systemd install (no Docker, no sudo).
#
#   ./install.sh              install latest release
#   ./install.sh v0.1.7       install a specific version
#
# What it does (all idempotent — safe to re-run, e.g. after an update):
#   1. Downloads the release binary and verifies its SHA-256 AND its
#      detached ed25519 release signature (manifest: tag + asset + digest,
#      keys from the repo's release_pubkeys — same contract as the updater)
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
# TMP and the EXIT trap are set up FIRST, and API_JSON lives UNDER TMP, so
# the trap removes it on every exit path. The old order created API_JSON
# with mktemp() before the trap existed and cleaned it up only inline — a
# grep/sed failure under set -e (no tag_name in a corrupt API response)
# leaked the temp file.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ "$VERSION" = "latest" ]; then
  # Fetch the JSON to a file BEFORE parsing: piping curl into `grep -m1`
  # is flaky under `set -o pipefail` — grep exits after the first match,
  # curl's next write gets SIGPIPE (exit 23), and the pipeline aborts.
  # How often it trips depends on whether the whole API response fits in
  # a single write before the pipe closes.
  API_JSON="$TMP/api.json"
  curl -sf --proto '=https' --tlsv1.2 "https://api.github.com/repos/$REPO/releases/latest" -o "$API_JSON" || {
    echo "pulsemon: could not reach the GitHub API (latest release lookup failed)" >&2
    exit 1; }
  VERSION="$(grep -m1 '"tag_name"' "$API_JSON" | sed 's/.*"tag_name": *"//;s/".*//')"
fi
[ -n "$VERSION" ] || { echo "pulsemon: could not resolve version" >&2; exit 1; }

# Validate the resolved version BEFORE it is interpolated into download
# URLs: a malformed or malicious tag (path traversal, spaces, a leading
# slash) would otherwise be planted into $BASE. Tags are vX.Y.Z with an
# optional -prerelease suffix.
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "pulsemon: invalid version '$VERSION' (expected vX.Y.Z) — refusing to install" >&2
  exit 1
fi

BASE="https://github.com/$REPO/releases/download/$VERSION"

curl -sfL --proto '=https' --tlsv1.2 -o "$TMP/$ASSET" "$BASE/$ASSET"
curl -sfL --proto '=https' --tlsv1.2 -o "$TMP/$ASSET.sha256" "$BASE/$ASSET.sha256" || {
  echo "pulsemon: release $VERSION has no published $ASSET.sha256 digest — refusing to install" >&2
  echo "        (an unverified binary is worse than no update; check github.com/$REPO/releases/$VERSION)" >&2
  exit 1; }
( cd "$TMP" && sha256sum -c "$ASSET.sha256" ) || {
  echo "pulsemon: SHA-256 verification FAILED — aborting" >&2; exit 1; }
echo "pulsemon: sha256 ok ($ASSET)"

# --- 1b. release signature (exact parity with the in-app updater) -------------
# The sidecar alone is NOT enough: the binary and its .sha256 come from the
# SAME release, so a compromised release pipeline can swap both together.
# The detached ed25519 .sig covers the manifest
# "pulsemon-release-v1\n<tag>\n<asset>\n<sha256>\n" and is made by the
# release-signing key, which lives OUTSIDE GitHub; the public keys live in
# the repo's release_pubkeys, one per line (rotation = add line, ship,
# retire later — any listed key verifying is accepted). This mirrors
# verifyReleaseSignature in update.go: fail closed on a missing .sig, a
# non-64-byte signature, an empty key set, or no key matching.
#
# Trust root: release_pubkeys is fetched from this repo's main branch over
# TLS — the same channel install.sh itself is fetched from, so a FULL
# account compromise defeats both (accepted: nothing install.sh ships with
# can survive that). What this closes is the case manifest signing exists
# for: compromised release/CI token WITHOUT a push to main — new binary +
# new sidecar, no signing key, refused here.
# PULSEMON_PUBKEYS_URL is a test hook (harness serves fixtures over
# file://); production installs always use the repo's main.
PUBKEYS_URL="${PULSEMON_PUBKEYS_URL:-https://raw.githubusercontent.com/$REPO/main/release_pubkeys}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "pulsemon: openssl not found — cannot verify the release signature; refusing to install unverified" >&2
  exit 1
fi

# hex2bin <hexfile> <outbin>: whitespace-tolerant hex decoder.
hex2bin() {
  if command -v xxd >/dev/null 2>&1; then
    xxd -r -p "$1" > "$2"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys,binascii;open(sys.argv[2],"wb").write(binascii.unhexlify("".join(open(sys.argv[1]).read().split())))' "$1" "$2"
  elif command -v perl >/dev/null 2>&1; then
    perl -pe 'BEGIN{binmode STDOUT} s/\s+//g; s/([0-9a-fA-F]{2})/chr hex $1/ge' "$1" > "$2"
  else
    echo "pulsemon: no hex decoder (xxd/python3/perl) — cannot verify the release signature" >&2
    return 1
  fi
}

curl -sfL -o "$TMP/release_pubkeys" "$PUBKEYS_URL" || {
  echo "pulsemon: could not fetch release_pubkeys from main — refusing to install an unverifiable binary" >&2
  exit 1; }
curl -sfL --proto '=https' --tlsv1.2 -o "$TMP/$ASSET.sig" "$BASE/$ASSET.sig" || {
  echo "pulsemon: release $VERSION has no published $ASSET.sig signature — refusing to install" >&2
  echo "        (the in-app updater requires it; a first install must not be weaker)" >&2
  exit 1; }

hex2bin "$TMP/$ASSET.sig" "$TMP/sig.bin" || exit 1
if [ "$(wc -c < "$TMP/sig.bin")" -ne 64 ]; then
  echo "pulsemon: $ASSET.sig is not a 64-byte ed25519 signature — refusing to install" >&2
  exit 1
fi

# Rebuild the manifest from the DOWNLOAD tag + asset + the digest of the
# bytes actually on disk (the sidecar check above proved the sidecar
# matches them; the signature below proves they are trusted for this tag).
sha256sum "$TMP/$ASSET" | cut -d' ' -f1 |
  { read -r bin_sha && printf 'pulsemon-release-v1\n%s\n%s\n%s\n' "$VERSION" "$ASSET" "$bin_sha"; } \
  > "$TMP/manifest"

SIG_OK=0
KEYS_SEEN=0
while read -r key _; do
  case "$key" in ''|'#'*) continue ;; esac
  case "$key" in *[!0-9a-fA-F]*) continue ;; esac
  [ "${#key}" -eq 64 ] || continue
  KEYS_SEEN=$((KEYS_SEEN+1))
  # SPKI/DER wrapper for ed25519 (302a300506032b6570032100 || key), built as
  # hex so hex2bin does the byte work (printf \x escapes are not POSIX).
  printf '302a300506032b6570032100%s\n' "$key" > "$TMP/pub.der.hex"
  hex2bin "$TMP/pub.der.hex" "$TMP/pub.der" || exit 1
  if openssl pkeyutl -verify -pubin -keyform DER -inkey "$TMP/pub.der" \
       -rawin -in "$TMP/manifest" -sigfile "$TMP/sig.bin" >/dev/null 2>&1; then
    SIG_OK=1
    break
  fi
done < "$TMP/release_pubkeys"

if [ "$KEYS_SEEN" -eq 0 ]; then
  echo "pulsemon: release_pubkeys lists no usable keys — refusing to install" >&2
  exit 1
fi
if [ "$SIG_OK" -ne 1 ]; then
  echo "pulsemon: release signature INVALID — $ASSET is not signed by a trusted" >&2
  echo "        release key for $VERSION. The binary is not installed." >&2
  echo "        If you are mid key-rotation, the key must be merged to main first." >&2
  exit 1
fi
echo "pulsemon: release signature ok ($VERSION / $ASSET)"

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
NoNewPrivileges=yes
# The self-update watchdog detaches into its own `systemd-run --scope`
# cgroup, but KillMode=process is the belt-and-suspenders: a
# stop/restart kills only the main process, so a watchdog that did not
# make it into a scope (no systemd-run) survives the restart it guards.
# pulsemon has no other long-lived children, so nothing leaks.
KillMode=process

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
  echo "pulsemon: fronting with a TLS-terminating reverse proxy (Caddy/nginx https->http)?"
  echo "       add PULSEMON_TRUSTED_PROXIES=<proxy-ip> or the dashboard 403s — README 'Behind a reverse proxy'"
else
  echo "pulsemon: warning: service started but http://$HOST:$PORT is not answering yet."
  echo "       Check: journalctl --user -u pulsemon"
fi
