#!/usr/bin/env bash
# zenmon release — build both arches, tag, and publish a GitHub release.
#
#   ./release.sh              dry run: build amd64+arm64, verify, show the plan
#   ./release.sh --publish    do it: also bump tag and publish the release
#
# Must run where Go is available AND where gh is authenticated for
# github.com/invizen/zenmon. (zenai has gh but no Go; the script cross-
# compiles fine on a single arch host — CGO_ENABLED=0 means no toolchains.)
#
# Release layout (one asset per arch, matching targetAsset() in update.go):
#   zenmon-linux-amd64          static binary, stripped, version-stamped
#   zenmon-linux-amd64.sha256   "<hex>  <name>" (sha256sum format)
#   zenmon-linux-arm64          static binary, stripped, version-stamped
#   zenmon-linux-arm64.sha256   "<hex>  <name>"
#   install.sh                  arch-aware installer (shipped as an asset too)
set -euo pipefail
cd "$(dirname "$0")"

VERSION="$(tr -d '[:space:]' < VERSION)"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release.sh: VERSION file is not vN.N.N: '$VERSION'"; exit 1; }
PUBLISH=0
[[ "${1:-}" == "--publish" ]] && PUBLISH=1

echo "zenmon: releasing $VERSION (publish=$PUBLISH)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- 1. build both architectures ---------------------------------------------
for ARCH in amd64 arm64; do
  OUT="$TMP/zenmon-linux-$ARCH"
  echo "zenmon: building linux/$ARCH ..."
  CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
    go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" -o "$OUT" .
  file "$OUT" | grep -q "ARM aarch64\|x86-64" || { echo "release.sh: bad ELF for $ARCH"; exit 1; }
  ( cd "$TMP" && sha256sum "zenmon-linux-$ARCH" > "zenmon-linux-$ARCH.sha256" )
done

# --- 2. verify: the built binaries must satisfy the update verifier -----------
# Re-check each binary against its own sidecar the way runUpdate/install.sh do.
for ARCH in amd64 arm64; do
  ( cd "$TMP" && sha256sum -c "zenmon-linux-$ARCH.sha256" ) >/dev/null \
    || { echo "release.sh: sidecar verification failed for $ARCH"; exit 1; }
done
# And the version stamp actually landed.
for ARCH in amd64 arm64; do
  # The binary cannot run on the wrong arch; check the stamp in the binary
  # itself (main.Version is a string constant baked into the binary).
  grep -q "zenmon: $VERSION" "$TMP/zenmon-linux-$ARCH" \
    || grep -q "$VERSION" "$TMP/zenmon-linux-$ARCH" \
    || { echo "release.sh: version stamp $VERSION not found in linux/$ARCH binary"; exit 1; }
done

echo
echo "=== assets ready ==="
for f in "$TMP"/zenmon-linux-*; do
  echo "  $(basename "$f")  $(sha256sum "$f" | cut -c1-16)…  $(du -h "$f" | cut -f1)"
done
echo "  install.sh  (from repo, $(sha256sum install.sh | cut -c1-16)…)"

if [[ $PUBLISH -eq 0 ]]; then
  cat <<EOF

dry run complete — no tag created, nothing published.
to publish:  ./release.sh --publish
EOF
  exit 0
fi

# --- 3. tag + push -------------------------------------------------------------
git tag -a "$VERSION" -m "zenmon $VERSION"
git push origin "$VERSION"

# --- 4. publish the release ----------------------------------------------------
gh release create "$VERSION" \
  --title "zenmon $VERSION" \
  --notes-file RELEASE_NOTES.md \
  "$TMP"/zenmon-linux-amd64 \
  "$TMP"/zenmon-linux-amd64.sha256 \
  "$TMP"/zenmon-linux-arm64 \
  "$TMP"/zenmon-linux-arm64.sha256 \
  install.sh

echo
echo "zenmon: $VERSION published with both arches + installer."
echo "       verify:  gh release view $VERSION"
echo "       smoke:   curl -sfL <release>/install.sh | bash   (on an $ARCH host)"
