#!/usr/bin/env bash
# pulsemon release — build both arches, tag, and publish a GitHub release.
#
#   ./release.sh              dry run: build amd64+arm64, verify, show the plan
#   ./release.sh --publish    do it: also bump tag and publish the release
#
# Must run where Go is available AND where gh is authenticated for
# github.com/invizen/pulsemon. (zenai has gh but no Go; the script cross-
# compiles fine on a single arch host — CGO_ENABLED=0 means no toolchains.)
#
# Release layout (one asset per arch, matching targetAsset() in update.go):
#   pulsemon-linux-amd64          static binary, stripped, version-stamped
#   pulsemon-linux-amd64.sha256   "<hex>  <name>" (sha256sum format)
#   pulsemon-linux-arm64          static binary, stripped, version-stamped
#   pulsemon-linux-arm64.sha256   "<hex>  <name>"
#   install.sh                  arch-aware installer (shipped as an asset too)
set -euo pipefail
cd "$(dirname "$0")"

VERSION="$(tr -d '[:space:]' < VERSION)"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release.sh: VERSION file is not vN.N.N: '$VERSION'"; exit 1; }
PUBLISH=0
[[ "${1:-}" == "--publish" ]] && PUBLISH=1

echo "pulsemon: releasing $VERSION (publish=$PUBLISH)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p dist

# --- 1. build both architectures ---------------------------------------------
for ARCH in amd64 arm64; do
  OUT="dist/pulsemon-linux-$ARCH"
  echo "pulsemon: building linux/$ARCH ..."
  CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
    go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" -o "$OUT" .
  file "$OUT" | grep -q "ARM aarch64\|x86-64" || { echo "release.sh: bad ELF for $ARCH"; exit 1; }
  ( cd "dist" && sha256sum "pulsemon-linux-$ARCH" > "pulsemon-linux-$ARCH.sha256" )
done

# --- 2. verify: the built binaries must satisfy the update verifier -----------
# Re-check each binary against its own sidecar the way runUpdate/install.sh do.
for ARCH in amd64 arm64; do
  ( cd "dist" && sha256sum -c "pulsemon-linux-$ARCH.sha256" ) >/dev/null \
    || { echo "release.sh: sidecar verification failed for $ARCH"; exit 1; }
done
# And the version stamp actually landed.
for ARCH in amd64 arm64; do
  # The binary cannot run on the wrong arch; check the stamp in the binary
  # itself (main.Version is a string constant baked into the binary).
  grep -q "pulsemon: $VERSION" "dist/pulsemon-linux-$ARCH" \
    || grep -q "$VERSION" "dist/pulsemon-linux-$ARCH" \
    || { echo "release.sh: version stamp $VERSION not found in linux/$ARCH binary"; exit 1; }
done

echo
echo "=== assets ready ==="
for f in dist/pulsemon-linux-*; do
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
git tag -a "$VERSION" -m "pulsemon $VERSION"
git push origin "$VERSION"

# --- 4. publish the release ----------------------------------------------------
gh release create "$VERSION" \
  --title "pulsemon $VERSION" \
  --notes-file RELEASE_NOTES.md \
  dist/pulsemon-linux-amd64 \
  dist/pulsemon-linux-amd64.sha256 \
  dist/pulsemon-linux-arm64 \
  dist/pulsemon-linux-arm64.sha256 \
  install.sh

echo
echo "pulsemon: $VERSION published with both arches + installer."
echo "       verify:  gh release view $VERSION"
echo "       smoke:   curl -sfL <release>/install.sh | bash   (on an $ARCH host)"
