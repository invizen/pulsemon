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
# L2 (2026-10-19 review F21): pin the vuln scanner. @latest silently changes
# the tool (and its database) between runs, so two "identical" release runs
# can disagree; a pinned version makes the gate reproducible. Bump this
# deliberately, not as a drive-by.
GOVULNCHECK="${GOVULNCHECK:-v1.1.0}"

echo "pulsemon: releasing $VERSION (publish=$PUBLISH)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p dist

# --- 0. pre-build gates: clean tree + passing tests --------------------------
# L1 (2026-10-19 review F21): never ship from a dirty tree (uncommitted work
# would land in the binary but not the tag) and never ship a build whose
# tests fail. -count=1 defeats the test cache so the suite actually runs.
if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
  echo "release.sh: working tree is not clean — commit or stash first:"
  git status --porcelain
  exit 1
fi
echo "pulsemon: go test -count=1 . (release fails on any failure) ..."
go test -count=1 . || { echo "release.sh: tests failed — release aborted"; exit 1; }

# --- 0b. vulnerability gate: fail the release on reachable vulns --------------
# govulncheck scans the module graph and flags vulnerabilities that are
# actually REACHABLE from our code (its exit code 2), so a new CVE in a
# dependency aborts the release before a single binary is built. Set
# SKIP_VULNCHECK=1 to bypass (e.g. an offline run); the gate is on by
# default.
if [[ "${SKIP_VULNCHECK:-}" == "1" ]]; then
  echo "pulsemon: SKIP_VULNCHECK=1 — skipping govulncheck"
else
  echo "pulsemon: govulncheck $GOVULNCHECK (release fails on reachable vulnerabilities) ..."
  go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK" ./... \
    || { echo "release.sh: govulncheck reported reachable vulnerabilities (or failed) — release aborted"; exit 1; }
fi

# --- 1. build both architectures ---------------------------------------------
for ARCH in amd64 arm64; do
  OUT="dist/pulsemon-linux-$ARCH"
  echo "pulsemon: building linux/$ARCH ..."
  CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
    go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" -o "$OUT" .
  file "$OUT" | grep -q "ARM aarch64\|x86-64" || { echo "release.sh: bad ELF for $ARCH"; exit 1; }
  ( cd "dist" && sha256sum "pulsemon-linux-$ARCH" > "pulsemon-linux-$ARCH.sha256" )
done

# --- 1b. sign each binary (release AUTHENTICITY) ----------------------------
# The .sig is a detached ed25519 signature over the binary's exact bytes. At
# update time the client verifies it against the embedded release_pubkeys —
# the authenticity root the SHA-256 (integrity) cannot provide: a compromised
# pipeline can publish a binary + its SHA, but not a valid signature.
#
# The private key is the release-signing secret, provided via
# RELEASE_SIGNING_KEY_FILE (a file holding the 64-byte hex key, 600 perms).
# The release FAILS if the key is missing, signing fails, or the signature
# does not verify against the embedded release_pubkeys — an unsigned release
# must never be published (the client refuses to install it).
SIGN_KEY="${RELEASE_SIGNING_KEY_FILE:-$HOME/.config/pulsemon/release-signing-key.hex}"
if [[ ! -f "$SIGN_KEY" ]]; then
  echo "release.sh: signing key not found: $SIGN_KEY"
  echo "  generate one:  dist/pulsemon-linux-amd64 sign genkey"
  echo "  (set RELEASE_SIGNING_KEY_FILE to the hex private key file)"
  exit 1
fi
SIGNER="dist/pulsemon-linux-amd64"   # runs natively on the amd64 release host
for ARCH in amd64 arm64; do
  BIN="dist/pulsemon-linux-$ARCH"
  "$SIGNER" sign release "$BIN" "$SIGN_KEY" >/dev/null \
    || { echo "release.sh: signing failed for $BIN"; exit 1; }
  # Verify against the EMBEDDED release_pubkeys (the keys a client checks):
  # catches a release cut with the wrong signing key before it ships.
  "$SIGNER" sign verify "$BIN" >/dev/null \
    || { echo "release.sh: signature does not verify against release_pubkeys for $BIN"; exit 1; }
  [[ -f "$BIN.sig" ]] || { echo "release.sh: no .sig produced for $BIN"; exit 1; }
  echo "  signed $BIN"
done

# --- 2. verify: the built binaries must satisfy the update verifier -----------
# Re-check each binary against its own sidecar the way runUpdate/install.sh do.
for ARCH in amd64 arm64; do
  ( cd "dist" && sha256sum -c "pulsemon-linux-$ARCH.sha256" ) >/dev/null \
    || { echo "release.sh: sidecar verification failed for $ARCH"; exit 1; }
done
# And the version stamp actually landed.
# L3 (2026-10-19 review F21): run the NATIVE binary's -version and check the
# exact stamp. (`go version -m` was the original approach, but Go does NOT
# record -X ldflag values in the embedded build info — it only shows module
# and compiler settings — so it can never see main.Version. Running the
# binary is the only reliable check.) The release is built on an amd64 host,
# so the amd64 binary is executable here; the arm64 build uses the identical
# -ldflags line, so a correct amd64 stamp implies a correct arm64 stamp.
# -version works without a data dir (ensureDataDir runs in the server path,
# not at process start), so this check is safe on any build host.
dist/pulsemon-linux-amd64 -version 2>&1 | grep -qF "pulsemon $VERSION" \
  || { echo "release.sh: version stamp $VERSION not found in linux/amd64 binary (-version)"; exit 1; }

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

# --- 3. tag (LOCAL only) --------------------------------------------------------
# L4 (2026-10-19 review F21): the tag is created locally but NOT pushed yet —
# the push is the very last step, after the release exists.
git tag -a "$VERSION" -m "pulsemon $VERSION"

# --- 4. publish the release ----------------------------------------------------
gh release create "$VERSION" \
  --title "pulsemon $VERSION" \
  --notes-file RELEASE_NOTES.md \
  dist/pulsemon-linux-amd64 \
  dist/pulsemon-linux-amd64.sha256 \
  dist/pulsemon-linux-amd64.sig \
  dist/pulsemon-linux-arm64 \
  dist/pulsemon-linux-arm64.sha256 \
  dist/pulsemon-linux-arm64.sig \
  install.sh

# --- 5. push the tag LAST -------------------------------------------------------
# The tag push triggers the Windows release workflow. It must run AFTER the
# GitHub release exists: if the tag went out first, the workflow would build
# the Windows assets against a release that has no assets yet, and a
# self-updating client polling in that window finds nothing.
git push origin "$VERSION"

echo
echo "pulsemon: $VERSION published with both arches + installer."
echo "       verify:  gh release view $VERSION"
echo "       smoke:   curl -sfL <release>/install.sh | bash   (on an $ARCH host)"
