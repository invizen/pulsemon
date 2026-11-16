#!/usr/bin/env bash
# m4 harness v2: run install.sh's release-signature block (extracted
# verbatim) against signed fixtures. Each case gets its OWN serve dir
# (binary + chosen .sig) and pubkeys file — every refusal path asserted
# independently (v1 shared fx/ as BASE, so the good .sig leaked into
# every case).
set -uo pipefail
cd "$(dirname "$0")"; FX="$PWD/fx"

PM="${PM:-./pm}"
rm -rf "$FX"; mkdir -p "$FX"

$PM sign genkey > "$FX/key1"
$PM sign genkey > "$FX/key2"
PUB1=$(grep PUBKEY "$FX/key1" | cut -d= -f2)
PRIV1=$(grep PRIVKEY "$FX/key1" | cut -d= -f2)
PUB2=$(grep PUBKEY "$FX/key2" | cut -d= -f2)
echo "$PRIV1" > "$FX/priv1.hex"

ASSET=pulsemon-linux-amd64
head -c 4096 /dev/urandom > "$FX/$ASSET"
cp "$FX/$ASSET" "$FX/$ASSET.orig"
$PM sign release "$FX/$ASSET" "$FX/priv1.hex" v9.9.9 "$ASSET" >/dev/null
cp "$FX/$ASSET.sig" "$FX/$ASSET.sig.good"
$PM sign release "$FX/$ASSET" "$FX/priv1.hex" v9.9.8 "$ASSET" >/dev/null
mv "$FX/$ASSET.sig" "$FX/$ASSET.sig.oldtag"
rm -f "$FX/$ASSET.sig"                      # fx/ keeps NO default .sig
head -c 100 "$FX/$ASSET.sig.good" > "$FX/$ASSET.sig.short"
cp "$FX/$ASSET" "$FX/$ASSET.tampered"; printf 'evil' >> "$FX/$ASSET.tampered"

cat > "$FX/pubkeys" <<EOF
# fixture keys
$PUB1
EOF
cat > "$FX/pubkeys-unknown" <<EOF
# fixture keys
$PUB2
EOF
cat > "$FX/pubkeys-empty" <<EOF
# only comments
EOF

sed -n '/^# --- 1b\./,/^# --- 2\. install binary/p' install.sh | sed '$d' > "$FX/verify.inc"
[ "$(grep -c 'SIG_OK' "$FX/verify.inc")" -ge 2 ] || { echo "HARNESS: extraction failed"; exit 1; }

FAILED=0
run() { # name expect sig|NONE keys|NONE tag binary
  local name=$1 expect=$2 sig=$3 keys=$4 tag=$5 bin=$6 rc
  local t serve; t=$(mktemp -d); serve="$t/serve"; mkdir -p "$serve"
  cp "$FX/$bin" "$serve/$ASSET"
  [ "$sig" = NONE ] || cp "$FX/$sig" "$serve/$ASSET.sig"
  [ "$keys" = NONE ] || cp "$FX/$keys" "$t/$keys"
  TMP="$t" BASE="file://$serve" ASSET="$ASSET" VERSION="$tag" REPO="invizen/pulsemon" \
    PULSEMON_PUBKEYS_URL="file://$t/$keys" \
    bash -c "$(cat "$FX/verify.inc")" >/dev/null 2>&1
  rc=$?
  if { [ "$rc" -eq 0 ] && [ "$expect" = ok ]; } || { [ "$rc" -ne 0 ] && [ "$expect" = refuse ]; }; then
    echo "PASS $name ($expect)"
  else
    echo "FAIL $name: want $expect, rc=$rc"; FAILED=1
  fi
  rm -rf "$t"
}
run valid-sig       ok     "$ASSET.sig.good"  pubkeys         v9.9.9 "$ASSET.orig"
run tampered-binary refuse "$ASSET.sig.good"  pubkeys         v9.9.9 "$ASSET.tampered"
run tag-replay      refuse "$ASSET.sig.oldtag" pubkeys        v9.9.9 "$ASSET.orig"
run missing-sig     refuse NONE               pubkeys         v9.9.9 "$ASSET.orig"
run unknown-key     refuse "$ASSET.sig.good"  pubkeys-unknown v9.9.9 "$ASSET.orig"
run short-sig       refuse "$ASSET.sig.short" pubkeys         v9.9.9 "$ASSET.orig"
run pubkeys-404     refuse "$ASSET.sig.good"  NONE            v9.9.9 "$ASSET.orig"
run empty-keyset    refuse "$ASSET.sig.good"  pubkeys-empty   v9.9.9 "$ASSET.orig"
echo "harness done (FAILED=$FAILED)"; exit $FAILED
