#!/bin/bash
# Builds libv2ray.aar (Xray core bridge) from the pinned AndroidLibXrayLite submodule, with Xray-core
# patched so TLS is not mandatory (see patch_xray.py). Output: libv2ray-out/libv2ray.aar
# Needs: Go, gomobile prerequisites (Android SDK + NDK, ANDROID_NDK_HOME), python3, jq, curl.
set -o errexit
set -o pipefail
set -o nounset

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/libv2ray-out"
PATCHED="$ROOT/xray-core-patched"
mkdir -p "$OUT"

cd "$ROOT/AndroidLibXrayLite"

go install golang.org/x/mobile/cmd/gomobile@latest
export PATH="$PATH:$(go env GOPATH)/bin"

# copy the exact Xray-core version the bridge is pinned to and patch the copy
go mod download github.com/xtls/xray-core
SRC="$(go list -m -f '{{.Dir}}' github.com/xtls/xray-core)"
echo "Xray-core source: $SRC"
rm -rf "$PATCHED"
cp -r "$SRC" "$PATCHED"
chmod -R u+w "$PATCHED"
python3 "$ROOT/scripts/patch_xray.py" "$PATCHED"
go mod edit -replace "github.com/xtls/xray-core=$PATCHED"

mkdir -p assets data
bash gen_assets.sh download
cp -v data/*.dat assets/

gomobile init
go mod tidy
gomobile bind -v -androidapi 24 -trimpath -ldflags='-s -w -buildid= -checklinkname=0' ./

cp -v libv2ray*.aar "$OUT/libv2ray.aar"
ls -la "$OUT"
