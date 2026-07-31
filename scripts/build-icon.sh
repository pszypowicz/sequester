#!/bin/bash
set -euo pipefail

# Render the master PNG, scale it to a full iconset, and pack Resources/Sequester.icns.
# Run from the repo root: bash scripts/build-icon.sh

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

MASTER="$TMP/icon-1024.png"
swift "$ROOT/scripts/generate-icon.swift" "$MASTER"

SET="$TMP/Sequester.iconset"
mkdir -p "$SET"

# name              size
gen() { sips -z "$2" "$2" "$MASTER" --out "$SET/$1" >/dev/null; }
gen icon_16x16.png 16
gen icon_16x16@2x.png 32
gen icon_32x32.png 32
gen icon_32x32@2x.png 64
gen icon_128x128.png 128
gen icon_128x128@2x.png 256
gen icon_256x256.png 256
gen icon_256x256@2x.png 512
gen icon_512x512.png 512
gen icon_512x512@2x.png 1024

mkdir -p "$ROOT/Resources"
iconutil -c icns "$SET" -o "$ROOT/Resources/Sequester.icns"
echo "wrote Resources/Sequester.icns"
