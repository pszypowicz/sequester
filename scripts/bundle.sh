#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Build Sequester.app from the Swift package into .build/Sequester.app.

Usage: scripts/bundle.sh [--identity <substring|adhoc>]

Flags:
  --identity   Codesign identity, matched as a substring against
               'security find-identity' output (default: "Developer ID
               Application", the release identity). No fallback: a missing
               match is a hard error, never a silently different signature.
               Pass "adhoc" for an unsigned local build.
  -h, --help   Show this help.
EOF
}

identity="Developer ID Application"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --identity) identity="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Run from the repo root regardless of caller CWD; every path below is relative.
cd "$(cd "$(dirname "$0")/.." && pwd)"

# Version comes from the VERSION file - the single source of truth, also
# read by the BuildMetadata plugin so the app reports the same string.
VERSION=$(head -1 VERSION 2>/dev/null | tr -d '[:space:]')
[ -n "$VERSION" ] || { echo "error: VERSION file missing or empty" >&2; exit 1; }

# A VERSION-only bump changes no compiler input, so the build system can
# skip the metadata plugin and reuse binaries reporting the previous
# version. Deleting just the generated files forces them to be rewritten
# and their targets recompiled; removing the directory itself would
# invalidate the build plan and fail the build.
find .build/plugins/outputs -name 'BuildMetadata.generated.swift' -delete 2>/dev/null || true
swift build -c release

# Guard the outcome: the binaries must report the version being stamped
# into the plist, so a stale build is a hard error rather than a release
# that lies about itself.
built_version=$(.build/release/sequester-cli --version | awk '{print $1}')
if [[ "$built_version" != "$VERSION" ]]; then
  echo "error: built binary reports $built_version but VERSION says $VERSION" >&2
  echo "Run 'swift package clean' and try again." >&2
  exit 1
fi

APP=".build/Sequester.app/Contents"
rm -rf ".build/Sequester.app"
mkdir -p "$APP/MacOS" "$APP/Resources"

cp .build/release/Sequester "$APP/MacOS/Sequester"
cp .build/release/sequester-cli "$APP/MacOS/sequester-cli"
cp Sources/Sequester/Info.plist "$APP/Info.plist"
# Both version fields come from VERSION; the plist's placeholders are never shipped.
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$APP/Info.plist"

if [[ -f Resources/Sequester.icns ]]; then
  cp Resources/Sequester.icns "$APP/Resources/Sequester.icns"
else
  echo "warning: Resources/Sequester.icns missing; run scripts/build-icon.sh" >&2
fi

ENTITLEMENTS="Sources/Sequester/Sequester.entitlements"

# The bundle-level codesign does not sign nested executables, so the CLI
# gets its own signature first. No entitlements: it must stay unsandboxed
# to reach /dev/tty, exec arbitrary commands, and write /usr/local/bin.
if [[ "$identity" == "adhoc" ]]; then
  codesign --sign - --force --options runtime "$APP/MacOS/sequester-cli"
  codesign --sign - --force --options runtime --entitlements "$ENTITLEMENTS" .build/Sequester.app
else
  # || true: with set -e, a failing security query (locked/absent
  # keychain) would abort before the explicit error below.
  # index() is a literal substring test; certificate names contain regex
  # metacharacters (dots, parentheses around the team id).
  sign=$(security find-identity -v -p codesigning | awk -v id="$identity" 'index($0, id) {print $2; exit}' || true)
  if [[ -z "$sign" ]]; then
    echo "error: no codesigning identity matching '$identity'" >&2
    echo "List identities with: security find-identity -v -p codesigning" >&2
    echo "Pick one with --identity <substring>, or --identity adhoc for an unsigned dev build." >&2
    exit 1
  fi
  # --timestamp: notarization requires a secure timestamp.
  codesign --sign "$sign" --force --options runtime --timestamp "$APP/MacOS/sequester-cli"
  codesign --sign "$sign" --force --options runtime --timestamp --entitlements "$ENTITLEMENTS" .build/Sequester.app
fi

echo "Built .build/Sequester.app"
