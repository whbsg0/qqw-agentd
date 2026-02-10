#!/bin/sh
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
LAYOUT="$ROOT/layout"
OUTDIR="$ROOT/packages"

BIN_SRC="${1:-$ROOT/../dist/agentd-ios-arm64}"
VERSION="${2:-1:0.1.0-1}"
ARCH="iphoneos-arm64"

if [ ! -f "$BIN_SRC" ]; then
  echo "missing BIN_SRC: $BIN_SRC" >&2
  exit 1
fi

mkdir -p "$OUTDIR"
mkdir -p "$LAYOUT/var/jb/usr/local/bin"

cp -f "$BIN_SRC" "$LAYOUT/var/jb/usr/local/bin/agentd"
chmod 755 "$LAYOUT/var/jb/usr/local/bin/agentd" || true
chmod 755 "$LAYOUT/DEBIAN/postinst" "$LAYOUT/DEBIAN/prerm" || true

CTRL="$LAYOUT/DEBIAN/control"
if [ -f "$CTRL" ]; then
  if command -v perl >/dev/null 2>&1; then
    perl -pi -e "s/^Version:\\s*.*/Version: $VERSION/" "$CTRL"
  else
    sed -i "s/^Version:.*/Version: $VERSION/" "$CTRL"
  fi
fi

VERSION_SAFE="$(printf '%s' "$VERSION" | tr ':' '_')"
OUT="$OUTDIR/com.qqw.agentd_${VERSION_SAFE}_${ARCH}.deb"
dpkg-deb -b "$LAYOUT" "$OUT"
echo "$OUT"
