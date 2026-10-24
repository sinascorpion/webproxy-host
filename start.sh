#!/bin/sh
# Copyright (c) 2026 sinascorpion. SPDX-License-Identifier: MIT
set -eu
umask 077
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
: "${ADMIN_PASSWORD:?Set ADMIN_PASSWORD in the host Environment panel}"
: "${PUBLIC_URL:?Set PUBLIC_URL to the assigned public HTTPS origin}"
case "$(uname -m)" in
  x86_64|amd64) arch=amd64; expected=7ad673c9e553be5ac129cf88ab913842315934d959e2561112bb8d1f3897aafc ;;
  aarch64|arm64) arch=arm64; expected=6c5a30b8f68d8f26a89b9e62e30374b7cba97323021a584c5a35556733dad8e4 ;;
  *) echo "Unsupported architecture; Linux amd64/arm64 is required." >&2; exit 1 ;;
esac
[ "$(uname -s)" = Linux ] || { echo "Linux is required." >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required." >&2; exit 1; }
cache="${DATA_DIR:-./data}/launcher"
mkdir -p "$cache"
bin="$cache/webproxy-host-v0.1.0-$arch"
verify() { [ -f "$bin" ] && printf '%s  %s\n' "$expected" "$bin" | sha256sum -c - >/dev/null 2>&1; }
if ! verify; then
  temp="$bin.download.$$"
  trap 'rm -f "$temp"' EXIT HUP INT TERM
  url="https://github.com/sinascorpion/webproxy-host/releases/download/v0.1.0/webproxy-host_linux_$arch"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 2 --connect-timeout 20 --max-time 180 -o "$temp" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -T 180 -O "$temp" "$url"
  else
    echo "curl or wget is required, or build this Go project from source." >&2; exit 1
  fi
  printf '%s  %s\n' "$expected" "$temp" | sha256sum -c - >/dev/null || { echo "Release checksum mismatch." >&2; exit 1; }
  chmod 700 "$temp"
  mv -f "$temp" "$bin"
  trap - EXIT HUP INT TERM
fi
chmod 700 "$bin"
exec "$bin"
