#!/bin/sh

set -eu

URL="https://raw.githubusercontent.com/rachidlaad/uxarion/main/scripts/install/install.sh"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" | sh -s -- "$@"
  exit 0
fi

if command -v wget >/dev/null 2>&1; then
  wget -q -O - "$URL" | sh -s -- "$@"
  exit 0
fi

echo "curl or wget is required to install Uxarion." >&2
exit 1
