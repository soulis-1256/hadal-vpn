#!/usr/bin/env sh
set -eu

# Skip service disable when upgrading deb/rpm packages
case "${1:-}" in
  upgrade|1|2) exit 0 ;;
esac

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl disable --now hadald.service >/dev/null 2>&1 || true
fi
