#!/usr/bin/env sh
set -eu

if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers hadald.conf >/dev/null 2>&1 || true
fi
if command -v groupadd >/dev/null 2>&1; then
  groupadd -f network || true
fi

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && command -v usermod >/dev/null 2>&1; then
  usermod -aG network "$SUDO_USER" || true
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
  systemctl enable hadald.service >/dev/null 2>&1 || true
  systemctl restart hadald.service >/dev/null 2>&1 || true
fi

echo "Hadal VPN installed. Ensure your user is in the 'network' group:"
echo "  sudo usermod -aG network \"\$USER\"  (then log out/in)"
echo "Enable the tray app for your user session:"
echo "  systemctl --user enable --now hadal-gui.service"
