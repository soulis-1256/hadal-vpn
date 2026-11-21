#!/usr/bin/env bash
set -euo pipefail

REPO_SLUG="${HADAL_REPO:-soulis-1256/hadal-vpn}"
PREFIX="${HADAL_PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
SYSTEMD_SYSTEM_DIR="/etc/systemd/system"
USER_SYSTEMD_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
DESKTOP_DIR="$PREFIX/share/applications"
ICON_DIR="$PREFIX/share/icons/hicolor/128x128/apps"

UI_ONLY=0
NO_BUILD=0
RECONNECT=0
FROM_RELEASE=0
VERSION_TAG=""

usage() {
  cat <<'EOF'
Usage: scripts/install.sh [OPTIONS]

Build (when run in a repo checkout) or download (when run standalone / --from-release)
Hadal VPN binaries, systemd units, and desktop entry, then restart services cleanly.

Options:
  --ui-only         Build and update only hadal-gui + hadal-cli (keeps hadald & VPN up)
  --no-build        Install existing target/release/* binaries without rebuilding
  --reconnect       If VPN was connected before hadald restart, reconnect to the same node
  --from-release    Download the prebuilt GitHub Release tarball instead of building locally
  --tag <tag>       Release tag to download with --from-release (defaults to latest)
  -h, --help        Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ui-only) UI_ONLY=1; shift ;;
    --no-build) NO_BUILD=1; shift ;;
    --reconnect) RECONNECT=1; shift ;;
    --from-release) FROM_RELEASE=1; shift ;;
    --tag) VERSION_TAG="${2:?missing --tag value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

SCRIPT_PATH="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
if [[ -n "$SCRIPT_PATH" && -e "$SCRIPT_PATH" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
fi
REPO_ROOT=""
BUNDLE_ROOT=""
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/../Cargo.toml" ]]; then
  REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [[ -n "$SCRIPT_DIR" && -x "$SCRIPT_DIR/../bin/hadald" && -f "$SCRIPT_DIR/../contrib/hadald.service" ]]; then
  BUNDLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

if [[ -z "$REPO_ROOT" && -z "$BUNDLE_ROOT" ]]; then
  FROM_RELEASE=1
fi

query_active_cluster() {
  python3 - <<'PY' 2>/dev/null || true
import json, socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2.0)
s.connect("/run/hadald/hadald.sock")
s.sendall(b'{"op":"status"}\n')
buf = b""
while not buf.endswith(b"\n"):
    chunk = s.recv(4096)
    if not chunk:
        break
    buf += chunk
resp = json.loads(buf.decode())
st = resp.get("data", {})
if st.get("state") == "protected":
    print(st.get("cluster_id") or st.get("domain") or "")
PY
}

install_user_gui_unit() {
  local unit_src="$1"
  mkdir -p "$USER_SYSTEMD_DIR"
  if command -v systemctl >/dev/null 2>&1 && systemctl --user status >/dev/null 2>&1; then
    # Stop and clear any leftover transient `systemd-run` unit BEFORE writing & reloading the persistent unit
    systemctl --user stop hadal-gui.service >/dev/null 2>&1 || true
    systemctl --user reset-failed hadal-gui.service >/dev/null 2>&1 || true
    rm -f "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/systemd/transient/hadal-gui.service"
    sed "s|/usr/local/bin/hadal-gui|$BIN_DIR/hadal-gui|g" "$unit_src" > "$USER_SYSTEMD_DIR/hadal-gui.service"
    systemctl --user daemon-reload
    systemctl --user enable hadal-gui.service >/dev/null 2>&1 || true
    if [[ -n "${WAYLAND_DISPLAY:-}${DISPLAY:-}" ]]; then
      systemctl --user import-environment WAYLAND_DISPLAY DISPLAY HYPRLAND_INSTANCE_SIGNATURE XDG_CURRENT_DESKTOP XDG_SESSION_TYPE >/dev/null 2>&1 || true
      systemctl --user start hadal-gui.service
    else
      echo "Note: no graphical DISPLAY/WAYLAND_DISPLAY detected; hadal-gui.service enabled for next login."
    fi
  else
    sed "s|/usr/local/bin/hadal-gui|$BIN_DIR/hadal-gui|g" "$unit_src" > "$USER_SYSTEMD_DIR/hadal-gui.service"
  fi
}

install_from_dir() {
  local root="$1"
  local bin_root="$2"
  local prev_cluster=""

  if [[ "$UI_ONLY" -eq 0 && "$RECONNECT" -eq 1 && -S /run/hadald/hadald.sock ]]; then
    prev_cluster="$(query_active_cluster)"
  fi

  echo "Installing Hadal VPN into $PREFIX (sudo required for $BIN_DIR and $SYSTEMD_SYSTEM_DIR)..."
  sudo install -Dm755 "$bin_root/hadal-cli" "$BIN_DIR/hadal-cli"
  sudo install -Dm755 "$bin_root/hadal-gui" "$BIN_DIR/hadal-gui"
  sudo install -Dm644 "$root/contrib/hadal-vpn.desktop" "$DESKTOP_DIR/hadal-vpn.desktop"
  if [[ -f "$root/crates/hadal-gui/src-tauri/icons/128x128.png" ]]; then
    sudo install -Dm644 "$root/crates/hadal-gui/src-tauri/icons/128x128.png" "$ICON_DIR/hadal-vpn.png"
  elif [[ -f "$root/contrib/hadal-vpn.png" ]]; then
    sudo install -Dm644 "$root/contrib/hadal-vpn.png" "$ICON_DIR/hadal-vpn.png"
  fi

  if [[ "$UI_ONLY" -eq 0 ]]; then
    sudo groupadd -f network
    if [[ -n "${USER:-}" && "$USER" != "root" ]] && ! id -nG "$USER" | tr ' ' '\n' | grep -qx network; then
      sudo usermod -aG network "$USER"
      echo "Added $USER to the 'network' group (re-login or run 'newgrp network' if IPC fails)."
    fi
    sudo install -Dm755 "$bin_root/hadald" "$BIN_DIR/hadald"
    sed "s|/usr/local/bin/hadald|$BIN_DIR/hadald|g" "$root/contrib/hadald.service" | \
      sudo tee "$SYSTEMD_SYSTEM_DIR/hadald.service" >/dev/null
    sudo chmod 644 "$SYSTEMD_SYSTEM_DIR/hadald.service"
    sudo systemctl daemon-reload
    sudo systemctl enable hadald.service >/dev/null 2>&1 || true
    sudo systemctl restart hadald.service
  else
    echo "Skipped hadald rebuild/restart (--ui-only); active tunnel untouched."
  fi

  install_user_gui_unit "$root/contrib/hadal-gui.service"

  if [[ -n "$prev_cluster" ]]; then
    echo "Reconnecting to previous node ($prev_cluster)..."
    for _ in $(seq 1 20); do
      [[ -S /run/hadald/hadald.sock ]] && break
      sleep 0.15
    done
    "$BIN_DIR/hadal-cli" connect --server "$prev_cluster" || true
  fi

  echo "Done! Installed:"
  echo "  hadal-cli: $BIN_DIR/hadal-cli"
  echo "  hadal-gui: $BIN_DIR/hadal-gui"
  [[ "$UI_ONLY" -eq 0 ]] && echo "  hadald:    $BIN_DIR/hadald (systemd: hadald.service)"
}

if [[ "$FROM_RELEASE" -eq 1 ]]; then
  arch="$(uname -m)"
  if [[ "$arch" != "x86_64" ]]; then
    echo "Prebuilt releases currently target x86_64 (detected $arch). Clone the repo and build from source." >&2
    exit 1
  fi
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT
  echo "Downloading prebuilt Hadal VPN release from GitHub ($REPO_SLUG)..."
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    if [[ -n "$VERSION_TAG" ]]; then
      gh release download "$VERSION_TAG" -R "$REPO_SLUG" -p "hadal-vpn-*-linux-x86_64.tar.gz" -p "SHA256SUMS" -D "$tmpdir"
    else
      gh release download -R "$REPO_SLUG" -p "hadal-vpn-*-linux-x86_64.tar.gz" -p "SHA256SUMS" -D "$tmpdir"
    fi
  else
    if [[ -n "$VERSION_TAG" ]]; then
      api_url="https://api.github.com/repos/$REPO_SLUG/releases/tags/$VERSION_TAG"
    else
      api_url="https://api.github.com/repos/$REPO_SLUG/releases/latest"
    fi
    asset_urls="$(curl -fsSL "$api_url" | python3 -c '
import json, sys
rel = json.load(sys.stdin)
for a in rel.get("assets", []):
    n = a["name"]
    if (n.startswith("hadal-vpn-") and n.endswith("-linux-x86_64.tar.gz")) or n == "SHA256SUMS":
        print(a["browser_download_url"], n)
')"
    if [[ -z "$asset_urls" ]]; then
      echo "Could not find linux-x86_64 release assets at $api_url (if repo is private, install & auth 'gh' CLI)." >&2
      exit 1
    fi
    while read -r url fname; do
      curl -fsSL -o "$tmpdir/$fname" "$url"
    done <<< "$asset_urls"
  fi

  tarball="$(find "$tmpdir" -maxdepth 1 -name 'hadal-vpn-*-linux-x86_64.tar.gz' | head -n1)"
  if [[ -z "$tarball" ]]; then
    echo "Release tarball missing in $tmpdir" >&2
    exit 1
  fi
  if [[ -f "$tmpdir/SHA256SUMS" ]]; then
    (cd "$tmpdir" && grep "$(basename "$tarball")" SHA256SUMS | sha256sum -c -)
  fi
  tar -xzf "$tarball" -C "$tmpdir"
  extracted="$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d -name 'hadal-vpn-*' | head -n1)"
  install_from_dir "$extracted" "$extracted/bin"
  exit 0
fi

if [[ "$FROM_RELEASE" -eq 0 && -n "$BUNDLE_ROOT" ]]; then
  install_from_dir "$BUNDLE_ROOT" "$BUNDLE_ROOT/bin"
  exit 0
fi

cd "$REPO_ROOT"

if [[ "$NO_BUILD" -eq 0 ]]; then
  echo "Building SolidJS frontend..."
  (cd "$REPO_ROOT/crates/hadal-gui" && bun install --frozen-lockfile && bun run build)
  if [[ "$UI_ONLY" -eq 1 ]]; then
    echo "Building release hadal-cli and hadal-gui..."
    cargo build --release -p hadal-cli -p hadal-gui
  else
    echo "Building release workspace (hadald, hadal-cli, hadal-gui)..."
    cargo build --release
  fi
fi

install_from_dir "$REPO_ROOT" "$REPO_ROOT/target/release"
