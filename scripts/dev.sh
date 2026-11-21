#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

usage() {
  cat <<'EOF'
Usage: scripts/dev.sh <command> [args...]

Run or deploy UI/CLI edits fast without touching the privileged hadald daemon.

Commands:
  gui              Run `bun run tauri dev` with live hot-reload against the running hadald
                   (temporarily stops hadal-gui.service if active, restarts it on exit)
  cli [args...]    Run `cargo run -p hadal-cli -- [args...]` against the running hadald
  ui               Rebuild and install only hadal-gui + hadal-cli (keeps VPN connected)
  deploy [flags]   Full local build + install + restart (forwards flags to scripts/install.sh)
EOF
}

cmd="${1:-}"
if [[ -z "$cmd" || "$cmd" == "-h" || "$cmd" == "--help" ]]; then
  usage
  exit 0
fi
shift

case "$cmd" in
  gui)
    if ! systemctl is-active --quiet hadald 2>/dev/null && [[ ! -S /run/hadald/hadald.sock ]]; then
      echo "Warning: hadald does not appear to be running at /run/hadald/hadald.sock" >&2
    fi
    was_active=0
    if systemctl --user is-active --quiet hadal-gui.service 2>/dev/null; then
      was_active=1
      systemctl --user stop hadal-gui.service
    fi
    cleanup() {
      if [[ "$was_active" -eq 1 ]]; then
        systemctl --user start hadal-gui.service || true
      fi
    }
    trap cleanup EXIT INT TERM
    cd "$REPO_ROOT/crates/hadal-gui"
    bun install
    bun run tauri dev
    ;;
  cli)
    exec cargo run -p hadal-cli -- "$@"
    ;;
  ui)
    exec "$REPO_ROOT/scripts/install.sh" --ui-only "$@"
    ;;
  deploy)
    exec "$REPO_ROOT/scripts/install.sh" "$@"
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    usage
    exit 2
    ;;
esac
