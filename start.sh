#!/usr/bin/env bash
# Launch ThatOsintMe.
#
#   ./start.sh            local: loopback, no password, opens your browser
#                         straight to the lawful-use attestation (purpose + I AGREE).
#   ./start.sh --lan      phone/LAN: binds this machine's LAN IP with TLS + a
#                         generated password, so you can reach it from your phone.
#   ./start.sh [--lan] PORT   pick a port (default 8443).
set -euo pipefail
cd "$(dirname "$0")"

MODE=local
if [ "${1:-}" = "--lan" ]; then MODE=lan; shift; fi
PORT="${1:-8443}"

if [ "$MODE" = lan ]; then
  # Re-detect the LAN IP each run (a DHCP lease change would strand an old bind).
  IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[\d.]+' | grep -v '^192\.168\.122\.' | head -1)
  [ -n "$IP" ] || { echo "no LAN address found" >&2; exit 1; }
  exec python3 serve.py --host "$IP" --port "$PORT"
else
  exec python3 serve.py --host 127.0.0.1 --port "$PORT" --open
fi
