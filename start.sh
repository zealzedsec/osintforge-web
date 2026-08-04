#!/usr/bin/env bash
# Start OSINTForge on the current LAN address. Re-detects the IP each run,
# because a DHCP lease change would otherwise leave it bound to an address
# the machine no longer has.
set -euo pipefail
cd "$(dirname "$0")"
IP=$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[\d.]+' | grep -v '^192\.168\.122\.' | head -1)
[ -n "$IP" ] || { echo "no LAN address found" >&2; exit 1; }
exec python3 serve.py --host "$IP" --port "${1:-8443}"
