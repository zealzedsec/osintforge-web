#!/usr/bin/env bash
# ThatOsintMe installer — one command to get the whole app ready to run.
#
#   ./install.sh                 install + verify (prompts about opencode)
#   ./install.sh --with-opencode install and auto-install opencode (the agent)
#   ./install.sh --no-opencode   install, skip the agent runtime
#   ./install.sh --selftest      just run the verification checks
#   ./install.sh --uninstall     remove the launcher + desktop entry
#
# No dependencies to pip-install: the app is stdlib Python + vanilla JS. The
# only hard requirements are python3 >= 3.11 and openssl. opencode is optional
# and only needed for the 🤖 Agent tab.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
LAUNCHER="${BIN_DIR}/thatosintme"
DESKTOP="${HOME}/.local/share/applications/thatosintme.desktop"

# ---- pretty output ---------------------------------------------------------
if [ -t 1 ]; then
  C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_ERR=$'\e[31m'; C_B=$'\e[1m'; C_DIM=$'\e[2m'; C_0=$'\e[0m'
else C_OK=; C_WARN=; C_ERR=; C_B=; C_DIM=; C_0=; fi
info(){ printf '%s▸%s %s\n' "$C_B" "$C_0" "$*"; }
ok(){   printf '  %s✓%s %s\n' "$C_OK" "$C_0" "$*"; }
warn(){ printf '  %s!%s %s\n' "$C_WARN" "$C_0" "$*"; }
die(){  printf '  %s✗ %s%s\n' "$C_ERR" "$*" "$C_0" >&2; exit 1; }

WITH_OPENCODE=ask
DO_INSTALL=1
case "${1:-}" in
  --with-opencode) WITH_OPENCODE=yes ;;
  --no-opencode)   WITH_OPENCODE=no ;;
  --selftest)      DO_INSTALL=0 ;;
  --uninstall)
      rm -f "$LAUNCHER" "$DESKTOP"
      command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "${HOME}/.local/share/applications" 2>/dev/null || true
      ok "removed launcher and desktop entry"
      echo "  (app files, cert, and credentials left in place — delete $APP_DIR to remove fully)"
      exit 0 ;;
  -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  "") ;;
  *) die "unknown option: $1 (try --help)" ;;
esac

printf '\n  %s◆ ThatOsintMe%s  %sv4 — intelligence console installer%s\n' "$C_B" "$C_0" "$C_DIM" "$C_0"
printf '  %s────────────────────────────────────────%s\n\n' "$C_DIM" "$C_0"

# ---- 1. prerequisites ------------------------------------------------------
info "Checking prerequisites"
command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.11+ and re-run."
PYV="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
python3 -c 'import sys;raise SystemExit(0 if sys.version_info>=(3,11) else 1)' \
  || die "Python $PYV found, but 3.11+ is required."
ok "python3 $PYV"
command -v openssl >/dev/null 2>&1 && ok "openssl $(openssl version 2>/dev/null | awk '{print $2}')" \
  || die "openssl not found (needed to generate the TLS certificate)."

# ---- 2. opencode (the agent runtime, optional) -----------------------------
info "Agent runtime (opencode — powers the 🤖 Agent tab)"
if command -v opencode >/dev/null 2>&1; then
  ok "opencode $(opencode --version 2>/dev/null || echo present)"
  opencode providers list >/dev/null 2>&1 \
    && ok "opencode has provider credentials" \
    || warn "opencode is not logged in — run 'opencode providers' before using the Agent tab"
else
  warn "opencode not installed — the Agent tab will be disabled (everything else works)"
  do_oc=no
  case "$WITH_OPENCODE" in
    yes) do_oc=yes ;;
    no)  do_oc=no ;;
    ask) if [ -t 0 ]; then
           printf '  Install opencode now? [y/N] '; read -r a; [ "${a:-}" = y ] || [ "${a:-}" = Y ] && do_oc=yes
         fi ;;
  esac
  if [ "$do_oc" = yes ]; then
    info "Installing opencode via the official script"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL https://opencode.ai/install | bash && ok "opencode installed — run 'opencode providers' to log in" \
        || warn "opencode install failed; install it manually from https://opencode.ai"
    else warn "curl not found; install opencode manually from https://opencode.ai"; fi
  else
    echo "    (install later: curl -fsSL https://opencode.ai/install | bash)"
  fi
fi

# ---- 3. self-test ----------------------------------------------------------
info "Verifying the app"
( cd "$APP_DIR" && python3 - <<'PY'
import sys
import osint_tools as t, workflows as w, osint_mcp  # noqa: F401  (import must succeed)
assert t._ip_is_public("8.8.8.8") and not t._ip_is_public("127.0.0.1"), "SSRF guard wrong"
for bad in ("http://127.0.0.1/", "http://169.254.169.254/", "file:///etc/passwd"):
    try: t._validate(bad); sys.exit(f"SSRF guard failed to block {bad}")
    except t.BlockedTarget: pass
assert t.phone_parse("+27821234567")["meta"]["country"] == "ZA", "phone parse wrong"
assert t.generate_dorks("example.com")["meta"]["count"] > 0, "dork engine broken"
assert len(t.TOOLS) >= 9 and len(w.WORKFLOWS) == 4, "tool/workflow registry incomplete"
print("OK")
PY
) >/dev/null 2>/tmp/osf_install_test.err && ok "self-test passed (SSRF guard, tools, workflows, dorks)" \
  || { cat /tmp/osf_install_test.err >&2; die "self-test failed (see above)"; }

[ "$DO_INSTALL" = 0 ] && { echo; ok "selftest-only run complete"; exit 0; }

chmod +x "$APP_DIR/serve.py" "$APP_DIR/start.sh" "$APP_DIR/osint_mcp.py" 2>/dev/null || true

# ---- 4. launcher + desktop entry -------------------------------------------
info "Installing launcher"
# remove any launcher/desktop entry from the pre-rename "osintforge" name
rm -f "${BIN_DIR}/osintforge" "${HOME}/.local/share/applications/osintforge.desktop" \
      "${HOME}/.local/share/applications/zedsec-osintforge.desktop" 2>/dev/null || true
mkdir -p "$BIN_DIR"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
# ThatOsintMe launcher (generated by install.sh). No args = local mode: no
# password, opens the browser to the attestation gate. Pass --lan for secure
# phone/LAN access, and/or a port number.
exec "$APP_DIR/start.sh" "\$@"
EOF
chmod +x "$LAUNCHER"
ok "launcher → $LAUNCHER"
case ":$PATH:" in *":$BIN_DIR:"*) ok "$BIN_DIR is on your PATH" ;;
  *) warn "add $BIN_DIR to PATH:  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc" ;;
esac

info "Installing desktop entry"
mkdir -p "$(dirname "$DESKTOP")"
ICON="utilities-terminal"; [ -f "${HOME}/.icons/zedsec-owl.svg" ] && ICON="zedsec-owl"
cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=ThatOsintMe
Comment=Private OSINT intelligence console
Exec=$LAUNCHER
Icon=$ICON
Terminal=true
Categories=Network;Security;
StartupNotify=true
EOF
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$(dirname "$DESKTOP")" 2>/dev/null || true
ok "desktop entry → $DESKTOP"

# ---- 5. done ---------------------------------------------------------------
echo
printf '%s✓ ThatOsintMe is installed.%s\n\n' "$C_OK$C_B" "$C_0"
echo "Run it:"
echo "    ${C_B}thatosintme${C_0}                 # local: opens your browser, no password —"
echo "                                just state your purpose + type I AGREE"
echo "    ${C_B}thatosintme --lan${C_0}           # phone/LAN: TLS + generated password"
echo "    ${C_B}thatosintme --lan 9443${C_0}      # ...on a custom port"
echo
echo "Local mode needs no password (loopback isn't reachable from the network —"
echo "the in-app attestation is the gate). ${C_DIM}--lan${C_0} prints a generated password"
echo "(also in ${C_DIM}$APP_DIR/.credentials${C_0}) and uses a self-signed cert your"
echo "phone warns about once. Either way it is never exposed to the internet."
echo
command -v opencode >/dev/null 2>&1 \
  && echo "The 🤖 Agent tab is ready (opencode detected)." \
  || echo "Install opencode to enable the 🤖 Agent tab (see above)."
