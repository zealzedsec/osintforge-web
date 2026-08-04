#!/usr/bin/env python3
"""Private HTTPS host for the OSINTForge console.

Threat model, since "accessible from my phone" and "secure" pull against
each other and the resolution is worth stating:

  * The page must be reachable from another device, so it cannot bind
    loopback. It binds one explicit LAN address rather than 0.0.0.0 --
    0.0.0.0 would also publish it on the libvirt bridge (192.168.122.1),
    exposing it to every VM on this host for no benefit.
  * Anyone else on the same Wi-Fi can reach that address, so it requires
    HTTP Basic auth with a generated 128-bit password. Compared with
    hmac.compare_digest so a wrong password leaks nothing through timing.
  * Basic auth sends the password in every request, so plaintext HTTP would
    put it on the air in clear. TLS is therefore not optional here even on
    a home network; the certificate is self-signed, which your phone will
    warn about once.
  * It is never exposed to the internet. No port forwarding, no tunnel.
    Off the LAN it simply is not reachable.

Nothing here is written to disk by the app itself: the console keeps its
case data in the browser's localStorage on whichever device you use.
"""
from __future__ import annotations

import argparse
import base64
import hmac
import http.server
import os
import secrets
import ssl
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CERT = ROOT / "cert.pem"
KEY = ROOT / "key.pem"
CRED = ROOT / ".credentials"


def ensure_cert(host: str) -> None:
    """Self-signed cert with the LAN IP in subjectAltName.

    The SAN matters: a certificate carrying only a CN is rejected outright
    by modern mobile browsers, which would make the site unreachable rather
    than merely warned-about.
    """
    if CERT.exists() and KEY.exists():
        return
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(KEY), "-out", str(CERT), "-days", "825",
         "-subj", "/CN=osintforge.local",
         "-addext", f"subjectAltName=IP:{host},DNS:osintforge.local"],
        check=True, capture_output=True,
    )
    KEY.chmod(0o600)
    CERT.chmod(0o644)


def ensure_password() -> tuple[str, str]:
    """Load or mint credentials. Written 0600 so other local users cannot
    read them out of the file."""
    if CRED.exists():
        user, _, pw = CRED.read_text().strip().partition(":")
        if user and pw:
            return user, pw
    user, pw = "osint", secrets.token_urlsafe(16)
    CRED.write_text(f"{user}:{pw}\n")
    CRED.chmod(0o600)
    return user, pw


class Handler(http.server.SimpleHTTPRequestHandler):
    user = pw = ""

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(ROOT), **kw)

    def _authorised(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            got = base64.b64decode(header[6:]).decode("utf-8", "replace")
        except Exception:
            return False
        # compare_digest on the whole "user:pass" pair: comparing the two
        # halves separately with == would leak the username by timing.
        return hmac.compare_digest(got, f"{self.user}:{self.pw}")

    def _deny(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="OSINTForge", charset="UTF-8"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        if not self._authorised():
            return self._deny()
        # Never serve the key, cert or credentials file, whatever the path
        # normalisation ends up doing.
        if Path(self.path).name in {"key.pem", "cert.pem", ".credentials", "serve.py"}:
            self.send_error(404)
            return
        super().do_GET()

    def do_HEAD(self) -> None:
        if not self._authorised():
            return self._deny()
        super().do_HEAD()

    def end_headers(self) -> None:
        # The console fetches third-party APIs and CORS relays by design, so
        # a restrictive CSP would break it. These are the headers that cost
        # nothing and still help.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:
        # Default logging would print the request line only, but be explicit:
        # nothing derived from the Authorization header is ever logged.
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Serve OSINTForge over private HTTPS.")
    ap.add_argument("--host", default=os.environ.get("OSF_HOST", "127.0.0.1"),
                    help="LAN address to bind. Loopback by default; pass your "
                         "LAN IP to reach it from a phone.")
    ap.add_argument("--port", type=int, default=8443)
    args = ap.parse_args()

    ensure_cert(args.host)
    user, pw = ensure_password()
    Handler.user, Handler.pw = user, pw

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(CERT), keyfile=str(KEY))

    httpd = http.server.ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"OSINTForge  https://{args.host}:{args.port}/")
    print(f"  user      {user}")
    print(f"  password  {pw}")
    print("  (self-signed cert — your phone will warn once; accept it)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
