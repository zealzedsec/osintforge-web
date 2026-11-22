#!/usr/bin/env python3
"""Private HTTPS host + local OSINT API for the OSINTForge console.

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

New in v4 — the local OSINT API (everything under /api/, behind the same auth):

  * /api/relay  moves cross-origin fetches SERVER-SIDE. The old console sent
    every probed URL (i.e. who you are investigating) to public CORS relays.
    That leaked targets to strangers and contradicted this file's own "never
    announce to a third party" rule. Now traffic leaves from this host, guarded
    by the SSRF allowlist in osint_tools.safe_fetch (public destinations only).
  * /api/tool, /api/workflow run the server-side OSINT primitives/pipelines.
  * /api/agent drives opencode headless as an autonomous investigator. The
    agent is locked down (bash/edit/write/webfetch disabled at the agent level)
    so it can ONLY call the read-only osint_* MCP tools -- a prompt-injected
    objective cannot make it run a shell command or touch the filesystem.

Case data still lives in the browser's localStorage. Agent run dirs are created
under OSF_RUN_DIR (a temp dir by default) and deleted when the run ends, so the
repo stays clean.
"""
from __future__ import annotations

import argparse
import base64
import hmac
import http.server
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

import osint_tools
import workflows

ROOT = Path(__file__).resolve().parent
CERT = ROOT / "cert.pem"
KEY = ROOT / "key.pem"
CRED = ROOT / ".credentials"
MCP = ROOT / "osint_mcp.py"
AGENT_PROMPT = (ROOT / "agent" / "osint.md").read_text(encoding="utf-8") if (ROOT / "agent" / "osint.md").exists() else "You are an OSINT investigator. Use only the osint_* tools."
RUN_ROOT = os.environ.get("OSF_RUN_DIR", tempfile.gettempdir())
AGENT_MODEL = os.environ.get("OSF_AGENT_MODEL", "")  # "" => opencode's configured default (auto-detect)
AGENT_TIMEOUT = int(os.environ.get("OSF_AGENT_TIMEOUT", "300"))  # hard cap on one agent run (s)

NEVER_SERVE = {"key.pem", "cert.pem", ".credentials", "serve.py",
               "osint_tools.py", "workflows.py", "osint_mcp.py"}


def ensure_cert(host: str) -> None:
    """Self-signed cert with the LAN IP in subjectAltName. The SAN matters:
    a certificate carrying only a CN is rejected outright by modern mobile
    browsers, which would make the site unreachable rather than merely warned."""
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
    if CRED.exists():
        user, _, pw = CRED.read_text().strip().partition(":")
        if user and pw:
            return user, pw
    user, pw = "osint", secrets.token_urlsafe(16)
    CRED.write_text(f"{user}:{pw}\n")
    CRED.chmod(0o600)
    return user, pw


# ---------------------------------------------------------------------------
class Handler(http.server.SimpleHTTPRequestHandler):
    user = pw = ""
    protocol_version = "HTTP/1.1"  # keep-alive, needed for SSE

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(ROOT), **kw)

    # --- auth ---
    def _authorised(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            got = base64.b64decode(header[6:]).decode("utf-8", "replace")
        except Exception:
            return False
        return hmac.compare_digest(got, f"{self.user}:{self.pw}")

    def _deny(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="OSINTForge", charset="UTF-8"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    # --- responses ---
    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except (ValueError, TypeError):
            return {}
        if n <= 0 or n > 1_048_576:   # no body, or implausibly large for this API
            return {}
        try:
            d = json.loads(self.rfile.read(n).decode("utf-8"))
            return d if isinstance(d, dict) else {}
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return {}

    def _sse_open(self) -> None:
        # No Content-Length on a stream, so under HTTP/1.1 we must close the
        # connection at the end rather than claim keep-alive — the client reads
        # until EOF. close_connection stops the handler reusing the socket.
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

    def _sse(self, event: str, data) -> bool:
        """Return False if the client has gone away."""
        try:
            payload = data if isinstance(data, str) else json.dumps(data)
            self.wfile.write(f"event: {event}\ndata: {payload}\n\n".encode("utf-8"))
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            return False

    # --- routing ---
    def do_GET(self) -> None:
        if not self._authorised():
            return self._deny()
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"):
            return self._api_get(path)
        if Path(path).name in NEVER_SERVE or Path(path).suffix == ".py" or "/agent/" in path:
            return self.send_error(404)
        super().do_GET()

    def do_HEAD(self) -> None:
        if not self._authorised():
            return self._deny()
        super().do_HEAD()

    def do_POST(self) -> None:
        if not self._authorised():
            return self._deny()
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/"):
            return self._api_post(path)
        self.send_error(404)

    # --- API: GET ---
    def _api_get(self, path: str) -> None:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if path == "/api/health":
            return self._json({"ok": True, "version": "4.0",
                               "tools": list(osint_tools.TOOLS),
                               "workflows": list(workflows.WORKFLOWS)})
        if path == "/api/agent/info":
            return self._json({"available": shutil.which("opencode") is not None,
                               "model": AGENT_MODEL or "auto (opencode default)"})
        if path == "/api/relay":
            url = (qs.get("url") or [""])[0]
            if not url:
                return self._json({"error": "missing url"}, 400)
            try:
                t = max(5, min(60, int((qs.get("timeout") or ["30"])[0])))
            except (ValueError, TypeError):
                t = 30
            try:
                r = osint_tools.safe_fetch(url, timeout=t, max_bytes=osint_tools.MAX_BYTES_LARGE)
                return self._json({"status": r["status"], "text": r["text"],
                                   "final_url": r["final_url"]})
            except osint_tools.BlockedTarget as e:
                return self._json({"error": f"blocked: {e}"}, 400)
            except osint_tools.FetchError as e:
                return self._json({"error": str(e)}, 502)
        if path.startswith("/api/workflow/") and path.endswith("/stream"):
            name = path[len("/api/workflow/"):-len("/stream")]
            args = {}
            try:
                args = json.loads((qs.get("args") or ["{}"])[0])
            except (json.JSONDecodeError, ValueError):
                pass
            return self._stream_workflow(name, args)
        if path == "/api/agent/stream":
            objective = (qs.get("objective") or [""])[0]
            model = (qs.get("model") or [""])[0]
            return self._stream_agent(objective, model)
        self.send_error(404)

    # --- API: POST ---
    def _api_post(self, path: str) -> None:
        body = self._read_body()
        if path.startswith("/api/tool/"):
            name = path[len("/api/tool/"):]
            fn = osint_tools.TOOLS.get(name)
            if not fn:
                return self._json({"error": f"unknown tool {name}"}, 404)
            try:
                return self._json(fn(**body))
            except TypeError as e:
                return self._json({"error": f"bad args: {e}"}, 400)
            except Exception as e:  # noqa: BLE001
                return self._json({"error": str(e)}, 500)
        if path.startswith("/api/workflow/"):
            name = path[len("/api/workflow/"):]
            wf = workflows.WORKFLOWS.get(name)
            if not wf:
                return self._json({"error": f"unknown workflow {name}"}, 404)
            try:
                return self._json(wf["fn"](**{k: v for k, v in body.items() if k in wf["args"]}))
            except Exception as e:  # noqa: BLE001
                return self._json({"error": str(e)}, 500)
        self.send_error(404)

    # --- workflow SSE ---
    def _stream_workflow(self, name: str, args: dict) -> None:
        wf = workflows.WORKFLOWS.get(name)
        if not wf:
            return self._json({"error": f"unknown workflow {name}"}, 404)
        self._sse_open()
        alive = [True]

        def emit(step):
            if alive[0] and not self._sse("step", step):
                alive[0] = False
        try:
            res = wf["fn"](**{k: v for k, v in args.items() if k in wf["args"]}, emit=emit)
            self._sse("result", {"findings": res["findings"], "summary": res.get("summary", {})})
        except Exception as e:  # noqa: BLE001
            self._sse("error", {"message": str(e)})
        self._sse("done", {})

    # --- agent SSE: drive opencode headless ---
    def _stream_agent(self, objective: str, model: str) -> None:
        if not objective.strip():
            return self._json({"error": "missing objective"}, 400)
        if not shutil.which("opencode"):
            return self._json({"error": "opencode not installed"}, 503)
        self._sse_open()
        run_dir = Path(tempfile.mkdtemp(prefix="osf_run_", dir=RUN_ROOT))
        case_file = run_dir / "findings.jsonl"
        case_file.touch()
        (run_dir / "opencode.json").write_text(json.dumps({
            "$schema": "https://opencode.ai/config.json",
            "permission": {"edit": {"*": "deny"}, "bash": {"*": "deny"}, "webfetch": "deny"},
            "mcp": {"osint": {"type": "local", "command": ["python3", str(MCP)],
                              "enabled": True, "environment": {"OSF_CASE_FILE": str(case_file)}}},
            "agent": {"osint": {"description": "Autonomous OSINT investigator",
                                "mode": "primary", "prompt": AGENT_PROMPT,
                                "tools": {k: False for k in ("bash", "edit", "write", "read",
                                          "webfetch", "glob", "grep", "list", "patch")}}},
        }), encoding="utf-8")

        cmd = ["opencode", "run", "--agent", "osint", "--format", "json", "--auto"]
        use_model = model or AGENT_MODEL
        if use_model:
            cmd += ["--model", use_model]
        cmd.append(objective)
        self._sse("start", {"objective": objective, "model": use_model or "auto", "run": run_dir.name})

        stderr_path = run_dir / "stderr.log"
        stderr_f = open(stderr_path, "wb")
        proc = subprocess.Popen(cmd, cwd=str(run_dir), stdout=subprocess.PIPE,
                                stderr=stderr_f, text=True, bufsize=1)
        stderr_f.close()  # the child holds its own dup of the fd

        # Watchdog: a stuck model or a tool loop must not pin the request
        # forever. After AGENT_TIMEOUT the process is terminated.
        killed = {"watchdog": False}

        def _kill():
            if proc.poll() is None:
                killed["watchdog"] = True
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        timer = threading.Timer(AGENT_TIMEOUT, _kill)
        timer.daemon = True
        timer.start()

        offset = 0
        alive = True

        def drain_findings():
            nonlocal offset
            try:
                lines = case_file.read_text(encoding="utf-8").splitlines()
            except OSError:
                return True
            for ln in lines[offset:]:
                offset += 1
                if ln.strip():
                    try:
                        if not self._sse("finding", json.loads(ln)):
                            return False
                    except json.JSONDecodeError:
                        pass
            return True

        try:
            for line in proc.stdout:  # raw opencode JSON events, streamed live
                if line.strip() and not self._sse("agent", line.strip()):
                    alive = False
                    break
                if not drain_findings():
                    alive = False
                    break
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if alive:
                drain_findings()
                rc = proc.returncode
                if killed["watchdog"]:
                    self._sse("error", {"message": f"agent run exceeded {AGENT_TIMEOUT}s and was stopped"})
                elif rc not in (0, None):
                    try:
                        err = stderr_path.read_text("utf-8", "replace")[-600:]
                    except OSError:
                        err = ""
                    self._sse("error", {"message": f"agent exited with code {rc}",
                                        "detail": err or "(no stderr — is opencode logged in? check `opencode providers`)"})
                self._sse("done", {"exit": rc})
            shutil.rmtree(run_dir, ignore_errors=True)

    # --- headers / logging ---
    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        if "Cache-Control" not in self._headers_buffer_keys():
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _headers_buffer_keys(self) -> set:
        keys = set()
        for raw in getattr(self, "_headers_buffer", []):
            try:
                line = raw.decode("latin-1")
            except Exception:
                continue
            if ":" in line:
                keys.add(line.split(":", 1)[0])
        return keys

    def log_message(self, fmt: str, *args) -> None:
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

    agent = "available" if shutil.which("opencode") else "not installed"
    print(f"OSINTForge  https://{args.host}:{args.port}/")
    print(f"  user      {user}")
    print(f"  password  {pw}")
    print(f"  api       /api/health · /api/relay · /api/tool · /api/workflow · /api/agent")
    print(f"  agent     opencode {agent} · model {AGENT_MODEL or 'auto (opencode default)'}")
    print("  (self-signed cert — your phone will warn once; accept it)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
