#!/usr/bin/env python3
"""Minimal stdio MCP server exposing OSINTForge tools to opencode.

opencode (the agent runtime) connects to this over stdio and can call any
OSINT primitive or workflow as a tool. This is deliberately a from-scratch
JSON-RPC/MCP implementation (stdlib only) so the project keeps its zero-dep,
nothing-installed ethos — opencode speaks MCP, this answers it.

Transport: MCP stdio = newline-delimited JSON-RPC 2.0. stdout is the protocol
channel and must carry nothing else; all logging goes to stderr.

Side effect: every tool call also appends its findings (one JSON object per
line) to the case file named by $OSF_CASE_FILE, so the backend can tail the
agent's discoveries and stream them into the live graph as they happen.
"""
from __future__ import annotations

import json
import os
import sys
import time

import osint_tools as T
import workflows as W

PROTO = "2025-06-18"
CASE_FILE = os.environ.get("OSF_CASE_FILE")


def log(*a):
    print("[osint-mcp]", *a, file=sys.stderr, flush=True)


def _schema(props: dict, required: list[str]) -> dict:
    return {"type": "object",
            "properties": {k: {"type": "string", "description": v} for k, v in props.items()},
            "required": required}


# Tool catalogue: primitives + workflows, each with a JSON input schema.
TOOL_DEFS: list[dict] = [
    {"name": "username_sweep",
     "description": "Probe ~37 platforms for a username and return confirmed accounts with per-site evidence and confidence.",
     "inputSchema": _schema({"username": "handle to probe, without @"}, ["username"])},
    {"name": "email_intel",
     "description": "Investigate an email: gravatar identity, MX/SPF/DMARC health, GitHub commit attribution, Proton key, disposable detection, derived handles.",
     "inputSchema": _schema({"email": "target email address", "name": "optional real name for permutations"}, ["email"])},
    {"name": "domain_dns",
     "description": "RDAP registration + live DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA/CAA) for a domain.",
     "inputSchema": _schema({"domain": "domain name"}, ["domain"])},
    {"name": "domain_ct",
     "description": "Certificate-transparency subdomain enumeration via crt.sh.",
     "inputSchema": _schema({"domain": "apex domain"}, ["domain"])},
    {"name": "domain_wayback",
     "description": "Wayback CDX recon: historical subdomains, archived sensitive files, and secrets scraped from snapshots.",
     "inputSchema": _schema({"domain": "domain name"}, ["domain"])},
    {"name": "ip_intel",
     "description": "Geo/ASN/PTR for an IP plus reputation link-outs (Shodan, GreyNoise, AbuseIPDB, VirusTotal).",
     "inputSchema": _schema({"ip": "IPv4 or IPv6 address"}, ["ip"])},
    {"name": "web_search",
     "description": "Server-side DuckDuckGo search; returns de-duplicated result URLs with titles.",
     "inputSchema": _schema({"query": "search query (dork syntax allowed)"}, ["query"])},
    {"name": "phone_parse",
     "description": "E.164 validation and country attribution for a phone number.",
     "inputSchema": _schema({"number": "phone number in any format"}, ["number"])},
    {"name": "generate_dorks",
     "description": "Generate categorised advanced search dorks (files, creds, cloud buckets, code, infra, paste sites, leaks) for a target. kind auto-detects from the target.",
     "inputSchema": _schema({"target": "domain / name / username / email / ip",
                             "kind": "optional: domain|name|username|email|ip (default auto)",
                             "city": "optional city (name dorks)", "org": "optional org (infra dorks)"}, ["target"])},
    # workflows
    {"name": "wf_handle_profile",
     "description": "WORKFLOW: full identity profile for a handle — sweep, dossier, mine emails, email-intel each, re-sweep derived handles.",
     "inputSchema": _schema({"username": "handle"}, ["username"])},
    {"name": "wf_domain_surface",
     "description": "WORKFLOW: full domain attack-surface scan — RDAP+DNS, CT subdomains, Wayback secrets/files, merged.",
     "inputSchema": _schema({"domain": "domain name"}, ["domain"])},
    {"name": "wf_email_identity",
     "description": "WORKFLOW: email → identity — email intel then sweep every derived handle.",
     "inputSchema": _schema({"email": "email address", "name": "optional real name"}, ["email"])},
    {"name": "wf_person_search",
     "description": "WORKFLOW: broad person pivot — dorked web search across selectors + handle sweep + email-intel. Give any of name/city/username/email.",
     "inputSchema": _schema({"name": "full name", "city": "city", "username": "handle", "email": "email"}, [])},
]


def _dispatch(name: str, args: dict) -> dict:
    if name in T.TOOLS:
        return T.TOOLS[name](**args)
    if name == "wf_handle_profile":
        return W.handle_profile(args["username"])
    if name == "wf_domain_surface":
        return W.domain_surface(args["domain"])
    if name == "wf_email_identity":
        return W.email_identity(args["email"], args.get("name", ""))
    if name == "wf_person_search":
        return W.person_search(args.get("name", ""), args.get("city", ""),
                               args.get("username", ""), args.get("email", ""))
    raise KeyError(f"unknown tool {name}")


def _persist(name: str, res: dict) -> None:
    if not CASE_FILE:
        return
    try:
        with open(CASE_FILE, "a", encoding="utf-8") as fh:
            for f in res.get("findings", []):
                fh.write(json.dumps({**f, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                     "source": f"agent:{name}"}) + "\n")
    except OSError as e:
        log("persist failed:", e)


def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id, code, msg):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": msg}}


def handle(msg: dict):
    method = msg.get("method")
    req_id = msg.get("id")
    if method == "initialize":
        proto = (msg.get("params") or {}).get("protocolVersion", PROTO)
        return _result(req_id, {"protocolVersion": proto,
                                "capabilities": {"tools": {"listChanged": False}},
                                "serverInfo": {"name": "osintforge", "version": "4.0"}})
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return _result(req_id, {})
    if method == "tools/list":
        return _result(req_id, {"tools": TOOL_DEFS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            res = _dispatch(name, args)
            _persist(name, res)
            # summarise for the model: counts + the findings themselves
            text = json.dumps({"tool": name, "found": len(res.get("findings", [])),
                               "summary": res.get("summary") or res.get("meta", {}),
                               "findings": res.get("findings", [])}, indent=1)
            return _result(req_id, {"content": [{"type": "text", "text": text}],
                                    "isError": False})
        except Exception as e:  # noqa: BLE001
            return _result(req_id, {"content": [{"type": "text", "text": f"error: {e}"}],
                                    "isError": True})
    if req_id is not None:
        return _error(req_id, -32601, f"method not found: {method}")
    return None


def main() -> int:
    log("ready;", len(TOOL_DEFS), "tools; case file:", CASE_FILE or "(none)")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            resp = handle(msg)
        except Exception as e:  # noqa: BLE001
            resp = _error(msg.get("id"), -32603, str(e))
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
