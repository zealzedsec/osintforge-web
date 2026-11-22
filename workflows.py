#!/usr/bin/env python3
"""Deterministic OSINT workflows — one-click multi-step investigations.

A *workflow* chains the primitives in osint_tools, auto-pivots on what the
earlier steps discover (a handle's committed email becomes an email-intel run;
a dossier's alternate handle becomes another sweep), de-duplicates, and emits
progress so the UI/agent can draw a live timeline.

These are the "scans / automations" layer: fast, no LLM, reproducible. The
agent (opencode) can call them as high-level tools, or a human can fire one
from the Workflows panel. Every workflow returns:
    {"findings": [...], "steps": [{name,status,detail,count}], "summary": {...}}
and, if given an `emit` callback, streams each step as it completes.
"""
from __future__ import annotations

import re
from typing import Callable

import osint_tools as T

Emit = Callable[[dict], None] | None
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


def _dedupe(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in findings:
        k = (f.get("kind"), f.get("url", ""), f.get("title", ""))
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def _run(name: str, emit: Emit, fn, *a, **k) -> dict:
    """Execute one tool, record a step, stream it. Never let one failed step
    abort the workflow — a dead relay on step 3 shouldn't lose steps 1–2."""
    if emit:
        emit({"name": name, "status": "running"})
    try:
        res = fn(*a, **k)
        n = len(res.get("findings", []))
        step = {"name": name, "status": "done", "count": n,
                "detail": _summarize(res.get("meta", {}))}
    except Exception as e:  # noqa: BLE001
        res = {"findings": [], "meta": {"error": str(e)}}
        step = {"name": name, "status": "error", "count": 0, "detail": str(e)[:80]}
    if emit:
        emit({**step, "status_final": True})
    res["_step"] = step
    return res


def _summarize(meta: dict) -> str:
    if "error" in meta:
        return "error: " + str(meta["error"])[:60]
    bits = []
    for k in ("hits", "probed", "subdomains", "count", "handles"):
        if k in meta:
            v = meta[k]
            bits.append(f"{k}={len(v) if isinstance(v,list) else v}")
    return " · ".join(bits)


# ---------------------------------------------------------------------------
def handle_profile(username: str, emit: Emit = None, depth: int = 1) -> dict:
    """Full identity sweep for a handle: probe all platforms, compile a dossier
    across identity APIs, mine any committed/self-published emails, then run
    email-intel on each discovered address and re-sweep derived handles."""
    u = username.strip().lstrip("@")
    findings: list[dict] = []
    steps: list[dict] = []

    r = _run("username sweep", emit, T.username_sweep, u)
    findings += r["findings"]; steps.append(r["_step"])

    # emails surfaced by the sweep's dossier-grade sources, plus git attribution
    emails: set[str] = set()
    handles: set[str] = set()
    for f in findings:
        emails.update(_EMAIL_RE.findall(f.get("title", "") + " " + f.get("detail", "")))
        if f.get("kind") == "derived_username":
            m = re.search(r"Derived handle:\s*(\S+)", f.get("title", ""))
            if m:
                handles.add(m.group(1))

    # pull a GitHub email if the handle exists there (common identity anchor)
    gh = T.fetch_json(f"https://api.github.com/users/{u}")
    if gh and gh.get("login"):
        if gh.get("email"):
            emails.add(gh["email"])
        name = gh.get("name")
        if name:
            findings.append(T._finding("dossier", "canonical_name", f"Likely real name: {name}",
                                       gh.get("html_url", ""), "GitHub profile name", "med"))

    if depth >= 1:
        for em in list(emails)[:3]:
            r = _run(f"email intel · {em}", emit, T.email_intel, em)
            findings += r["findings"]; steps.append(r["_step"])
            handles.update(h for h in _derived_handles(r["findings"]))

    if depth >= 2:
        for h in list(handles - {u})[:3]:
            r = _run(f"re-sweep · {h}", emit, T.username_sweep, h)
            findings += r["findings"]; steps.append(r["_step"])

    findings = _dedupe(findings)
    summary = {"target": u, "accounts": sum(1 for f in findings if f["kind"] == "profile"),
               "emails": sorted(emails), "derived_handles": sorted(handles)}
    return {"findings": findings, "steps": steps, "summary": summary}


def _derived_handles(findings: list[dict]) -> set[str]:
    out = set()
    for f in findings:
        if f.get("kind") == "derived_username":
            m = re.search(r"Derived handle:\s*(\S+)", f.get("title", ""))
            if m:
                out.add(m.group(1))
        if f.get("kind") == "derived_handles":
            m = re.search(r"candidates:\s*(.+)", f.get("title", ""))
            if m:
                out.update(x.strip() for x in m.group(1).split(","))
    return out


def domain_surface(domain: str, emit: Emit = None) -> dict:
    """Attack-surface scan for a domain: registration + live DNS, full CT
    subdomain enumeration, and Wayback recon (historical hosts, archived
    secrets, sensitive files). The merged subdomain set is the deliverable."""
    d = T._clean_domain(domain)
    findings, steps = [], []
    for name, fn in (("DNS / RDAP", T.domain_dns),
                     ("CT subdomains", T.domain_ct),
                     ("Wayback recon", T.domain_wayback)):
        r = _run(name, emit, fn, d)
        findings += r["findings"]; steps.append(r["_step"])
    findings = _dedupe(findings)
    subs = sorted({f["title"] for f in findings if f["kind"] in ("ct_subdomain", "wb_subdomain")})
    secrets = [f for f in findings if f["kind"] == "wb_secret"]
    summary = {"domain": d, "subdomains": subs, "subdomain_count": len(subs),
               "secrets_found": len(secrets)}
    return {"findings": findings, "steps": steps, "summary": summary}


def email_identity(email: str, name: str = "", emit: Emit = None) -> dict:
    """Email → identity: mail health + gravatar + git attribution, then sweep
    every handle the address implies to find the person's account footprint."""
    findings, steps = [], []
    r = _run("email intel", emit, T.email_intel, email, name)
    findings += r["findings"]; steps.append(r["_step"])
    handles = list(_derived_handles(findings))[:4]
    for h in handles:
        r = _run(f"sweep · {h}", emit, T.username_sweep, h)
        findings += r["findings"]; steps.append(r["_step"])
    findings = _dedupe(findings)
    summary = {"email": email, "handles_tried": handles,
               "accounts": sum(1 for f in findings if f["kind"] == "profile")}
    return {"findings": findings, "steps": steps, "summary": summary}


def person_search(name: str = "", city: str = "", username: str = "",
                  email: str = "", emit: Emit = None) -> dict:
    """Broad person pivot: dorked web search across selectors, a handle sweep
    if a username is given, and email-intel if an address is given."""
    findings, steps = [], []
    selector = (name or username or email).strip()
    if not selector:
        return {"findings": [], "steps": [], "summary": {"error": "no selector provided"}}
    dorks = [selector]
    if name:
        dorks += [f'"{name}" (profile OR resume OR contact)',
                  f'site:linkedin.com/in "{name}"']
        if city:
            dorks.append(f'"{name}" "{city}"')
    if username:
        dorks.append(f'(site:reddit.com OR site:github.com OR site:keybase.io) "{username}"')
    if email:
        dorks.append(f'"{email}"')
    for q in dorks[:4]:
        r = _run(f"web · {q[:40]}", emit, T.web_search, q)
        findings += r["findings"]; steps.append(r["_step"])
    if username:
        r = _run("handle sweep", emit, T.username_sweep, username)
        findings += r["findings"]; steps.append(r["_step"])
    if email:
        r = _run("email intel", emit, T.email_intel, email, name)
        findings += r["findings"]; steps.append(r["_step"])
    findings = _dedupe(findings)
    return {"findings": findings, "steps": steps,
            "summary": {"selector": selector, "total": len(findings)}}


WORKFLOWS: dict[str, dict] = {
    "handle_profile": {"fn": handle_profile, "label": "Full Handle Profile",
                       "args": ["username"], "about": "Sweep → dossier → mine emails → email-intel → re-sweep"},
    "domain_surface": {"fn": domain_surface, "label": "Domain Attack-Surface Scan",
                       "args": ["domain"], "about": "RDAP+DNS → CT subdomains → Wayback secrets/files"},
    "email_identity": {"fn": email_identity, "label": "Email → Identity",
                       "args": ["email", "name"], "about": "Mail health + gravatar + git attribution → handle sweeps"},
    "person_search": {"fn": person_search, "label": "Person Search",
                      "args": ["name", "city", "username", "email"], "about": "Dorked web search + sweep + email-intel"},
}
