#!/usr/bin/env python3
"""Server-side OSINT primitives for ThatOsintMe.

Why this file exists
--------------------
The original console did every cross-origin fetch through *public* CORS relays
(allorigins.win / corsproxy.io). That leaks the one thing an intelligence
console must never leak: the target of the investigation. Every probed URL —
which encodes *who* you are looking at — was handed to an untrusted third party.
serve.py's own threat model forbids exactly that for web fonts, yet the relays
did it on every query.

Moving the fetch here fixes three things at once:
  * Privacy / OPSEC — traffic leaves from *your* host, not a stranger's relay.
  * Reliability — no third-party rate limits or truncated responses
    (crt.sh and the Wayback CDX were the worst-hit).
  * Capability — the browser same-origin wall no longer blocks anything, so
    tools that were impossible client-side (reliable body inspection, holehe-
    style checks) become possible.

Security note — this module makes outbound requests to URLs the caller supplies,
so it is an SSRF surface by definition. `safe_fetch` is the only door out, and
it refuses non-public destinations (loopback, RFC1918, link-local incl. the
cloud-metadata address, reserved/multicast), caps body size and time, and
re-validates every redirect hop. Residual DNS-rebinding risk is accepted for a
single-user LAN tool and noted at the call site.

Pure functions. No global state, no secrets on disk. Each tool returns
{"findings": [ {module,kind,title,url,detail,confidence}, ... ], "meta": {...}}.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterable

# --- limits -----------------------------------------------------------------
UA = "ThatOsintMe/4 (+local; research)"
DEFAULT_TIMEOUT = 15
MAX_BYTES = 8 * 1024 * 1024           # 8 MiB default cap on any single response
MAX_BYTES_LARGE = 64 * 1024 * 1024    # for crt.sh / Wayback CDX, which can be huge
MAX_REDIRECTS = 5
POOL = 8                               # default fan-out for parallel probes


# --- SSRF guard -------------------------------------------------------------
class FetchError(Exception):
    pass


class BlockedTarget(FetchError):
    """Raised when a URL resolves to a non-public address."""


def _ip_is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # is_global is the authoritative check; the rest are belt-and-braces and
    # make the intent legible. 169.254.169.254 is covered by is_link_local.
    if a.is_private or a.is_loopback or a.is_link_local or a.is_multicast:
        return False
    if a.is_reserved or a.is_unspecified:
        return False
    return a.is_global


def _host_resolves_public(host: str) -> bool:
    """Every A/AAAA record for host must be public, or we refuse the fetch.
    An attacker who can point a hostname at 127.0.0.1 or 169.254.169.254 must
    not be able to make this box fetch its own internal services."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise BlockedTarget(f"cannot resolve {host}")
    addrs = {i[4][0] for i in infos}
    if not addrs:
        raise BlockedTarget(f"no address for {host}")
    bad = [ip for ip in addrs if not _ip_is_public(ip)]
    if bad:
        raise BlockedTarget(f"{host} resolves to non-public address {bad[0]}")
    return True


def _validate(url: str) -> urllib.parse.ParseResult:
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        raise BlockedTarget(f"scheme {p.scheme!r} not allowed")
    if not p.hostname:
        raise BlockedTarget("no host in URL")
    _host_resolves_public(p.hostname)
    return p


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # we handle redirects by hand so each hop is re-validated


_opener = urllib.request.build_opener(_NoRedirect)


def safe_fetch(url: str, *, method: str = "GET", timeout: int = DEFAULT_TIMEOUT,
               headers: dict | None = None, data: bytes | None = None,
               max_bytes: int = MAX_BYTES) -> dict:
    """The single outbound door. Returns {status, text, final_url, headers}.
    Raises BlockedTarget for non-public destinations, FetchError otherwise."""
    hop = url
    for _ in range(MAX_REDIRECTS + 1):
        _validate(hop)
        req = urllib.request.Request(hop, method=method, data=data, headers={
            "User-Agent": UA,
            "Accept": "application/json, text/html;q=0.9, */*;q=0.8",
            **(headers or {}),
        })
        try:
            resp = _opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location") if e.headers else None
            if e.code in (301, 302, 303, 307, 308) and loc:
                hop = urllib.parse.urljoin(hop, loc)  # re-validated next loop
                continue
            body = b""
            try:
                body = e.read(max_bytes + 1)
            except Exception:
                pass
            return {"status": e.code, "text": _decode(body, max_bytes),
                    "final_url": hop, "headers": dict(e.headers or {})}
        except urllib.error.URLError as e:
            raise FetchError(str(getattr(e, "reason", e)))
        except (TimeoutError, socket.timeout):
            raise FetchError("timeout")
        raw = resp.read(max_bytes + 1)
        return {"status": resp.status, "text": _decode(raw, max_bytes),
                "final_url": resp.url, "headers": dict(resp.headers)}
    raise FetchError("too many redirects")


def _decode(raw: bytes, max_bytes: int) -> str:
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    return raw.decode("utf-8", "replace")


def fetch_json(url: str, **kw) -> Any:
    r = safe_fetch(url, **kw)
    try:
        return json.loads(r["text"])
    except (json.JSONDecodeError, ValueError):
        return None


def doh(name: str, rtype: str) -> Any:
    return fetch_json(
        f"https://dns.google/resolve?name={urllib.parse.quote(name)}&type={rtype}")


def _pool(items: Iterable, fn: Callable, workers: int = POOL) -> list:
    items = list(items)
    out: list = [None] * len(items)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, max(1, len(items)))) as ex:
        futs = {ex.submit(fn, it): i for i, it in enumerate(items)}
        for f in concurrent.futures.as_completed(futs):
            i = futs[f]
            try:
                out[i] = f.result()
            except Exception as e:  # noqa: BLE001 — one bad probe must not sink the batch
                out[i] = {"error": str(e)}
    return out


def _finding(module, kind, title, url="", detail="", confidence="med") -> dict:
    return {"module": module, "kind": kind, "title": title, "url": url,
            "detail": detail, "confidence": confidence}


# ---------------------------------------------------------------------------
# Username sweep — data-driven, with real per-site detection (server-side, so
# response bodies are actually readable; no same-origin wall, no soft-404 lies).
# Each site: name, probe URL template {u}, and a detector describing a HIT.
#   exists:  "status"   HIT = probe status == 200
#            "json:<s>"  HIT = status 200 and substring <s> in body
#            "absent:<re>"  HIT = status 200 and regex NOT found (soft-404 text)
#            "present:<re>" HIT = status 200 and regex found
# `profile` is the human-facing URL. `norm` optionally lowercases etc.
# ---------------------------------------------------------------------------
SWEEP_SITES: list[dict] = [
    {"n": "GitHub", "u": "https://api.github.com/users/{u}", "d": 'json:"login"', "p": "https://github.com/{u}"},
    {"n": "GitLab", "u": "https://gitlab.com/api/v4/users?username={u}", "d": 'present:"id":', "p": "https://gitlab.com/{u}"},
    {"n": "Bitbucket", "u": "https://api.bitbucket.org/2.0/users/{u}", "d": 'json:"account_id"', "p": "https://bitbucket.org/{u}"},
    {"n": "Reddit", "u": "https://www.reddit.com/user/{u}/about.json", "d": 'json:"t2_"', "p": "https://www.reddit.com/user/{u}/"},
    {"n": "HackerNews", "u": "https://hacker-news.firebaseio.com/v0/user/{u}.json", "d": "absent:^null$", "p": "https://news.ycombinator.com/user?id={u}"},
    {"n": "Mastodon.social", "u": "https://mastodon.social/api/v1/accounts/lookup?acct={u}", "d": 'json:"username"', "p": "https://mastodon.social/@{u}"},
    {"n": "Bluesky", "u": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social", "d": 'json:"did"', "p": "https://bsky.app/profile/{u}.bsky.social"},
    {"n": "Lichess", "u": "https://lichess.org/api/user/{u}", "d": 'json:"id"', "p": "https://lichess.org/@/{u}"},
    {"n": "Chess.com", "u": "https://api.chess.com/pub/player/{u}", "d": 'json:"player_id"', "p": "https://www.chess.com/member/{u}", "norm": "lower"},
    {"n": "NPM", "u": "https://registry.npmjs.org/-/user/org.couchdb.user:{u}", "d": 'json:"_id"', "p": "https://www.npmjs.com/~{u}"},
    {"n": "DockerHub", "u": "https://hub.docker.com/v2/users/{u}/", "d": 'json:"username"', "p": "https://hub.docker.com/u/{u}"},
    {"n": "Crates.io", "u": "https://crates.io/api/v1/users/{u}", "d": 'json:"login"', "p": "https://crates.io/users/{u}"},
    {"n": "Keybase", "u": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", "d": 'present:"status":\\s*\\{\\s*"code":\\s*0', "p": "https://keybase.io/{u}"},
    {"n": "Mixcloud", "u": "https://api.mixcloud.com/{u}/", "d": 'json:"username"', "p": "https://www.mixcloud.com/{u}/"},
    {"n": "Scratch", "u": "https://api.scratch.mit.edu/users/{u}", "d": 'json:"username"', "p": "https://scratch.mit.edu/users/{u}"},
    {"n": "Lemmy.world", "u": "https://lemmy.world/api/v3/user?username={u}", "d": 'json:"person"', "p": "https://lemmy.world/u/{u}"},
    {"n": "Trello", "u": "https://trello.com/1/Members/{u}?fields=username", "d": 'json:"username"', "p": "https://trello.com/{u}"},
    {"n": "Duolingo", "u": "https://www.duolingo.com/2017-06-30/users?username={u}&fields=id", "d": 'present:"id":\\s*\\d', "p": "https://www.duolingo.com/profile/{u}"},
    {"n": "Telegram", "u": "https://t.me/{u}", "d": "present:tgme_page_title|tg://resolve", "p": "https://t.me/{u}"},
    {"n": "Gravatar", "u": "https://en.gravatar.com/{u}.json", "d": 'json:"entry"', "p": "https://gravatar.com/{u}"},
    {"n": "Medium", "u": "https://medium.com/@{u}", "d": "status", "p": "https://medium.com/@{u}"},
    {"n": "Dev.to", "u": "https://dev.to/{u}", "d": "absent:(?i)this page does not exist", "p": "https://dev.to/{u}"},
    {"n": "GitHubGist", "u": "https://api.github.com/users/{u}/gists", "d": "present:^\\[", "p": "https://gist.github.com/{u}"},
    {"n": "Pypi", "u": "https://pypi.org/user/{u}/", "d": "status", "p": "https://pypi.org/user/{u}/"},
    {"n": "Steam", "u": "https://steamcommunity.com/id/{u}?xml=1", "d": "present:<steamID>", "p": "https://steamcommunity.com/id/{u}"},
    {"n": "Twitch", "u": "https://www.twitch.tv/{u}", "d": "absent:(?i)sorry\\. unless you", "p": "https://www.twitch.tv/{u}"},
    {"n": "SoundCloud", "u": "https://soundcloud.com/{u}", "d": "status", "p": "https://soundcloud.com/{u}"},
    {"n": "Last.fm", "u": "https://www.last.fm/user/{u}", "d": "status", "p": "https://www.last.fm/user/{u}"},
    {"n": "Vimeo", "u": "https://vimeo.com/{u}", "d": "status", "p": "https://vimeo.com/{u}"},
    {"n": "About.me", "u": "https://about.me/{u}", "d": "status", "p": "https://about.me/{u}"},
    {"n": "Patreon", "u": "https://www.patreon.com/{u}", "d": "status", "p": "https://www.patreon.com/{u}"},
    {"n": "Wattpad", "u": "https://www.wattpad.com/user/{u}", "d": "status", "p": "https://www.wattpad.com/user/{u}"},
    {"n": "Kickstarter", "u": "https://www.kickstarter.com/profile/{u}", "d": "status", "p": "https://www.kickstarter.com/profile/{u}"},
    {"n": "Tumblr", "u": "https://{u}.tumblr.com/", "d": "status", "p": "https://{u}.tumblr.com/", "raw": True},
    {"n": "Substack", "u": "https://{u}.substack.com/", "d": "status", "p": "https://{u}.substack.com/", "raw": True},
    {"n": "Replit", "u": "https://replit.com/@{u}", "d": "status", "p": "https://replit.com/@{u}"},
    {"n": "Pinterest", "u": "https://www.pinterest.com/{u}/", "d": "status", "p": "https://www.pinterest.com/{u}/"},
]


def _matches(detector: str, status: int, text: str) -> bool:
    if detector == "status":
        return status == 200
    kind, _, arg = detector.partition(":")
    if status != 200:
        return False
    if kind == "json":
        return arg in text
    if kind == "present":
        return re.search(arg, text) is not None
    if kind == "absent":
        return re.search(arg, text) is None
    return False


def username_sweep(username: str, sites: list[dict] | None = None,
                   workers: int = POOL) -> dict:
    """Probe many platforms for a username. Returns confirmed/soft hits with
    per-site evidence. Confidence reflects detector strength: JSON/regex body
    matches are 'high', bare status-200 is 'low' (soft-404 prone)."""
    u = username.strip().lstrip("@")
    sites = sites or SWEEP_SITES
    # Reject whitespace / path / query chars: these would break the raw-subdomain
    # templates (tumblr/substack) and are never valid handles anyway.
    if not u or len(u) > 64 or re.search(r"[\s/\\?#%]", u):
        return {"findings": [], "meta": {"error": "invalid username"}}

    def probe(s: dict) -> dict | None:
        raw = u.lower() if s.get("norm") == "lower" else u
        enc = raw if s.get("raw") else urllib.parse.quote(raw, safe="")
        target = s["u"].replace("{u}", enc)
        try:
            r = safe_fetch(target, timeout=12)
        except FetchError:
            return {"n": s["n"], "state": "err"}
        hit = _matches(s["d"], r["status"], r["text"])
        if not hit:
            return {"n": s["n"], "state": "miss"}
        strong = s["d"] != "status"
        return {"n": s["n"], "state": "hit", "strong": strong,
                "profile": s["p"].replace("{u}", raw)}

    results = _pool(sites, probe, workers)
    findings = []
    hits = 0
    for r in results:
        if not r or r.get("state") != "hit":
            continue
        hits += 1
        conf = "high" if r.get("strong") else "low"
        detail = "verified via API/body signature" if r.get("strong") else "status-200 only (verify — soft-404 prone)"
        findings.append(_finding("username", "profile",
                                 f"{r['n']}: @{u}", r["profile"], detail, conf))
    return {"findings": findings,
            "meta": {"username": u, "probed": len(sites), "hits": hits}}


# ---------------------------------------------------------------------------
# Email intel — gravatar (sha256 + md5), DoH mail health, GitHub commit
# attribution, Proton HKP key disclosure, disposable detection, permutations.
# All account-existence checks here are read-only public lookups; nothing
# triggers a password-reset or an email to the target.
# ---------------------------------------------------------------------------
import hashlib

DISPOSABLE = {"mailinator.com", "tempmail.com", "temp-mail.org", "guerrillamail.com",
              "10minutemail.com", "yopmail.com", "sharklasers.com", "getnada.com",
              "dispostable.com", "fakeinbox.com", "throwawaymail.com", "maildrop.cc",
              "mintemail.com", "spamgourmet.com", "mytemp.email", "tmpmail.org"}


def email_intel(email: str, name: str = "") -> dict:
    email = email.strip().lower()
    if "@" not in email:
        return {"findings": [], "meta": {"error": "invalid email"}}
    dom = email.split("@", 1)[1]
    out: list[dict] = []
    md5 = hashlib.md5(email.encode()).hexdigest()
    sha = hashlib.sha256(email.encode()).hexdigest()
    out.append(_finding("email", "hash", f"Gravatar hash (sha256) {sha}", "",
                        f"md5 {md5} · interop for gravatar/NCII lists", "high"))
    if dom in DISPOSABLE:
        out.append(_finding("email", "disposable_domain",
                            f"{dom} is a disposable/burner domain", "",
                            "identity assurance low", "high"))

    # mail health
    mx = doh(dom, "MX")
    if mx and mx.get("Answer"):
        hosts = ", ".join(a["data"] for a in mx["Answer"][:3])
        out.append(_finding("email", "mx", f"MX alive: {hosts}", "", "domain accepts mail", "high"))
    else:
        out.append(_finding("email", "mx", f"No MX for {dom}", "", "domain likely cannot receive mail", "high"))
    txt = doh(dom, "TXT")
    if txt and txt.get("Answer"):
        spf = next((a["data"] for a in txt["Answer"] if "v=spf1" in a["data"]), None)
        if spf:
            out.append(_finding("email", "spf", f"SPF: {spf.strip(chr(34))[:120]}", "", "", "med"))
    dmarc = doh("_dmarc." + dom, "TXT")
    if dmarc and dmarc.get("Answer"):
        dm = next((a["data"] for a in dmarc["Answer"] if "DMARC1" in a["data"]), None)
        if dm:
            out.append(_finding("email", "dmarc", f"DMARC: {dm.strip(chr(34))[:120]}", "", "", "med"))

    # gravatar profile (sha256 is the modern primary; md5 still resolves)
    g = fetch_json(f"https://en.gravatar.com/{sha}.json") or fetch_json(f"https://en.gravatar.com/{md5}.json")
    if g and g.get("entry"):
        e = g["entry"][0]
        out.append(_finding("email", "gravatar", f"Gravatar profile: {e.get('displayName') or email}",
                            e.get("profileUrl", ""), "public identity hub", "high"))
        for a in (e.get("accounts") or [])[:20]:
            out.append(_finding("email", "linked_account",
                                f"{a.get('shortname','service')}: {a.get('username','')}",
                                a.get("url", ""), "verified linked service on gravatar", "high"))
        for x in (e.get("emails") or []):
            out.append(_finding("email", "alt_email", f"Alternate email: {x.get('value')}", "",
                                "self-disclosed on gravatar", "high"))

    # github commit attribution → derived handles
    gh = fetch_json(f"https://api.github.com/search/commits?q=author-email:{urllib.parse.quote(email)}",
                    headers={"Accept": "application/vnd.github.cloak-preview+json"})
    if gh and gh.get("total_count"):
        logins = sorted({i["author"]["login"] for i in (gh.get("items") or [])
                         if i.get("author") and i["author"].get("login")})
        out.append(_finding("email", "github_attribution",
                            f"GitHub account(s): {', '.join(logins) or 'see search'}",
                            f"https://github.com/search?q=author-email%3A{urllib.parse.quote(email)}&type=commits",
                            f"{gh['total_count']} public commit(s) with this email", "high"))
        for l in logins:
            out.append(_finding("username", "derived_username", f"Derived handle: {l}",
                                f"https://github.com/{l}", "from email commit attribution", "high"))

    # Proton HKP key disclosure
    if re.search(r"(proton\.me|protonmail\.com)$", dom):
        try:
            r = safe_fetch(f"https://api.protonmail.ch/pks/lookup?op=get&search={urllib.parse.quote(email)}")
            if "BEGIN PGP PUBLIC KEY" in r["text"]:
                out.append(_finding("email", "pgp", "Public PGP key published (Proton HKP)",
                                    r["final_url"], "key presence confirms account at lookup time", "high"))
        except FetchError:
            pass

    # permutations + derived handles
    if name:
        parts = name.lower().split()
        f, l = parts[0], parts[-1]
        pats = [f"{f}.{l}", f"{f}{l}", f"{f[0]}{l}", f"{f}_{l}", f"{f}.{l[0]}", f"{l}{f}", f"{f}-{l}"]
        perms = sorted({f"{p}@{d}" for p in pats for d in ("gmail.com", "outlook.com", "proton.me")})
        out.append(_finding("email", "permutations", f"{len(perms)} candidate addresses",
                            "", " · ".join(perms[:10]) + " …", "low"))
    lp = email.split("@")[0]
    handles = list(dict.fromkeys([lp, re.sub(r"[._-]+", "", lp)] +
                                 [p for p in re.split(r"[._-]+", lp) if len(p) > 2]))[:6]
    out.append(_finding("email", "derived_handles", f"Handle candidates: {', '.join(handles)}",
                        "", "from local-part segmentation", "med"))
    out.append(_finding("email", "email_exposed", f"Target email: {email}", "", "input entity", "high"))
    out.append(_finding("email", "breach_check", "HaveIBeenPwned (manual)",
                        f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}",
                        "defensive breach lookup", "low"))
    return {"findings": out, "meta": {"email": email, "domain": dom, "handles": handles}}


# ---------------------------------------------------------------------------
# Domain intel — RDAP + DoH records + crt.sh CT subdomains + Wayback recon.
# ---------------------------------------------------------------------------
_SECRET_PATTERNS = [
    ("AWS access key", r"AKIA[0-9A-Z]{16}"),
    ("GitHub token", r"gh[pousr]_[A-Za-z0-9]{20,}"),
    ("Google API key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("Slack token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("Stripe key", r"sk_live_[0-9a-zA-Z]{24,}"),
]
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
_WB_SENSITIVE = re.compile(
    r"\.(env|sql|bak|zip|tar\.gz|tgz|xlsx?|docx?|pdf|ya?ml|json|conf|ini|log|csv|key|pem|old|orig)(\?|$)", re.I)


def domain_dns(domain: str) -> dict:
    d = _clean_domain(domain)
    out: list[dict] = []
    rd = fetch_json(f"https://rdap.org/domain/{d}")
    if rd and rd.get("events"):
        ev = {e["eventAction"]: e["eventDate"] for e in rd.get("events", [])}
        reg = next((e for e in rd.get("entities", []) if "registrar" in (e.get("roles") or [])), None)
        regname = ""
        if reg:
            vc = reg.get("vcardArray")
            if vc and len(vc) > 1:
                fn = next((v for v in vc[1] if v and v[0] == "fn"), None)
                regname = (fn[3] if fn and len(fn) > 3 else "") or reg.get("handle", "")
        out.append(_finding("domain", "whois_rdap", f"{d} — registrar {regname}",
                            f"https://rdap.org/domain/{d}",
                            f"registered {ev.get('registration','?')} · expires {ev.get('expiration','?')}", "high"))
        for ns in rd.get("nameservers", []):
            out.append(_finding("domain", "nameserver", (ns.get("ldhName") or ""), "", "", "high"))
    for t in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
        j = doh(d, t)
        for a in (j or {}).get("Answer", []):
            out.append(_finding("domain", "dns_" + t, a["data"].rstrip("."), "", f"TTL {a.get('TTL')}s", "high"))
    return {"findings": out, "meta": {"domain": d}}


def domain_ct(domain: str, limit: int = 200) -> dict:
    d = _clean_domain(domain)
    subs: dict[str, int] = {}
    certs = 0
    for q in (f"%25.{d}", d):
        # crt.sh returns one big JSON array; the default 8 MiB cap truncates it
        # for busy domains (→ invalid JSON → zero subdomains), so raise it here.
        r = fetch_json(f"https://crt.sh/?q={q}&output=json", timeout=50, max_bytes=MAX_BYTES_LARGE)
        if r:
            certs = len(r)
            for c in r:
                for s in (c.get("name_value") or "").split("\n"):
                    s = s.replace("*.", "").strip().lower()
                    if s and s.endswith(d) and s != d:
                        subs[s] = subs.get(s, 0) + 1
            if subs:
                break
    ordered = sorted(subs.items(), key=lambda x: -x[1])
    out = [_finding("domain", "ct_subdomain", s, f"https://{s}/", f"in {c} cert(s)", "high")
           for s, c in ordered[:limit]]
    out.append(_finding("domain", "ct_summary", f"{len(ordered)} unique subdomains from {certs} certs",
                        f"https://crt.sh/?q=%25.{d}", "", "high"))
    return {"findings": out, "meta": {"domain": d, "subdomains": [s for s, _ in ordered]}}


def domain_wayback(domain: str) -> dict:
    d = _clean_domain(domain)
    r = safe_fetch(
        f"https://web.archive.org/cdx/search/cdx?url=*.{urllib.parse.quote(d)}/*"
        "&output=json&fl=original,mimetype,timestamp&collapse=urlkey&limit=2000&filter=statuscode:200",
        timeout=50, max_bytes=MAX_BYTES_LARGE)
    try:
        rows = json.loads(r["text"])[1:]
    except (json.JSONDecodeError, ValueError):
        rows = []
    subs, files = set(), []
    for row in rows:
        u = row[0] if row else ""
        try:
            h = urllib.parse.urlparse(u).hostname or ""
            if h.endswith(d) and h != d:
                subs.add(h)
        except ValueError:
            pass
        if _WB_SENSITIVE.search(u) and len(files) < 120:
            files.append(u)
    out = [_finding("domain", "wb_summary",
                    f"{len(rows)} snapshots · {len(subs)} historical subdomains · {len(files)} sensitive-file candidates",
                    f"https://web.archive.org/web/*/{d}/*", "", "high")]
    for s in list(subs)[:100]:
        out.append(_finding("domain", "wb_subdomain", s, f"https://{s}/", "historical", "med"))
    for f in files:
        out.append(_finding("domain", "wb_file", f.split("/")[-1][:60], f, "archived sensitive-file candidate", "med"))
    # deep-fetch a few HTML snapshots for secrets / emails
    pages = [row for row in rows if "html" in (row[1] or "")]
    step = max(1, len(pages) // 4)
    for row in pages[::step][:4]:
        snap = f"https://web.archive.org/web/{row[2]}id_/{row[0]}"
        try:
            t = safe_fetch(snap, timeout=25)["text"]
        except FetchError:
            continue
        for em in set(_EMAIL_RE.findall(t)[:15]):
            out.append(_finding("domain", "wb_email", f"Archived email: {em}", snap, f"snapshot {row[2]}", "med"))
        for label, pat in _SECRET_PATTERNS:
            for m in set(re.findall(pat, t)):
                out.append(_finding("domain", "wb_secret", f"{label} in archive", snap, str(m)[:12] + "…", "high"))
    return {"findings": out, "meta": {"domain": d, "subdomains": sorted(subs)}}


def _clean_domain(domain: str) -> str:
    return re.sub(r"^https?://", "", domain.strip().lower()).split("/")[0]


# ---------------------------------------------------------------------------
# IP intel + Phone parse + Reddit + web search (server-side scrapes).
# ---------------------------------------------------------------------------
def ip_intel(ip: str) -> dict:
    ip = ip.strip()
    if not re.match(r"^[0-9a-fA-F.:]+$", ip):
        return {"findings": [], "meta": {"error": "invalid ip"}}
    out: list[dict] = []
    j = fetch_json(f"https://ipinfo.io/{ip}/json")
    if j and j.get("country"):
        out.append(_finding("ip", "geo", f"{ip} → {j.get('city','?')}, {j.get('region','')}, {j['country']}",
                            f"https://ipinfo.io/{ip}", f"{j.get('org','')} · {j.get('hostname','')}", "high"))
        if j.get("loc"):
            lat, lon = (j["loc"].split(",") + ["", ""])[:2]
            out.append(_finding("ip", "map", f"Map: {j['loc']}",
                                f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{j['loc']}", "", "med"))
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        p = doh(rev, "PTR")
        for a in (p or {}).get("Answer", []):
            out.append(_finding("ip", "ptr", f"PTR: {a['data'].rstrip('.')}", "", "reverse DNS", "high"))
    for n, url in (("Shodan", f"https://www.shodan.io/host/{ip}"),
                   ("GreyNoise", f"https://viz.greynoise.io/ip/{ip}"),
                   ("AbuseIPDB", f"https://www.abuseipdb.com/check/{ip}"),
                   ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{ip}")):
        out.append(_finding("ip", n.lower(), n, url, "", "low"))
    return {"findings": out, "meta": {"ip": ip}}


_SEARCH_ENGINES = [
    ("Google", "https://www.google.com/search?q="),
    ("Bing", "https://www.bing.com/search?q="),
    ("DuckDuckGo", "https://duckduckgo.com/?q="),
    ("Startpage", "https://www.startpage.com/sp/search?query="),
    ("Yandex", "https://yandex.com/search/?text="),
]


def web_search(query: str, limit: int = 20) -> dict:
    """Server-side web search — honest about what actually works off-host.

    Full organic scraping of Google/Bing/DuckDuckGo from a non-residential IP is
    actively *poisoned*: the engines serve decoy results (right page title,
    unrelated links) to anything that looks like a bot, so parsing their HTML
    returns misleading findings — worse than none. So this returns only what is
    reliable:
      * DuckDuckGo's Instant-Answer **JSON API** — real abstract + related URLs
        for entity queries, served cleanly server-side.
      * Actionable **search link-outs** across five engines for the human or
        agent to open in a browser, where organic results are not poisoned.
    A keyed provider (Brave Search / Serper / SerpAPI) is the right way to get
    true organic results server-side; slot it in here and feed the key from the
    optional local keystore (see README)."""
    query = (query or "").strip()
    if not query:
        return {"findings": [], "meta": {"error": "empty query"}}
    out: list[dict] = []
    j = fetch_json(f"https://api.duckduckgo.com/?q={urllib.parse.quote(query)}&format=json&no_html=1&t=thatosintme")
    if j:
        if j.get("AbstractURL"):
            out.append(_finding("meta_search", "web_abstract", j.get("Heading") or query,
                                j["AbstractURL"], (j.get("AbstractText") or "")[:160], "high"))
        n = [0]

        def walk(topics):
            for r in topics:
                if n[0] >= 12 or not isinstance(r, dict):
                    continue
                if r.get("Topics"):
                    walk(r["Topics"])
                    continue
                u = r.get("FirstURL", "")
                if u and "duckduckgo.com" not in u:
                    n[0] += 1
                    out.append(_finding("meta_search", "web_mention", (r.get("Text") or u)[:110],
                                        u, "DDG related topic", "med"))
        walk(j.get("RelatedTopics", []))
    for name, base in _SEARCH_ENGINES:
        out.append(_finding("meta_search", "search_link", f"{name}: {query}",
                            base + urllib.parse.quote(query),
                            "open in a browser — not scraped (engines poison bot scrapes)", "low"))
    return {"findings": out, "meta": {"query": query, "count": len(out)}}


_CC = {
    "971": "AE", "972": "IL", "973": "BH", "974": "QA", "975": "BT", "976": "MN", "977": "NP",
    "992": "TJ", "993": "TM", "994": "AZ", "995": "GE", "996": "KG", "998": "UZ", "880": "BD",
    "855": "KH", "856": "LA", "852": "HK", "853": "MO", "850": "KP", "81": "JP", "82": "KR",
    "84": "VN", "86": "CN", "90": "TR", "91": "IN", "92": "PK", "93": "AF", "94": "LK", "95": "MM",
    "98": "IR", "60": "MY", "61": "AU", "62": "ID", "63": "PH", "64": "NZ", "65": "SG", "66": "TH",
    "40": "RO", "41": "CH", "43": "AT", "44": "UK", "45": "DK", "46": "SE", "47": "NO", "48": "PL",
    "49": "DE", "30": "GR", "31": "NL", "32": "BE", "33": "FR", "34": "ES", "36": "HU", "39": "IT",
    "351": "PT", "352": "LU", "353": "IE", "354": "IS", "355": "AL", "358": "FI", "359": "BG",
    "370": "LT", "371": "LV", "372": "EE", "373": "MD", "374": "AM", "375": "BY", "380": "UA",
    "381": "RS", "385": "HR", "386": "SI", "387": "BA", "389": "MK", "420": "CZ", "421": "SK",
    "212": "MA", "213": "DZ", "216": "TN", "218": "LY", "220": "GM", "221": "SN", "223": "ML",
    "225": "CI", "226": "BF", "227": "NE", "228": "TG", "229": "BJ", "230": "MU", "231": "LR",
    "232": "SL", "233": "GH", "234": "NG", "235": "TD", "237": "CM", "238": "CV", "240": "GQ",
    "241": "GA", "242": "CG", "243": "CD", "244": "AO", "249": "SD", "250": "RW", "251": "ET",
    "252": "SO", "253": "DJ", "254": "KE", "255": "TZ", "256": "UG", "257": "BI", "258": "MZ",
    "260": "ZM", "261": "MG", "262": "RE", "263": "ZW", "264": "NA", "265": "MW", "266": "LS",
    "267": "BW", "268": "SZ", "269": "KM", "27": "ZA", "20": "EG", "501": "BZ", "502": "GT",
    "503": "SV", "504": "HN", "505": "NI", "506": "CR", "507": "PA", "509": "HT", "51": "PE",
    "52": "MX", "53": "CU", "54": "AR", "55": "BR", "56": "CL", "57": "CO", "58": "VE", "591": "BO",
    "592": "GY", "593": "EC", "595": "PY", "597": "SR", "598": "UY", "7": "RU/KZ", "1": "US/CA",
}


def phone_parse(number: str) -> dict:
    digits = re.sub(r"[^\d+]", "", number.strip())
    body = digits.lstrip("+")
    if len(body) < 7:
        return {"findings": [], "meta": {"error": "too short"}}
    cc, rest = "unknown", body
    for L in (3, 2, 1):
        if body[:L] in _CC:
            cc, rest = _CC[body[:L]], body[L:]
            break
    valid = 7 <= len(body) <= 15
    out = [_finding("phone", "parse", "+" + body, "",
                    f"country={cc} · national={rest} · E.164 valid={valid}",
                    "high" if cc != "unknown" else "low")]
    return {"findings": out, "meta": {"e164": "+" + body, "country": cc, "valid": valid}}


# ---------------------------------------------------------------------------
# Dork engine — advanced, automated dork generation across every category.
# Dorks are *link-outs*: organic results are reliable in a browser (engines
# poison server-side scrapes), so each dork is a ready-to-click search URL with
# the raw query attached for copy/paste into any engine.
# ---------------------------------------------------------------------------
_DORK_ENGINES = {
    "google": "https://www.google.com/search?q=",
    "bing": "https://www.bing.com/search?q=",
    "ddg": "https://duckduckgo.com/?q=",
    "yandex": "https://yandex.com/search/?text=",
    "startpage": "https://www.startpage.com/sp/search?query=",
    "brave": "https://search.brave.com/search?q=",
    "github": "https://github.com/search?type=code&q=",
    "grep": "https://grep.app/search?q=",
    "shodan": "https://www.shodan.io/search?query=",
    "censys": "https://search.censys.io/search?resource=hosts&q=",
    "fofa": "https://en.fofa.info/result?qbase64=",
    "publicwww": "https://publicwww.com/websites/",
    "intelx": "https://intelx.io/?s=",
}

# Each entry: (category, label, query-template, engine). Placeholders: {t}
# (target), {city}, {org}. A dork mentioning {city} is skipped when no city.
DORKS: dict[str, list[tuple]] = {
    "domain": [
        ("Files", "Directory listing", 'site:{t} intitle:"index of"', "google"),
        ("Files", "Open dirs with secrets", 'site:{t} intitle:"index of" (passwd|password|backup|credentials|.sql|.env)', "google"),
        ("Files", "Config files", 'site:{t} (ext:env|ext:ini|ext:conf|ext:cfg|ext:yml|ext:yaml|ext:json)', "google"),
        ("Files", "Backups & DB dumps", 'site:{t} (ext:bak|ext:old|ext:backup|ext:sql|ext:tar|ext:gz|ext:zip|ext:rar)', "google"),
        ("Files", "Log files", 'site:{t} ext:log', "google"),
        ("Files", "Git / SVN exposure", 'site:{t} (inurl:.git|inurl:.svn|intitle:"index of" ".git")', "google"),
        ("Files", "Env / dotfiles", 'site:{t} (inurl:.env|inurl:.htaccess|inurl:.npmrc|inurl:.aws)', "google"),
        ("Docs", "Documents & sheets", 'site:{t} (ext:pdf|ext:doc|ext:docx|ext:xls|ext:xlsx|ext:csv|ext:ppt|ext:pptx)', "google"),
        ("Creds", "Passwords in text", 'site:{t} (intext:"password"|intext:"passwd"|intext:"pwd"|intext:"DB_PASSWORD")', "google"),
        ("Creds", "API keys / secrets", 'site:{t} (intext:"api_key"|intext:"apikey"|intext:"client_secret"|intext:"secret_key"|intext:"access_token")', "google"),
        ("Access", "Login / admin panels", 'site:{t} (inurl:admin|inurl:login|intitle:login|inurl:signin|inurl:portal)', "google"),
        ("Access", "Dev / staging / test", 'site:{t} (inurl:dev|inurl:test|inurl:staging|inurl:uat|inurl:sandbox)', "google"),
        ("Access", "Open redirects", 'site:{t} (inurl:redirect=|inurl:url=|inurl:return=|inurl:next=|inurl:dest=)', "google"),
        ("App", "phpinfo()", 'site:{t} ext:php intitle:phpinfo "published by the PHP Group"', "google"),
        ("App", "WordPress internals", 'site:{t} (inurl:wp-content|inurl:wp-config|inurl:wp-admin|inurl:xmlrpc.php)', "google"),
        ("App", "SQL / stack errors", 'site:{t} (intext:"sql syntax near"|intext:"Warning: mysql"|intext:"unhandled exception"|intext:"stack trace:")', "google"),
        ("Recon", "Subdomains (ex-www)", 'site:*.{t} -www', "google"),
        ("Cloud", "S3 buckets", '(site:s3.amazonaws.com|site:s3-external-1.amazonaws.com|site:s3.*.amazonaws.com) "{t}"', "google"),
        ("Cloud", "GCS / Azure / DO", '(site:storage.googleapis.com|site:blob.core.windows.net|site:digitaloceanspaces.com) "{t}"', "google"),
        ("Paste", "Paste sites", '(site:pastebin.com|site:ghostbin.com|site:rentry.co|site:controlc.com|site:justpaste.it) "{t}"', "google"),
        ("Code", "GitHub secrets", '"{t}" (password OR api_key OR secret OR token OR credentials)', "github"),
        ("Code", "GitHub private keys", '"{t}" "BEGIN RSA PRIVATE KEY"', "github"),
        ("Code", "Code search (grep.app)", '{t}', "grep"),
        ("Code", "Sites running tech (publicwww)", '"{t}"', "publicwww"),
        ("Infra", "Shodan hostname", 'hostname:{t}', "shodan"),
        ("Infra", "Shodan SSL/cert", 'ssl:"{t}"', "shodan"),
        ("Infra", "Shodan org", 'org:"{org}"', "shodan"),
        ("Infra", "Censys hosts", '{t}', "censys"),
        ("Leaks", "IntelX exposure", '{t}', "intelx"),
    ],
    "name": [
        ("Profiles", "LinkedIn", 'site:linkedin.com/in "{t}"', "google"),
        ("Profiles", "Facebook", 'site:facebook.com "{t}"', "google"),
        ("Profiles", "X / Twitter", '(site:twitter.com|site:x.com) "{t}"', "google"),
        ("Profiles", "Instagram", 'site:instagram.com "{t}"', "google"),
        ("Docs", "Resume / CV", '"{t}" (resume OR cv OR "curriculum vitae") (ext:pdf OR ext:doc OR ext:docx)', "google"),
        ("Contact", "Contact details", '"{t}" (email OR "e-mail" OR contact OR phone OR mobile)', "google"),
        ("Geo", "Name + city", '"{t}" "{city}"', "google"),
        ("People", "People-search sites", '"{t}" (site:thatsthem.com OR site:spokeo.com OR site:fastpeoplesearch.com OR site:idcrawl.com OR site:truepeoplesearch.com)', "google"),
        ("Breach", "Leaks / mentions", '"{t}" (leak OR breach OR dump OR database)', "google"),
        ("Leaks", "IntelX", '{t}', "intelx"),
    ],
    "username": [
        ("Communities", "Dev & chat platforms", '"{t}" (site:reddit.com OR site:github.com OR site:gitlab.com OR site:keybase.io OR site:t.me OR site:news.ycombinator.com)', "google"),
        ("Paste", "Paste sites", '"{t}" (site:pastebin.com OR site:ghostbin.com OR site:rentry.co OR site:controlc.com)', "google"),
        ("Forums", "Forums & boards", '"{t}" (intitle:profile OR inurl:user OR inurl:member OR forum)', "google"),
        ("Web", "Exact mentions", 'intext:"{t}"', "google"),
        ("Code", "GitHub mentions", '"{t}"', "github"),
        ("Leaks", "IntelX", '{t}', "intelx"),
    ],
    "email": [
        ("Exact", "Exact email", '"{t}"', "google"),
        ("Breach", "Leaks / combolists", '"{t}" (leak OR breach OR dump OR password OR combolist)', "google"),
        ("Paste", "Paste sites", '(site:pastebin.com OR site:ghostbin.com OR site:rentry.co) "{t}"', "google"),
        ("Code", "GitHub commits/config", '"{t}"', "github"),
        ("Docs", "In documents", '"{t}" (ext:pdf OR ext:xlsx OR ext:csv OR ext:txt)', "google"),
        ("Leaks", "IntelX", '{t}', "intelx"),
    ],
    "ip": [
        ("Infra", "Shodan host", '{t}', "shodan"),
        ("Infra", "Censys host", 'ip:{t}', "censys"),
        ("Infra", "FOFA host", 'ip="{t}"', "fofa"),
        ("Web", "Mentions of IP", '"{t}"', "google"),
        ("Leaks", "IntelX", '{t}', "intelx"),
    ],
}


def _infer_dork_kind(t: str) -> str:
    if "@" in t:
        return "email"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t):
        return "ip"
    if " " in t.strip():
        return "name"
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", t, re.I):
        return "domain"
    return "username"


def _dork_url(engine: str, q: str) -> str:
    if engine == "fofa":
        # FOFA wants a base64 query string
        import base64
        return _DORK_ENGINES["fofa"] + urllib.parse.quote(base64.b64encode(q.encode()).decode())
    base = _DORK_ENGINES.get(engine, _DORK_ENGINES["google"])
    return base + urllib.parse.quote(q)


def generate_dorks(target: str, kind: str = "auto", city: str = "", org: str = "") -> dict:
    """Generate a categorised set of advanced search dorks for a target.
    `kind` ∈ auto|domain|name|username|email|ip. Returns findings whose url is a
    ready-to-click search link and whose detail is the raw query (copy/paste)."""
    target = (target or "").strip().lstrip("@")
    if not target:
        return {"findings": [], "meta": {"error": "empty target"}}
    kind = kind if kind in DORKS else _infer_dork_kind(target)
    ctx = {"t": target, "city": city.strip(), "org": (org or target).strip()}
    out = []
    for cat, label, tmpl, engine in DORKS[kind]:
        if "{city}" in tmpl and not ctx["city"]:
            continue
        try:
            q = tmpl.format(**ctx)
        except (KeyError, IndexError):
            continue
        out.append(_finding("dorks", "dork_" + engine, f"[{cat}] {label}", _dork_url(engine, q), q, "low"))
    return {"findings": out, "meta": {"target": target, "kind": kind, "count": len(out)}}


# dispatch table shared by the HTTP API and the MCP server
TOOLS: dict[str, Callable[..., dict]] = {
    "username_sweep": username_sweep,
    "email_intel": email_intel,
    "domain_dns": domain_dns,
    "domain_ct": domain_ct,
    "domain_wayback": domain_wayback,
    "ip_intel": ip_intel,
    "web_search": web_search,
    "phone_parse": phone_parse,
    "generate_dorks": generate_dorks,
}
