# OSINTForge v4 — Intelligence Console

A private, self-hosted OSINT console: a browser UI for username/email/domain/IP/
image/phone recon with an entity graph, now backed by a **local OSINT API** and
an **autonomous agent**. Public-source data only; lawful-use attestation and a
local audit trail are built in.

## Run

```bash
./start.sh            # binds your LAN IP on :8443 (reachable from your phone)
# or
python3 serve.py --host 127.0.0.1 --port 8443   # loopback only
```

It prints a generated Basic-auth password (also in `.credentials`, mode 0600)
and uses a self-signed TLS cert (your browser warns once — accept it). Nothing
is exposed to the internet.

No dependencies beyond Python 3.11+ and `openssl`. For the agent, `opencode`
must be on `PATH` and logged in to a provider (`opencode providers`).

## What's new in v4

**1. The relay moved server-side (privacy fix).** The old build sent every
probed URL — i.e. *who you were investigating* — to public CORS relays
(allorigins / corsproxy). v4 routes cross-origin fetches through `/api/relay`
on this host, guarded by an SSRF allowlist (`osint_tools.safe_fetch`) that
refuses loopback, RFC1918, link-local (incl. the `169.254.169.254` metadata
address), and non-HTTP schemes, caps body size/time, and re-validates every
redirect hop. Public relays are now an **opt-in** fallback in Settings.

**2. Server-side tools** (`/api/tool/<name>`) — reliable, private versions of
the recon primitives: `username_sweep` (per-site body/API detection with honest
confidence, not status-200 guesses), `email_intel`, `domain_dns` / `domain_ct`
/ `domain_wayback`, `ip_intel`, `web_search`, `phone_parse`.

**3. Workflows** (`⚡ Workflows` tab, `/api/workflow/<name>`) — one-click,
multi-step automations that chain tools and auto-pivot, streaming a live step
timeline over SSE:
- `handle_profile` — sweep → dossier → mine emails → email-intel → re-sweep.
- `domain_surface` — RDAP+DNS → CT subdomains → Wayback secrets/files.
- `email_identity` — mail health + gravatar + git attribution → handle sweeps.
- `person_search` — dorked search + sweep + email-intel.

**4. Autonomous agent** (`🤖 Agent` tab, `/api/agent`) — give an objective in
plain language; an **opencode**-driven agent plans and runs a multi-step
investigation using the tools (exposed to it via the MCP server `osint_mcp.py`),
streaming reasoning and findings into the case graph. The agent uses opencode's
configured default model (override with `OSF_AGENT_MODEL=provider/model`).

### Agent safety

The agent is locked down at the agent level: `bash`, `edit`, `write`, and
`webfetch` are **disabled**, so it can only call the read-only `osint_*` tools.
A prompt-injected objective (or a scraped page telling it to "run X") cannot
make it touch a shell, the filesystem, or arbitrary URLs. Tool output is treated
as data, never instructions. Agent run dirs are created under `$OSF_RUN_DIR`
(a temp dir by default) and deleted when the run ends.

## Files

| File | Role |
|---|---|
| `index.html` | the single-page console (UI, graph, client modules) |
| `serve.py` | HTTPS host + Basic auth + the `/api/*` backend |
| `osint_tools.py` | server-side OSINT primitives + SSRF-guarded `safe_fetch` |
| `workflows.py` | deterministic multi-step pipelines |
| `osint_mcp.py` | stdio MCP server exposing the tools to opencode |
| `agent/osint.md` | the agent's system prompt |

## Honest limitations

- **Web search:** full organic scraping of Google/Bing/DuckDuckGo from a
  non-residential IP is actively *poisoned* (decoy results), so `web_search`
  returns DuckDuckGo instant-answer data plus actionable link-outs rather than
  fabricated results. For true server-side organic search, slot a keyed provider
  (Brave Search / Serper / SerpAPI) into `web_search`.
- **No API keys yet:** depth-limited by what's free/unauthenticated (no Shodan /
  Censys / HIBP-account / VirusTotal). The intended next step is an optional,
  at-rest-encrypted local keystore the browser never sees — keeping the
  "no secrets on disk in cleartext" posture while unlocking keyed sources.
- Findings are **leads** — corroborate before operational use.

## Lawful use

OSINTForge collects publicly available data only. Use it for authorized
investigation, journalism, security research, self-lookup, or consented client
work. Not for stalking, harassment, doxxing, or anything unlawful. Every query
is recorded in the local audit trail.
