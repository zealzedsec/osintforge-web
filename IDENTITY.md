# osintforge-web — Identity Dossier
Status: draft | Mode: autonomous  ·  Family: **OSINTForge** (with `osintforge`)
Phase 0 evidence: `.singular/baseline/tells.txt`

## Phase 0 summary (current state, observed)
- Single-page web console ("OSINTForge v3 — Intelligence Console") for the
  OSINTForge engine; fonts intentionally self-hosted (no CDN) — already a good
  decision.
- Current palette: deep navy `--bg:#070b12`, panels `#0d1420`, cyan `--acc:#22d3ee`
  + emerald `#34d399`, text `#dbe7f5`. Considered, but cyan-on-navy "console" is a
  mild cluster.
- Tell scan: emoji-as-ui 72, gradient-washes 9, caps-tracked 5, saturated-fonts
  3, glass-blur 2, emoji-in-logs 1.

## 1. Subject
- Subject: the operator console for an authorization-gated, evidence-logged OSINT
  investigation engine (usernames, emails, IPs, domains, images, Reddit).
- Audience: an investigator working a lawful case; needs the authorization
  statement, the evidence trail, and relationships between findings.
- Primary job: run gated queries, watch the evidence log fill, and read how
  findings connect — with the audit trail always in view.
- World it lives in: an investigator's case folder, a pin-and-thread evidence
  board, a chain-of-custody log, a redacted dossier.

## 2. References
- Physical-world references: a manila case folder with a redacted cover sheet; a
  cork evidence board with pins and thread; a chain-of-custody form.
- Anti-references: cyan-on-navy "cyber" console; hacker-green terminal; and
  unrelated siblings — apollo's stencil case, pedro's commonplace book.
- Given assets: self-hosted-fonts decision is Given (keep, don't regress to CDN).

## 3. Archetype slots (final)
structural metaphor: **evidence board / dossier** | type temperament: **typewriter
mono + a records sans** | color story: **manila/kraft + redaction ink + a single
pin-red** | density: **measured → dense** | motion: **state-only** |
surface/texture: **paper / kraft + ink** | grid: **free-form / collage (board)** |
imagery strategy: **diagrammatic (entity-relationship graph)**

## 4. The one memorable thing
The **entity board**: findings laid out as a pin-and-thread relationship graph
over the live evidence/audit timeline — the investigation *is* the interface,
authorization statement stamped on the cover.

## 5. Token plan
- Color (OKLCH): `manila`/`kraft` surfaces (warm, not navy), `ink` text,
  `redaction` (near-black bars where appropriate), `pin` (one red accent — marks a
  focal entity/alert). Moves deliberately OFF cyan-navy. Status colors functional,
  distinction-tested.
- Type: a **typewriter-grade mono** for report/evidence text + a **records sans**
  for labels and nav. Tabular figures in the log.
- Space/radius: paper-sheet radius ≈0; separation by ruled lines and tabs.
- Motion thesis: "Motion behaves like pinning a card to the board — it appears on
  an action, it doesn't drift." Reduced-motion respected.
- Dark mode: a designed "low-light desk" variant (own warm-dark surfaces), not an
  inversion of the manila theme.

## 6. Layout concept
- One sentence: a dossier cover (authorization + target) opening onto the evidence
  board and the chain-of-custody log.
- Hero thesis: opens on the authorization statement + target + empty board ready
  to fill, not a search box in a void.
- Alignment: board is free-form/collage; the log is a strict single axis.

## 7. Voice (shared family glossary with osintforge CLI)
- Adjectives: careful, lawful, precise.
- Says: "Authorized by: <statement>. 14 requests logged." / "No public record
  found for that handle." Never: "oops", emoji as UI, anything implying
  access-control bypass.
- Naming: *targets*, *findings*, *evidence log*, *authorization* — identical to
  the CLI's vocabulary (family resemblance by design).

## 8. Collision Test log
| Plan element | Default I'd have produced | Chosen | Why different |
|---|---|---|---|
| Color | Cyan/emerald on navy | Manila/kraft + ink + pin-red | Leaves the "cyber console" cluster |
| Layout | Search box + results list | Evidence board + chain-of-custody log | Investigation, not a search UI |
| Type | Inter + mono | Typewriter mono + records sans | Reads like a case file |
| Emoji | 72 emoji-as-ui | Drawn marks / ruled tabs | Removes the dominant tell |

## 9. Chosen defaults (documented exceptions)
| Default kept | Why it's right for this subject |
|---|---|
| Self-hosted fonts, no CDN | Correct privacy/perf decision — keep |
| Monospace-forward | Evidence/report text is the subject's native form |

## 10. Backend identity
Shares the OSINTForge engine; the console surfaces the authorization gate and
`evidence.jsonl` as first-class UI. No 200-with-failure; truthful "no result" vs
"error"; never implies bypass of access controls.

## 11. Non-negotiable constraints
Authorization statement always visible; evidence log immutable in UI; WCAG 2.2
AA; never surface adult-platform harvesting; never commit targets or case data.
