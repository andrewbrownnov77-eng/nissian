# nissian

A **scope-aware bug bounty reconnaissance assistant**. Built for authorized
testing only — it operates strictly inside a bounty program's declared scope,
and that constraint is what lets it dig deep without hesitation.

> ⚠️ **Authorized use only.** Only run this against targets you have explicit
> permission to test (a public/private bug bounty program's in-scope assets,
> your own systems, or an engagement with written authorization). Testing
> systems you are not authorized to test is illegal in most jurisdictions.

## Stage 1 — Deep Contextual Discovery

Surface scanners spray payloads and match regexes. Stage 1 instead tries to
*understand the app* the way a good hunter does:

- **Full browsing & JS execution** — drives a real Chromium (Playwright), so
  it renders SPAs, runs their JavaScript, and captures the XHR/`fetch` API
  calls that never appear in static crawls.
- **Relationship inference** — harvests identifiers (UUIDs, numeric ids, JWTs)
  from traffic and flags endpoints whose path embeds an id that also appears
  elsewhere. That flow — client-supplied reference → server-side lookup — is
  where **IDOR / BOLA** lives. Output is *candidates to verify*, not claims.
- **Stateful token analysis** — pulls JWTs from `localStorage`,
  `sessionStorage`, and `Authorization` headers; decodes header + claims; and
  flags what's worth probing: `role`/`admin` claims (privilege escalation),
  `alg: none` or HMAC (signature-stripping / alg-confusion), missing `exp`.

Everything in Stage 1 is **passive** — it observes and reasons about traffic
the app itself generates. Active probing (actually substituting an id, forging
a token) belongs to Stage 2 and is gated by `allowedTestTypes` in your scope
file.

## Scope is the point, not a limitation

`nissian` refuses to start without a scope file, and refuses to crawl any seed
whose host isn't in scope. At the network layer, requests to out-of-scope hosts
are **aborted before they're sent** and recorded as warnings for manual review.
This is deliberate: once "am I authorized to touch this?" is answered up front,
the tool can be relentless everywhere it's allowed to be.

## Install

```bash
npm install
npx playwright install chromium   # not needed in environments that pre-install it
npm run build
```

## Usage

```bash
# 1. Copy the example scope file and edit it for your program.
cp scope.example.json scope.json

# 2. Run discovery against in-scope seeds.
npm run discover -- \
  --scope ./scope.json \
  --seed https://app.example.com \
  --out ./discovery.json \
  --max-pages 50 \
  --settle 1500
```

Output: a human-readable summary on stdout and a structured `discovery.json`
(the full attack-surface map) for later stages.

### Scope file format

See `scope.example.json`. Fields:

| field              | meaning                                                            |
| ------------------ | ------------------------------------------------------------------ |
| `program`          | Program name (for reports).                                        |
| `inScope`          | Host patterns allowed. `*.example.com` matches subdomains + apex.  |
| `outOfScope`       | Explicit exclusions; override `inScope`.                           |
| `allowedTestTypes` | Which active tests later stages may generate. Absent ⇒ passive.    |
| `rateLimit`        | Politeness limits so you never degrade a target.                   |

## Stage 2 — Reliable validation (zero false positives)

Turns Stage 1 candidates into **confirmed** findings backed by reproducible
evidence. Every probe returns `CONFIRMED` / `REFUTED` / `INCONCLUSIVE`, and only
confirmed findings reach a report:

- **Blind SQLi** — statistical, time-based (baseline vs. delayed samples with a
  separation guard), so noise can't fake a finding.
- **SSRF** — fires at a controlled OOB collector and captures the exact inbound
  request the target made.
- **IDOR/BOLA** — two identities; confirms attacker reads victim's object, and
  rules out "it's just public data".
- **Reflected XSS** — renders in real Chromium and detects actual execution,
  after ruling out CSP / X-XSS-Protection.

```bash
npm run build
node dist/index.js validate --scope ./scope.json --plan ./plan.json --out report.md
```

See `plan.example.json` for the validation-plan format.

## Stage 3 — Adaptability & operational polish

- **Adaptive throttle** (`src/stealth/throttle.ts`) — backs off on 429/503,
  honors `Retry-After`, eases back up on success, optional off-hours windows.
  Good citizenship, structurally enforced.
- **Auth-flow intelligence** (`src/auth/session.ts`) — auto-login, early JWT
  refresh from the token's own `exp`, re-auth on a killed session, and
  `refreshBefore()` to survive session-invalidating endpoints.
- **WAF-aware encoding** (`src/stealth/waf.ts`) — equivalent payload encodings
  to confirm a bug isn't merely filter-masked. For *truthful reporting*, not
  evading a defender.
- **Program-identity tagging** (`src/stealth/identity.ts`) — the anti-ghost:
  tags every request with your researcher handle so the security team can tell
  authorized testing from an attack (what most programs require).
- **Format-perfect output** (`src/report/templates.ts`) — HackerOne / custom
  templates with CWE, CVSS vector, and a stack-aware remediation.

## Roadmap

- **Stage 1 — Deep contextual discovery** ✅
- **Stage 2 — Reliable validation** ✅
- **Stage 3 — Adaptability & operational polish** ✅
- **Stage 4 — Differential coverage mapping** ✅ — parse OpenAPI / GraphQL
  introspection / sitemap, diff against actual crawl coverage, and emit a gap
  report that says *why* each untested endpoint was unreachable (403 → escalate
  a role and re-scan, 401 → needs creds, never-reached → add a flow).
  `nissian coverage --discovery <file> [--openapi|--graphql|--sitemap <f>]`
- **Stage 5 — Poisoning awareness** ✅ — safe-mode mutators (synthetic UUIDs,
  `nissian-test-` names, `@example.com` emails), a rollback journal that undoes
  state changes LIFO, and destructive-action gating (DELETE / billing /
  notification writes need explicit opt-in, and in safe mode may only target
  synthetic values). All state changes funnel through `MutationClient`.
- **Stage 6 — Cross-target memory** ✅ — a persisted experience layer:
  WAF-fingerprint→encoding success rates (best-first recommendations), a
  version-aware stack-gadget library (a Spring Boot 2.7 gadget fires on 2.7.3
  but not 3.0), and per-program pay/N-A history that ranks vuln classes by
  expected value. Stored in a gitignored `memory.json`.
- **Stage 7 — Human-readable narratives** (planned)
- **Stage 8 — Autonomous triage & duplicate detection** (planned)

## License

MIT
