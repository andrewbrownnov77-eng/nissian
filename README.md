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

## Roadmap

- **Stage 1 — Deep contextual discovery** ✅ (this)
- **Stage 2 — Active analysis**: scope-gated IDOR/token/auth probing driven by
  Stage 1 candidates.
- **Stage 3 — Triage & reporting**: dedup, CVSS scoring, reproducible PoC
  report drafts.

## License

MIT
