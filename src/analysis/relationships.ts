/**
 * Relationship inference — the "IDORs live here" stage.
 *
 * We extract identifiers (UUIDs, numeric ids, emails) from captured traffic,
 * then look for endpoints whose *path* embeds an identifier that also appeared
 * elsewhere. That pattern — a client-supplied reference flowing into a
 * server-side lookup — is where broken-object-level-authorization (IDOR) lives.
 *
 * Output is a set of CANDIDATES to test in a later, scope-gated active stage.
 * Nothing here sends a request; it only reasons about traffic already captured.
 */

import type {
  CapturedRequest,
  ExtractedIdentifier,
  AccessControlCandidate,
} from "../types.js";

const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi;
const JWT_RE = /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
/** Numeric ids of 3+ digits — short enough numbers are too noisy to be useful. */
const NUMERIC_ID_RE = /\b\d{3,}\b/g;

export interface RelationshipOutput {
  identifiers: ExtractedIdentifier[];
  candidates: AccessControlCandidate[];
}

export function analyzeRelationships(requests: CapturedRequest[]): RelationshipOutput {
  const index = new Map<string, ExtractedIdentifier>();

  const note = (value: string, kind: ExtractedIdentifier["kind"], locator: string) => {
    const key = `${kind}:${value}`;
    const existing = index.get(key);
    if (existing) {
      if (!existing.seenIn.includes(locator)) existing.seenIn.push(locator);
    } else {
      index.set(key, { value, kind, seenIn: [locator] });
    }
  };

  // Pass 1: harvest identifiers from every request/response we captured.
  for (const req of requests) {
    const haystacks: Array<[string, string]> = [
      [req.url, `req:${req.id}:url`],
      [req.requestBody ?? "", `req:${req.id}:body`],
      [req.responseBody ?? "", `req:${req.id}:response`],
    ];
    for (const [text, locator] of haystacks) {
      for (const m of text.matchAll(UUID_RE)) note(m[0], "uuid", locator);
      for (const m of text.matchAll(JWT_RE)) note(m[0], "jwt", locator);
      for (const m of text.matchAll(EMAIL_RE)) note(m[0], "email", locator);
      // Numeric ids: only harvest from paths/bodies, not whole HTML responses,
      // to avoid capturing timestamps and asset hashes as "ids".
      if (locator.endsWith(":url") || locator.endsWith(":body")) {
        for (const m of text.matchAll(NUMERIC_ID_RE)) note(m[0], "numeric", locator);
      }
    }
  }

  // Pass 2: find endpoints whose path embeds an identifier we also saw
  // elsewhere — the classic IDOR shape.
  const candidates: AccessControlCandidate[] = [];
  const seenTemplates = new Set<string>();

  for (const req of requests) {
    const path = safePath(req.url);
    if (!path) continue;

    for (const id of index.values()) {
      if (id.kind === "email") continue; // handled as info, not an object ref
      if (!path.includes(id.value)) continue;

      // Only interesting if the identifier also showed up somewhere OTHER
      // than this request's own URL — i.e. it flows between contexts.
      const elsewhere = id.seenIn.some((loc) => !loc.startsWith(`req:${req.id}:`));
      if (!elsewhere) continue;

      const template = `${req.method} ${path.replace(id.value, `{${id.kind}}`)}`;
      if (seenTemplates.has(template)) continue;
      seenTemplates.add(template);

      candidates.push({
        endpointTemplate: template,
        method: req.method,
        identifier: id,
        rationale:
          `Path embeds a ${id.kind} identifier that also appears in other traffic ` +
          `(${id.seenIn.length} location(s)). If the server does not verify that the ` +
          `authenticated principal owns this object, substituting another user's ` +
          `${id.kind} may expose or mutate their data (IDOR / BOLA candidate).`,
        requestIds: [req.id],
      });
    }
  }

  return { identifiers: [...index.values()], candidates };
}

function safePath(url: string): string | null {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return null;
  }
}
