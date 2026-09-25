/**
 * Duplicate detection.
 *
 * On a busy program, 40 other hunters have already found the low-hanging fruit.
 * Filing a dup burns your reputation and the triager's time. Before filing, we
 * compare each finding against (a) the program's public disclosed reports and
 * (b) our own memory of what we already submitted, and flag likely duplicates.
 *
 * Matching is deliberately simple and explainable: same vulnerability class AND
 * either the same normalized endpoint or a high token-overlap between the
 * finding and the prior report's text. No opaque scoring a triager can't follow.
 */

import { normalizePath } from "../coverage/spec-parser.js";

export interface PriorArtifact {
  /** "self" for our own memory, "disclosed" for the program's public reports. */
  origin: "self" | "disclosed";
  type?: string;
  endpoint?: string;
  title: string;
  text?: string;
  outcome?: string;
  scanId?: string;
}

export interface DuplicateVerdict {
  isDuplicate: boolean;
  similarity: number;
  matched?: PriorArtifact;
  reason: string;
}

export interface FindingLike {
  type: string;
  endpoint: string;
  title?: string;
}

const ENDPOINT_MATCH_THRESHOLD = 0.34; // token overlap needed when endpoints differ

export function detectDuplicate(finding: FindingLike, priors: PriorArtifact[]): DuplicateVerdict {
  const fEndpoint = normalizeEndpoint(finding.endpoint);
  const fTokens = tokenize(`${finding.type} ${finding.endpoint} ${finding.title ?? ""}`);

  let best: { art: PriorArtifact; sim: number; sameEndpoint: boolean } | undefined;

  for (const p of priors) {
    // Class must match to be a duplicate (an XSS is not a dup of an IDOR).
    if (p.type && p.type !== finding.type) continue;

    const sameEndpoint = p.endpoint !== undefined && normalizeEndpoint(p.endpoint) === fEndpoint;
    const pTokens = tokenize(`${p.type ?? ""} ${p.endpoint ?? ""} ${p.title} ${p.text ?? ""}`);
    const sim = jaccard(fTokens, pTokens);

    if (!best || sim > best.sim || (sameEndpoint && !best.sameEndpoint)) {
      best = { art: p, sim, sameEndpoint };
    }
  }

  if (!best) {
    return { isDuplicate: false, similarity: 0, reason: "no prior report of this class to compare against" };
  }

  const isDuplicate = best.sameEndpoint || best.sim >= ENDPOINT_MATCH_THRESHOLD;
  const originLabel = best.art.origin === "self" ? `your own prior report${best.art.scanId ? ` (scan ${best.art.scanId})` : ""}` : "a public disclosed report";
  const outcomeLabel = best.art.outcome ? ` — previously ${best.art.outcome}` : "";

  return {
    isDuplicate,
    similarity: Math.round(best.sim * 100) / 100,
    matched: isDuplicate ? best.art : undefined,
    reason: isDuplicate
      ? `Matches ${originLabel}${outcomeLabel}: "${best.art.title}"${best.sameEndpoint ? " (same endpoint & class)" : ` (token similarity ${Math.round(best.sim * 100)}%)`}.`
      : `Closest prior report "${best.art.title}" only ${Math.round(best.sim * 100)}% similar — treated as novel.`,
  };
}

function normalizeEndpoint(ep: string): string {
  // Strip a leading method if present, normalize the path portion.
  const parts = ep.trim().split(/\s+/);
  const pathish = parts.length > 1 ? parts[1] : parts[0];
  try {
    return normalizePath(new URL(pathish).pathname);
  } catch {
    return normalizePath(pathish.split("?")[0]);
  }
}

function tokenize(s: string): Set<string> {
  return new Set(
    s
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, " ")
      .split(" ")
      .filter((t) => t.length > 2),
  );
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let inter = 0;
  for (const t of a) if (b.has(t)) inter++;
  return inter / (a.size + b.size - inter);
}
