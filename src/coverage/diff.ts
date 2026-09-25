/**
 * Coverage diff — what was tested, what wasn't, and why.
 *
 * Given the endpoints an app claims to have (from specs) and what we actually
 * exercised (from the crawl/probe traffic), this computes coverage and, for each
 * untested endpoint, infers *why* we couldn't reach it — a 403 for the whole run
 * means "locked behind a role you don't have; escalate and re-scan", which is a
 * far more useful line in a report than silence.
 */

import type { Endpoint } from "./spec-parser.js";
import { normalizePath } from "./spec-parser.js";
import type { CapturedRequest } from "../types.js";

export type GapReason =
  | "tested"
  | "auth-required" // saw 401 across the run
  | "forbidden" // saw 403 across the run — likely a role gate
  | "not-found" // saw only 404 — may not exist at this path
  | "server-error" // saw 5xx — endpoint exists but errored
  | "never-attempted"; // we never hit it at all

export interface EndpointCoverage {
  endpoint: Endpoint;
  reason: GapReason;
  observedStatuses: number[];
  recommendation?: string;
}

export interface CoverageReport {
  totalKnown: number;
  tested: number;
  coveragePct: number;
  gaps: EndpointCoverage[];
}

interface Observed {
  statuses: number[];
}

export function computeCoverage(known: Endpoint[], requests: CapturedRequest[]): CoverageReport {
  // Index observed traffic by method + normalized path.
  const observed = new Map<string, Observed>();
  for (const req of requests) {
    const path = pathOf(req.url);
    if (path === null) continue;
    const key = `${req.method.toUpperCase()} ${normalizePath(path)}`;
    const entry = observed.get(key) ?? { statuses: [] };
    if (req.status !== undefined) entry.statuses.push(req.status);
    observed.set(key, entry);
  }

  const gaps: EndpointCoverage[] = [];
  let tested = 0;

  for (const ep of known) {
    const key = `${ep.method} ${ep.pathTemplate}`;
    const obs = observed.get(key);
    const statuses = obs?.statuses ?? [];
    const reason = classifyGap(statuses);
    if (reason === "tested") {
      tested++;
      continue;
    }
    gaps.push({
      endpoint: ep,
      reason,
      observedStatuses: statuses,
      recommendation: recommend(reason, ep),
    });
  }

  const totalKnown = known.length;
  return {
    totalKnown,
    tested,
    coveragePct: totalKnown === 0 ? 0 : Math.round((tested / totalKnown) * 1000) / 10,
    gaps,
  };
}

function classifyGap(statuses: number[]): GapReason {
  if (statuses.length === 0) return "never-attempted";
  const any2xx3xx = statuses.some((s) => s < 400);
  if (any2xx3xx) return "tested";
  // No success — pick the most informative failure that dominates.
  if (statuses.every((s) => s === 401)) return "auth-required";
  if (statuses.every((s) => s === 403)) return "forbidden";
  if (statuses.every((s) => s === 404)) return "not-found";
  if (statuses.some((s) => s >= 500)) return "server-error";
  // Mixed 401/403 etc.
  return statuses.includes(403) ? "forbidden" : "auth-required";
}

function recommend(reason: GapReason, ep: Endpoint): string | undefined {
  switch (reason) {
    case "forbidden":
      return `Consistently 403 — likely gated behind a role/permission. Re-run with an identity that has access (escalate the test account) to cover ${ep.method} ${ep.pathTemplate}.`;
    case "auth-required":
      return `Consistently 401 — provide valid credentials for this endpoint and re-scan.`;
    case "never-attempted":
      return `Declared in ${ep.source} but never exercised. Add a seed/flow that reaches it.`;
    case "server-error":
      return `Endpoint errors (5xx) — may itself be a finding; investigate the error before assuming coverage.`;
    case "not-found":
      return `Only 404s observed — the path template may be wrong or the endpoint retired.`;
    default:
      return undefined;
  }
}

function pathOf(url: string): string | null {
  try {
    return new URL(url).pathname;
  } catch {
    return null;
  }
}
