/**
 * Shared type definitions for the discovery pipeline.
 *
 * Stage 1 produces a DiscoveryResult that later stages (analysis, triage,
 * reporting) consume. Everything here is data — no side effects.
 */

/** A single captured HTTP exchange observed by the crawler. */
export interface CapturedRequest {
  id: string;
  method: string;
  url: string;
  /** Host component of the URL, precomputed for scope checks. */
  host: string;
  resourceType: string;
  requestHeaders: Record<string, string>;
  requestBody?: string;
  status?: number;
  responseHeaders?: Record<string, string>;
  /** Response body, truncated to a safe cap (see crawler config). */
  responseBody?: string;
  /** Whether this exchange was within authorized scope. */
  inScope: boolean;
  timestamp: number;
}

/** An identifier extracted from traffic that may drive an object-reference. */
export interface ExtractedIdentifier {
  value: string;
  kind: "uuid" | "numeric" | "jwt" | "email" | "opaque";
  /** Where we first saw it (request id + a short locator). */
  seenIn: string[];
}

/**
 * A candidate IDOR / broken-object-level-authorization site: an endpoint
 * whose path embeds an identifier that also appeared elsewhere, meaning the
 * server may be trusting a client-supplied reference without an auth check.
 *
 * This is a *candidate to test*, not a confirmed finding.
 */
export interface AccessControlCandidate {
  endpointTemplate: string;
  method: string;
  identifier: ExtractedIdentifier;
  /** Why we flagged it, in plain language, for the report. */
  rationale: string;
  requestIds: string[];
}

/** A decoded bearer token observed in storage or an Authorization header. */
export interface TokenObservation {
  source: "localStorage" | "sessionStorage" | "cookie" | "authorization-header";
  /** Never the raw signature — we keep header+claims for analysis only. */
  header?: Record<string, unknown>;
  claims?: Record<string, unknown>;
  /** Notable claims worth testing (role escalation, alg confusion, etc.). */
  observations: string[];
  raw_present: boolean;
}

/** A note about something seen outside authorized scope — recorded, never acted on. */
export interface ScopeWarning {
  url: string;
  host: string;
  reason: string;
}

/** The full output of a Stage 1 run. */
export interface DiscoveryResult {
  target: string;
  startedAt: string;
  finishedAt: string;
  requests: CapturedRequest[];
  identifiers: ExtractedIdentifier[];
  accessControlCandidates: AccessControlCandidate[];
  tokens: TokenObservation[];
  scopeWarnings: ScopeWarning[];
}
