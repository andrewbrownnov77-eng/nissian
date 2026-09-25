/**
 * Program-identity tagging — the opposite of "moving like a ghost".
 *
 * Most bug bounty programs *want* researchers identifiable so their security
 * team can tell authorized testing apart from a real attack. Many require a
 * header carrying your researcher handle (e.g. HackerOne username). Tagging
 * every request this way is what keeps you from getting IP-banned or reported
 * as an attacker mid-test — the actual "operational polish" that matters.
 *
 * This module builds those identifying headers and merges them into every
 * outbound request.
 */

export interface ResearcherIdentity {
  /** Header name the program asks for, e.g. "X-Bug-Bounty" or "X-HackerOne". */
  headerName: string;
  /** Your handle / program-issued identifier. */
  handle: string;
  /** Optional contact so the security team can reach you. */
  contact?: string;
}

/** Build the identifying headers to attach to every request. */
export function identityHeaders(id: ResearcherIdentity): Record<string, string> {
  const headers: Record<string, string> = { [id.headerName]: id.handle };
  if (id.contact) headers["X-Researcher-Contact"] = id.contact;
  return headers;
}

/** Merge identity headers into a request's headers (identity wins on conflict). */
export function withIdentity(
  headers: Record<string, string> | undefined,
  id: ResearcherIdentity | undefined,
): Record<string, string> {
  const base = { ...(headers ?? {}) };
  if (!id) return base;
  return { ...base, ...identityHeaders(id) };
}
