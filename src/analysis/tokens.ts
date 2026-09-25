/**
 * Stateful token analysis.
 *
 * SPAs commonly stash bearer tokens (JWTs) in localStorage / sessionStorage /
 * cookies. Decoding those tokens reveals the trust model the app relies on —
 * and the claims worth probing in a later, scope-gated active stage:
 *
 *   - a `role` / `admin` / `scope` claim → privilege-escalation candidate
 *   - alg "none" or a weak alg in the header → signature-stripping candidate
 *   - a long expiry / no expiry → session-lifetime issue
 *
 * We decode header and payload only. We deliberately do NOT retain or transmit
 * the signature, and we never attempt to forge or replay a token here — that is
 * a decision for the active-testing stage, gated by allowedTestTypes.
 */

import type { TokenObservation } from "../types.js";

/** Raw token sightings the crawler collected from a page's storage/headers. */
export interface RawTokenSighting {
  source: TokenObservation["source"];
  value: string;
}

const ROLE_CLAIMS = ["role", "roles", "admin", "is_admin", "scope", "scopes", "groups", "permissions"];

export function analyzeTokens(sightings: RawTokenSighting[]): TokenObservation[] {
  const out: TokenObservation[] = [];
  const seen = new Set<string>();

  for (const sighting of sightings) {
    const decoded = decodeJwt(sighting.value);
    if (!decoded) continue;

    // De-dupe identical tokens seen in multiple places.
    const key = sighting.value.split(".").slice(0, 2).join(".");
    if (seen.has(key)) continue;
    seen.add(key);

    const observations: string[] = [];

    // Algorithm-related observations.
    const alg = String(decoded.header["alg"] ?? "").toLowerCase();
    if (alg === "none") {
      observations.push('header alg is "none" — unsigned token; test whether the server accepts it as-is (auth bypass candidate)');
    } else if (alg.startsWith("hs")) {
      observations.push(`header alg is ${alg.toUpperCase()} (HMAC) — if the public key of any RS-mode endpoint is known, test alg-confusion (RS→HS)`);
    }

    // Claim-related observations.
    for (const claim of ROLE_CLAIMS) {
      if (claim in decoded.claims) {
        observations.push(`carries authorization claim "${claim}"=${JSON.stringify(decoded.claims[claim])} — privilege-escalation candidate if the value is trusted without server-side re-check`);
      }
    }

    // Expiry observations.
    if (!("exp" in decoded.claims)) {
      observations.push("no 'exp' claim — token may never expire (session-lifetime issue)");
    }

    out.push({
      source: sighting.source,
      header: decoded.header,
      claims: decoded.claims,
      observations,
      raw_present: true,
    });
  }

  return out;
}

interface DecodedJwt {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
}

function decodeJwt(token: string): DecodedJwt | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(b64urlDecode(parts[0]));
    const claims = JSON.parse(b64urlDecode(parts[1]));
    if (typeof header !== "object" || typeof claims !== "object") return null;
    return { header, claims };
  } catch {
    return null;
  }
}

function b64urlDecode(input: string): string {
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  return Buffer.from(b64 + pad, "base64").toString("utf8");
}
