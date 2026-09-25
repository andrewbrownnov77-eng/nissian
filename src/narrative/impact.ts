/**
 * Business-impact mapping.
 *
 * Triagers score impact, not cleverness. This translates a technical finding
 * into the concrete business consequence, sharpened by what the affected
 * endpoint appears to touch (payments, PII, donations, auth).
 */

import type { NarrativeFinding } from "./chain.js";

interface ContextHint {
  keyword: RegExp;
  noun: string;
  consequence: string;
}

// Order matters: more-specific contexts first, so /donate/checkout is scored
// as a donation page rather than a generic payment flow.
const CONTEXTS: ContextHint[] = [
  { keyword: /donat/i, noun: "donation page", consequence: "an injected fake payment form could siphon donor card details before your processor ever sees them" },
  { keyword: /pay|checkout|card|stripe|billing|charge/i, noun: "payment flow", consequence: "attackers could intercept or manipulate payments and card data" },
  { keyword: /invoice|report|export|statement/i, noun: "financial records", consequence: "confidential financial records could be exfiltrated at scale" },
  { keyword: /user|account|profile|pii|ssn|dob/i, noun: "user data", consequence: "personal data could be exposed, enabling fraud and privacy-law liability" },
  { keyword: /admin|internal|backup|config/i, noun: "administrative surface", consequence: "administrative or infrastructure control could be reached" },
];

const BASE_IMPACT: Record<string, string> = {
  idor: "one user can read or modify another user's data",
  sqli: "the database can be read or altered directly",
  ssrf: "the server can be coerced into making requests on the attacker's behalf",
  xss: "an attacker can run script in victims' authenticated sessions",
  cors: "another origin can read authenticated responses",
  "info-disclosure": "internal details useful for further attacks are leaked",
};

export function businessImpact(finding: NarrativeFinding): string {
  const base = BASE_IMPACT[finding.type] ?? "the application's security is weakened";
  const ctx = CONTEXTS.find((c) => c.keyword.test(finding.endpoint));
  if (ctx) {
    return `Because this affects the ${ctx.noun}, ${ctx.consequence} — concretely, ${base}.`;
  }
  return `Impact: ${base}.`;
}
