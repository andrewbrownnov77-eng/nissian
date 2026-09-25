/**
 * WAF-aware payload encoding — for CONFIRMING a vulnerability, not hiding.
 *
 * A WAF block is not proof an app is safe: the underlying bug can still be
 * present, merely masked by a signature filter. To write a truthful report we
 * need to know which it is. So when a payload is blocked, we retry with
 * semantically-equivalent encodings; if an encoding gets through AND the
 * underlying effect fires (proven by Stage 2's verdict logic), the finding is
 * real and the report should say "reachable via <encoding>, WAF partially
 * mitigates". If nothing gets through and no effect fires, we do not claim a
 * vulnerability.
 *
 * This is transformation for truth, not evasion of a defender. We deliberately
 * do not rotate IPs, forge identities, or try to slip past monitoring — that
 * belongs to attackers, violates most program rules, and corrupts results.
 */

export interface EncodingVariant {
  name: string;
  transform: (payload: string) => string;
}

/** Equivalent encodings ordered from most to least likely to be accepted. */
export const ENCODINGS: EncodingVariant[] = [
  { name: "raw", transform: (p) => p },
  { name: "url", transform: (p) => encodeURIComponent(p) },
  { name: "double-url", transform: (p) => encodeURIComponent(encodeURIComponent(p)) },
  { name: "mixed-case-keywords", transform: mixedCaseKeywords },
  { name: "html-entities", transform: htmlEntities },
  { name: "unicode-escape", transform: unicodeEscape },
];

/**
 * True when a response looks like a WAF block rather than the app's own answer:
 * a 403/406/501 with a short body, or a known block-page signature.
 */
export function looksLikeWafBlock(status: number, body: string): boolean {
  if ([403, 406, 501].includes(status) && body.length < 2000) return true;
  return /(request blocked|access denied|web application firewall|cloudflare|akamai|incapsula|mod_security)/i.test(body);
}

function mixedCaseKeywords(p: string): string {
  // Vary case of SQL/JS keywords — signature filters that match exact case miss these.
  return p.replace(/\b(select|union|script|alert|onerror|sleep|and|or)\b/gi, (m) =>
    m
      .split("")
      .map((c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase()))
      .join(""),
  );
}

function htmlEntities(p: string): string {
  return p.replace(/[<>"'&]/g, (c) => `&#${c.charCodeAt(0)};`);
}

function unicodeEscape(p: string): string {
  return p.replace(/[<>"']/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
