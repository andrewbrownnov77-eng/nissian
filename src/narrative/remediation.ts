/**
 * Stack-aware remediation.
 *
 * "Sanitize inputs" is useless advice. This tailors the fix to the stack we
 * actually detected (from response headers, framework fingerprints, etc.), so
 * the remediation is something the team can act on directly.
 */

import type { NarrativeFinding } from "./chain.js";

export interface StackSignals {
  /** Lowercased tokens like "react", "nginx", "express", "spring-boot", "rails". */
  frameworks: string[];
  server?: string;
}

/** Detect stack tokens from response headers / body markers. */
export function detectStack(headers: Record<string, string>, bodySample = ""): StackSignals {
  const frameworks = new Set<string>();
  const hv = Object.entries(headers).map(([k, v]) => `${k}:${v}`.toLowerCase()).join(" ");
  const hay = `${hv} ${bodySample.toLowerCase()}`;

  const MARKERS: Array<[string, RegExp]> = [
    ["react", /react|__next_data__|data-reactroot/],
    ["nextjs", /next\.js|_next\/static/],
    ["express", /x-powered-by:\s*express/],
    ["spring-boot", /x-application-context|whitelabel error page|jsessionid/],
    ["rails", /x-powered-by:.*phusion|_rails|csrf-token/],
    ["django", /csrftoken|wsgiserver/],
    ["php", /x-powered-by:\s*php|phpsessid/],
  ];
  for (const [name, re] of MARKERS) if (re.test(hay)) frameworks.add(name);

  const serverMatch = headers["server"];
  return { frameworks: [...frameworks], server: serverMatch };
}

export function remediationFor(finding: NarrativeFinding, stack: StackSignals): string {
  const fw = new Set(stack.frameworks);
  const bits: string[] = [];

  switch (finding.type) {
    case "xss":
      if (fw.has("react") || fw.has("nextjs")) {
        bits.push("You're on React — its JSX auto-escapes, so this almost certainly comes from a `dangerouslySetInnerHTML` sink or an injected `<script>`/URL. Remove the raw-HTML sink or sanitize with DOMPurify before it.");
      } else {
        bits.push("Contextually output-encode the reflected value for its exact sink (HTML body, attribute, JS string, URL).");
      }
      bits.push("Add a strict CSP: `script-src 'self' 'nonce-…'` without `'unsafe-inline'`.");
      if (stack.server && /nginx/i.test(stack.server)) {
        bits.push("On nginx, set `add_header X-Frame-Options DENY;` and `add_header Content-Security-Policy \"…\";` at the server block so it applies uniformly.");
      }
      break;
    case "idor":
    case "bola":
      bits.push("Enforce object-level authorization server-side: verify the authenticated principal owns/may access the referenced object before returning it.");
      if (fw.has("rails")) bits.push("In Rails, scope queries through the current user (`current_user.invoices.find(params[:id])`) rather than `Invoice.find`.");
      if (fw.has("spring-boot")) bits.push("In Spring, add a `@PreAuthorize`/method-security check that ties the object to the principal.");
      break;
    case "sqli":
      bits.push("Use parameterized queries / prepared statements; never concatenate input into SQL.");
      if (fw.has("php")) bits.push("In PHP, use PDO prepared statements with bound parameters.");
      if (fw.has("django")) bits.push("In Django, use the ORM or `params=` with `.raw()` — never string-format SQL.");
      break;
    case "ssrf":
      bits.push("Allowlist outbound destinations, resolve+pin IPs and block link-local/metadata ranges (169.254.169.254), and disable unused URL schemes/redirects to internal hosts.");
      break;
    case "cors":
      bits.push("Do not reflect arbitrary `Origin` into `Access-Control-Allow-Origin` with credentials; use a strict allowlist and avoid `Allow-Credentials: true` on wildcard origins.");
      break;
    default:
      bits.push("Validate input and enforce least privilege for the affected component.");
  }
  return bits.join(" ");
}
