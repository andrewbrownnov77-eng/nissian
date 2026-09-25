/**
 * Safety-mechanism analysis — the false-positive killer.
 *
 * Before we claim a vulnerability, we ask whether the target's own defenses
 * already neutralize it. A reflected string behind a strict CSP is not XSS. A
 * database stack trace with no controllable parameter is not SQLi. Encoding
 * this reasoning is what stops us shipping the reports triagers close in four
 * seconds.
 */

export interface CspAnalysis {
  present: boolean;
  /** Does the policy allow inline script execution? */
  allowsInlineScript: boolean;
  /** Does it use 'unsafe-eval'? */
  allowsEval: boolean;
  /** True if the policy would plausibly block a reflected inline-script XSS. */
  blocksReflectedXss: boolean;
  raw?: string;
}

/** Parse a Content-Security-Policy header enough to reason about script-src. */
export function analyzeCsp(headers: Record<string, string>): CspAnalysis {
  const raw = headers["content-security-policy"];
  if (!raw) {
    return { present: false, allowsInlineScript: true, allowsEval: true, blocksReflectedXss: false };
  }

  const directives = parseCsp(raw);
  // script-src falls back to default-src when absent.
  const scriptSrc = directives["script-src"] ?? directives["default-src"] ?? [];
  const tokens = new Set(scriptSrc.map((t) => t.toLowerCase()));

  const allowsInlineScript = tokens.has("'unsafe-inline'");
  const allowsEval = tokens.has("'unsafe-eval'");

  // A nonce/hash-based or source-list policy without 'unsafe-inline' blocks a
  // naive reflected inline-script payload.
  const hasNonceOrHash = scriptSrc.some((t) => /^'(nonce-|sha(256|384|512)-)/i.test(t));
  const hasSourceList = scriptSrc.length > 0 && !tokens.has("*");
  const blocksReflectedXss = scriptSrc.length > 0 && !allowsInlineScript && (hasNonceOrHash || hasSourceList);

  return { present: true, allowsInlineScript, allowsEval, blocksReflectedXss, raw };
}

function parseCsp(raw: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const part of raw.split(";")) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name) out[name.toLowerCase()] = values;
  }
  return out;
}

/**
 * Distinguish a genuinely injectable SQL context from a bare error/stack trace.
 *
 * A DB error string in a response only matters if OUR injected token changed
 * the app's behavior. This helper reports whether the error signature is a
 * known DB error AND whether it correlates with our marker — the caller supplies
 * both a baseline (no marker) and probed body.
 */
export interface SqlErrorAnalysis {
  looksLikeDbError: boolean;
  errorSignature?: string;
  /** True only if the error appears with our injection but not in baseline. */
  triggeredByInjection: boolean;
}

const DB_ERROR_SIGNATURES: Array<[string, RegExp]> = [
  ["MySQL", /you have an error in your sql syntax|mysql_fetch|warning: mysql/i],
  ["PostgreSQL", /pg_query|unterminated quoted string|syntax error at or near/i],
  ["MSSQL", /unclosed quotation mark|microsoft odbc|incorrect syntax near/i],
  ["Oracle", /ora-\d{5}|oracle error/i],
  ["SQLite", /sqlite3?::|sqlite_error|unrecognized token/i],
];

export function analyzeSqlError(baselineBody: string, probedBody: string): SqlErrorAnalysis {
  for (const [name, re] of DB_ERROR_SIGNATURES) {
    const inProbed = re.test(probedBody);
    const inBaseline = re.test(baselineBody);
    if (inProbed) {
      return {
        looksLikeDbError: true,
        errorSignature: name,
        // Only meaningful if injection introduced the error.
        triggeredByInjection: inProbed && !inBaseline,
      };
    }
  }
  return { looksLikeDbError: false, triggeredByInjection: false };
}

/** X-XSS-Protection is legacy but still worth noting when present and blocking. */
export function xssProtectionBlocks(headers: Record<string, string>): boolean {
  const v = headers["x-xss-protection"];
  if (!v) return false;
  // "1; mode=block" is the blocking form; "0" disables it.
  return /(^|;)\s*1/.test(v) && /mode=block/i.test(v);
}
