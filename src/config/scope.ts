/**
 * Scope enforcement — the foundation of the whole tool.
 *
 * A bug bounty program authorizes testing only against specific assets. This
 * module loads that authorization and answers one question everywhere else in
 * the code asks: "am I allowed to touch this host?"
 *
 * Policy is "allowlist + warnings":
 *   - Only hosts matching an in-scope pattern may be *navigated to or tested*.
 *   - Out-of-scope hosts observed passively (e.g. a third-party API a page
 *     calls) are recorded as warnings for manual review — never acted on.
 *
 * This is not a restriction on the user; it is what lets everything downstream
 * run hard without hesitation, because "is this authorized?" is already answered.
 */

import { readFile } from "node:fs/promises";

export interface ScopeConfig {
  /** Human-readable program name, for reports. */
  program: string;
  /**
   * In-scope host patterns. Supports a leading "*." wildcard for subdomains,
   * e.g. "*.example.com" matches "api.example.com" and "example.com".
   */
  inScope: string[];
  /** Explicit out-of-scope patterns; these override inScope matches. */
  outOfScope: string[];
  /**
   * Allowed active test types. The analysis stages consult this before
   * generating any active probe. Absence means "passive only".
   */
  allowedTestTypes: TestType[];
  /** Politeness / safety limits so we never hammer a target. */
  rateLimit: {
    maxRequestsPerSecond: number;
    maxConcurrency: number;
  };
}

export type TestType =
  | "passive-observation"
  | "idor-probe"
  | "token-manipulation"
  | "reflected-input"
  | "auth-workflow";

export class Scope {
  private readonly inScope: HostPattern[];
  private readonly outOfScope: HostPattern[];

  constructor(public readonly config: ScopeConfig) {
    this.inScope = config.inScope.map(compilePattern);
    this.outOfScope = config.outOfScope.map(compilePattern);
  }

  static async load(path: string): Promise<Scope> {
    const raw = await readFile(path, "utf8");
    const parsed = JSON.parse(raw) as Partial<ScopeConfig>;
    validate(parsed);
    // Fill safe defaults.
    const config: ScopeConfig = {
      program: parsed.program!,
      inScope: parsed.inScope!,
      outOfScope: parsed.outOfScope ?? [],
      allowedTestTypes: parsed.allowedTestTypes ?? ["passive-observation"],
      rateLimit: {
        maxRequestsPerSecond: parsed.rateLimit?.maxRequestsPerSecond ?? 4,
        maxConcurrency: parsed.rateLimit?.maxConcurrency ?? 4,
      },
    };
    return new Scope(config);
  }

  /** True only if the host is in-scope AND not explicitly excluded. */
  isInScope(host: string): boolean {
    const h = host.toLowerCase();
    if (this.outOfScope.some((p) => p.matches(h))) return false;
    return this.inScope.some((p) => p.matches(h));
  }

  /** True if an out-of-scope rule explicitly names this host. */
  isExplicitlyExcluded(host: string): boolean {
    return this.outOfScope.some((p) => p.matches(host.toLowerCase()));
  }

  allows(test: TestType): boolean {
    return this.config.allowedTestTypes.includes(test);
  }
}

interface HostPattern {
  matches(host: string): boolean;
}

function compilePattern(pattern: string): HostPattern {
  const p = pattern.trim().toLowerCase();
  if (p.startsWith("*.")) {
    const base = p.slice(2);
    return {
      matches: (host) => host === base || host.endsWith("." + base),
    };
  }
  return { matches: (host) => host === p };
}

function validate(parsed: Partial<ScopeConfig>): void {
  if (!parsed.program || typeof parsed.program !== "string") {
    throw new ScopeError("scope file must include a 'program' name");
  }
  if (!Array.isArray(parsed.inScope) || parsed.inScope.length === 0) {
    throw new ScopeError(
      "scope file must include a non-empty 'inScope' array — refusing to run with no authorized targets",
    );
  }
}

export class ScopeError extends Error {}
