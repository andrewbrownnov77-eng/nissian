/**
 * Validation types — the zero-false-positive core.
 *
 * Stage 1 produces *candidates*. Stage 2 turns each candidate into a Finding
 * with a Verdict backed by Evidence. The rule the whole stage enforces:
 * only CONFIRMED findings, each with a reproducible PoC, reach a report.
 */

export type Verdict =
  /** Exploitability was demonstrated with concrete, reproducible evidence. */
  | "CONFIRMED"
  /** A safety mechanism (CSP, prepared statement, output encoding, …) or the
   *  absence of the effect ruled it out. Recorded so we don't re-test it. */
  | "REFUTED"
  /** Neither confirmed nor cleanly refuted — needs a human or more signal.
   *  Never reported as a vulnerability. */
  | "INCONCLUSIVE";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** A single piece of proof attached to a finding. */
export interface Evidence {
  kind:
    | "timing-differential"
    | "oob-interaction"
    | "cross-identity-access"
    | "script-execution"
    | "response-diff"
    | "header-analysis";
  summary: string;
  /** Machine-readable detail (samples, callback record, diff, …). */
  detail: Record<string, unknown>;
}

/** A reproducible proof-of-concept: what the spec calls "60-second repro". */
export interface ProofOfConcept {
  /** A single curl command that reproduces the effect where possible. */
  curl?: string;
  /** Ordered, minimal reproduction steps. */
  steps: string[];
  /** The observable result a reviewer should see. */
  expectedObservation: string;
}

export interface Finding {
  id: string;
  title: string;
  type: string;
  severity: Severity;
  verdict: Verdict;
  endpoint: string;
  method: string;
  evidence: Evidence[];
  poc?: ProofOfConcept;
  /** Why we reached this verdict — including what was ruled out. */
  reasoning: string;
}

export interface ValidationResult {
  target: string;
  startedAt: string;
  finishedAt: string;
  findings: Finding[];
  /** Candidates we looked at but could not confirm, for transparency. */
  refuted: Finding[];
  inconclusive: Finding[];
}
