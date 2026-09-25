/**
 * Confidence scoring + threshold suppression.
 *
 * Not every candidate deserves the triager's eyes. We score each finding's
 * confidence from its verdict and the strength of its evidence, then suppress
 * anything below a threshold into an appendix — kept, not deleted, because the
 * operator might disagree with the machine.
 */

import type { Finding } from "../validate/types.js";

/** Evidence kinds that constitute strong, direct proof of exploitability. */
const STRONG_EVIDENCE = new Set(["oob-interaction", "cross-identity-access", "script-execution", "timing-differential"]);

export function confidenceScore(finding: Finding): number {
  let score = 0;

  // Verdict is the dominant signal.
  if (finding.verdict === "CONFIRMED") score += 0.6;
  else if (finding.verdict === "INCONCLUSIVE") score += 0.2;
  // REFUTED contributes 0.

  // Strong evidence raises confidence; weak/among-only header analysis less so.
  const strong = finding.evidence.filter((e) => STRONG_EVIDENCE.has(e.kind)).length;
  score += Math.min(0.3, strong * 0.15);

  // A reproducible PoC is a strong confidence signal on its own.
  if (finding.poc?.curl) score += 0.1;

  return Math.min(1, Math.round(score * 100) / 100);
}

export interface ScoredFinding {
  finding: Finding;
  confidence: number;
}

export function scoreAll(findings: Finding[]): ScoredFinding[] {
  return findings.map((finding) => ({ finding, confidence: confidenceScore(finding) }));
}
