/**
 * Autonomous triage — decide what to file, what to shelve, and what's a dup.
 *
 * Combines confidence scoring and duplicate detection into a single decision per
 * finding:
 *   - FILE:      confident enough AND not a duplicate → goes to the operator.
 *   - APPENDIX:  below the confidence threshold → kept for operator review, not filed.
 *   - DUPLICATE: matches a prior/disclosed report → not filed, with the match named.
 *
 * Nothing is discarded; the operator always sees the full picture and can
 * override any call.
 */

import type { Finding } from "../validate/types.js";
import { scoreAll } from "./confidence.js";
import { detectDuplicate, type PriorArtifact, type DuplicateVerdict } from "./dedup.js";

export type Disposition = "file" | "appendix" | "duplicate";

export interface TriagedFinding {
  finding: Finding;
  confidence: number;
  disposition: Disposition;
  duplicate: DuplicateVerdict;
}

export interface TriageResult {
  toFile: TriagedFinding[];
  appendix: TriagedFinding[];
  duplicates: TriagedFinding[];
}

export function triage(
  findings: Finding[],
  priors: PriorArtifact[],
  confidenceThreshold = 0.6,
): TriageResult {
  const result: TriageResult = { toFile: [], appendix: [], duplicates: [] };

  for (const { finding, confidence } of scoreAll(findings)) {
    const dup = detectDuplicate(finding, priors);
    let disposition: Disposition;
    if (dup.isDuplicate) disposition = "duplicate";
    else if (confidence < confidenceThreshold) disposition = "appendix";
    else disposition = "file";

    const entry: TriagedFinding = { finding, confidence, disposition, duplicate: dup };
    if (disposition === "file") result.toFile.push(entry);
    else if (disposition === "appendix") result.appendix.push(entry);
    else result.duplicates.push(entry);
  }

  // File highest-confidence first.
  result.toFile.sort((a, b) => b.confidence - a.confidence);
  return result;
}

export function renderTriage(result: TriageResult): string {
  const out: string[] = [];
  out.push(`# Triage decision`);
  out.push("");
  out.push(`**File: ${result.toFile.length}** · Appendix (low-confidence): ${result.appendix.length} · Duplicates: ${result.duplicates.length}`);
  out.push("");

  section(out, "✅ Ready to file", result.toFile, true);
  section(out, "📎 Appendix — below confidence threshold (review, not auto-filed)", result.appendix, true);
  section(out, "♻️ Suppressed as duplicates", result.duplicates, false);

  return out.join("\n");
}

function section(out: string[], heading: string, items: TriagedFinding[], showConfidence: boolean): void {
  if (items.length === 0) return;
  out.push(`## ${heading}`);
  for (const t of items) {
    const conf = showConfidence ? ` _(confidence ${Math.round(t.confidence * 100)}%)_` : "";
    out.push(`- **${t.finding.title}** \`${t.finding.endpoint}\`${conf}`);
    if (t.disposition === "duplicate") out.push(`    → ${t.duplicate.reason}`);
  }
  out.push("");
}
