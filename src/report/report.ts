/**
 * Report renderer.
 *
 * Renders ONLY confirmed findings into a clean, triager-friendly Markdown
 * report — each with its evidence and a 60-second PoC. Refuted and inconclusive
 * candidates are summarized separately so the researcher has full visibility
 * without those ever reaching the program as noise.
 */

import type { ValidationResult, Finding } from "../validate/types.js";

export function renderReport(result: ValidationResult): string {
  const out: string[] = [];
  out.push(`# Findings — ${result.target}`);
  out.push(`Validated ${result.startedAt} → ${result.finishedAt}`);
  out.push("");
  out.push(`**Confirmed: ${result.findings.length}** · Refuted: ${result.refuted.length} · Inconclusive: ${result.inconclusive.length}`);
  out.push("");

  if (result.findings.length === 0) {
    out.push("_No findings were confirmed. Nothing to report — this is a success, not a failure: it means no false positives will waste a triager's time._");
  }

  for (const f of sortBySeverity(result.findings)) {
    out.push(`## ${f.title} — ${f.severity.toUpperCase()}`);
    out.push(`**Endpoint:** \`${f.method} ${f.endpoint}\``);
    out.push("");
    out.push(`**Summary:** ${f.reasoning}`);
    out.push("");
    out.push(`### Evidence`);
    for (const e of f.evidence) out.push(`- _${e.kind}_ — ${e.summary}`);
    out.push("");
    if (f.poc) {
      out.push(`### Proof of concept (reproduce in ~60s)`);
      if (f.poc.curl) {
        out.push("```bash");
        out.push(f.poc.curl);
        out.push("```");
      }
      out.push("");
      f.poc.steps.forEach((s, i) => out.push(`${i + 1}. ${s}`));
      out.push("");
      out.push(`**Expected:** ${f.poc.expectedObservation}`);
      out.push("");
    }
  }

  if (result.refuted.length || result.inconclusive.length) {
    out.push(`---`);
    out.push(`## Not reported (transparency)`);
    for (const f of [...result.refuted, ...result.inconclusive]) {
      out.push(`- **${f.title}** \`${f.endpoint}\` → ${f.verdict}: ${f.reasoning}`);
    }
  }

  return out.join("\n");
}

const ORDER: Record<Finding["severity"], number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
}
