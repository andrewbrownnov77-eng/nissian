/**
 * Coverage gap report — the "here's what I did NOT test, and why" section.
 *
 * This is what turns the tool from a shotgun into a hunting partner: it states
 * coverage as a percentage and lists every gap with an actionable reason, so the
 * operator knows exactly what to unlock and re-scan.
 */

import type { CoverageReport, GapReason } from "./diff.js";

const REASON_LABEL: Record<GapReason, string> = {
  tested: "tested",
  "auth-required": "locked — needs auth (401)",
  forbidden: "locked — needs a role you don't have (403)",
  "not-found": "not found (404)",
  "server-error": "errored (5xx)",
  "never-attempted": "never reached",
};

export function renderCoverage(report: CoverageReport): string {
  const out: string[] = [];
  out.push(`# Coverage gap report`);
  out.push("");
  out.push(`Tested **${report.tested} / ${report.totalKnown}** known endpoints — **${report.coveragePct}%** coverage.`);
  out.push("");

  if (report.gaps.length === 0) {
    out.push(`_No gaps: every declared endpoint was exercised._`);
    return out.join("\n");
  }

  // Group gaps by reason so the operator sees the actionable buckets.
  const byReason = new Map<GapReason, typeof report.gaps>();
  for (const g of report.gaps) {
    const list = byReason.get(g.reason) ?? [];
    list.push(g);
    byReason.set(g.reason, list);
  }

  for (const [reason, gaps] of byReason) {
    out.push(`## ${REASON_LABEL[reason]} — ${gaps.length}`);
    for (const g of gaps) {
      const statuses = g.observedStatuses.length ? ` [saw ${uniq(g.observedStatuses).join(",")}]` : "";
      out.push(`- \`${g.endpoint.method} ${g.endpoint.pathTemplate}\`${statuses}`);
      if (g.recommendation) out.push(`    → ${g.recommendation}`);
    }
    out.push("");
  }

  return out.join("\n");
}

function uniq(nums: number[]): number[] {
  return [...new Set(nums)].sort((a, b) => a - b);
}
