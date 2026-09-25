/**
 * Assembles the final DiscoveryResult and renders a human summary.
 *
 * Stage 1's job is to hand Stage 2 (active analysis) a clean, structured map of
 * the attack surface — plus a readable summary so a human can sanity-check
 * before anything active runs.
 */

import { writeFile } from "node:fs/promises";
import type { DiscoveryResult } from "../types.js";

export async function writeResult(path: string, result: DiscoveryResult): Promise<void> {
  await writeFile(path, JSON.stringify(result, null, 2), "utf8");
}

export function summarize(result: DiscoveryResult): string {
  const lines: string[] = [];
  lines.push(`# Discovery summary — ${result.target}`);
  lines.push(`Ran ${result.startedAt} → ${result.finishedAt}`);
  lines.push("");
  lines.push(`Captured exchanges : ${result.requests.length}`);
  lines.push(`Identifiers found  : ${result.identifiers.length}`);
  lines.push(`IDOR/BOLA candidates: ${result.accessControlCandidates.length}`);
  lines.push(`Tokens analyzed    : ${result.tokens.length}`);
  lines.push(`Scope warnings     : ${result.scopeWarnings.length}`);
  lines.push("");

  if (result.accessControlCandidates.length) {
    lines.push("## Access-control candidates (verify before testing)");
    for (const c of result.accessControlCandidates.slice(0, 25)) {
      lines.push(`- ${c.endpointTemplate}`);
      lines.push(`    ${c.rationale}`);
    }
    lines.push("");
  }

  const notableTokens = result.tokens.filter((t) => t.observations.length);
  if (notableTokens.length) {
    lines.push("## Token observations");
    for (const t of notableTokens) {
      lines.push(`- from ${t.source}:`);
      for (const o of t.observations) lines.push(`    • ${o}`);
    }
    lines.push("");
  }

  if (result.scopeWarnings.length) {
    lines.push("## Out-of-scope hosts observed (blocked, not tested)");
    for (const w of result.scopeWarnings.slice(0, 25)) {
      lines.push(`- ${w.host} — ${w.reason}`);
    }
  }

  return lines.join("\n");
}
