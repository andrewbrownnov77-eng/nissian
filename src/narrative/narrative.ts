/**
 * Narrative composer — assembles the human-readable story.
 *
 * Produces a report that leads with the chained attack narrative (the part that
 * sells impact), then per-finding business impact and stack-aware remediation.
 */

import { chainFindings, type NarrativeFinding } from "./chain.js";
import { businessImpact } from "./impact.js";
import { remediationFor, type StackSignals } from "./remediation.js";

export interface NarrativeInput {
  findings: NarrativeFinding[];
  stack: StackSignals;
}

export function composeNarrative(input: NarrativeInput): string {
  const out: string[] = [];
  const chains = chainFindings(input.findings);

  out.push(`# Attack narrative & impact`);
  out.push("");
  if (input.stack.frameworks.length || input.stack.server) {
    out.push(`_Inferred stack: ${[...input.stack.frameworks, input.stack.server].filter(Boolean).join(", ")}._`);
    out.push("");
  }

  if (chains.length) {
    out.push(`## Chained attack paths`);
    for (const c of chains) {
      out.push(`### ${c.rule}`);
      out.push(c.narrative);
      out.push(`_Steps: ${c.steps.map((s) => `\`${s.endpoint}\``).join(" → ")}_`);
      out.push("");
    }
  } else {
    out.push(`_No multi-finding chains detected; findings assessed individually below._`);
    out.push("");
  }

  out.push(`## Per-finding impact & remediation`);
  for (const f of input.findings) {
    out.push(`### ${f.title ?? f.type} — \`${f.endpoint}\``);
    out.push(`**Business impact:** ${businessImpact(f)}`);
    out.push(`**Remediation:** ${remediationFor(f, input.stack)}`);
    out.push("");
  }

  return out.join("\n");
}
