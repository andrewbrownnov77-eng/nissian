/**
 * Format-perfect output — HackerOne-style and custom templates.
 *
 * Programs want reports in a predictable shape: title, severity, CWE, CVSS,
 * impact, steps to reproduce, PoC, and a remediation that fits the stack. This
 * renders a confirmed Finding into copy-paste-ready markdown for the target
 * platform, or via a caller-supplied template.
 */

import type { Finding, Severity } from "../validate/types.js";

/** Minimal CWE + CVSS-ish metadata per finding type, for the report header. */
const TYPE_META: Record<string, { cwe: string; cvss: string; remediation: string }> = {
  sqli: {
    cwe: "CWE-89: SQL Injection",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    remediation:
      "Use parameterized queries / prepared statements for every database call; never concatenate user input into SQL. Apply least-privilege DB accounts so an injection cannot read unrelated tables.",
  },
  xss: {
    cwe: "CWE-79: Cross-site Scripting",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    remediation:
      "Contextually output-encode all user-controlled data, and deploy a strict Content-Security-Policy (nonce- or hash-based script-src without 'unsafe-inline'). Framework auto-escaping should not be bypassed with raw-HTML sinks.",
  },
  ssrf: {
    cwe: "CWE-918: Server-Side Request Forgery",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L",
    remediation:
      "Validate and allowlist outbound URLs, resolve and pin destination IPs (blocking link-local/metadata ranges like 169.254.169.254), and disable unused URL schemes. Do not follow redirects to internal hosts.",
  },
  idor: {
    cwe: "CWE-639: Authorization Bypass Through User-Controlled Key",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    remediation:
      "Enforce object-level authorization on every request: verify the authenticated principal owns (or is granted) the referenced object server-side, rather than trusting the client-supplied identifier.",
  },
};

export type ReportFormat = "hackerone" | "plain";

export function renderFinding(finding: Finding, format: ReportFormat = "hackerone"): string {
  const meta = TYPE_META[finding.type] ?? {
    cwe: "CWE-Unknown",
    cvss: "n/a",
    remediation: "Apply input validation and least-privilege appropriate to the affected component.",
  };

  if (format === "plain") return renderPlain(finding, meta);
  return renderHackerOne(finding, meta);
}

function renderHackerOne(finding: Finding, meta: { cwe: string; cvss: string; remediation: string }): string {
  const out: string[] = [];
  out.push(`## Title`);
  out.push(finding.title);
  out.push("");
  out.push(`## Severity`);
  out.push(`${finding.severity.toUpperCase()} — \`${meta.cvss}\``);
  out.push("");
  out.push(`## Weakness`);
  out.push(meta.cwe);
  out.push("");
  out.push(`## Summary`);
  out.push(finding.reasoning);
  out.push("");
  out.push(`## Steps To Reproduce`);
  if (finding.poc?.curl) {
    out.push("```bash");
    out.push(finding.poc.curl);
    out.push("```");
  }
  (finding.poc?.steps ?? []).forEach((s, i) => out.push(`${i + 1}. ${s}`));
  out.push("");
  out.push(`## Proof / Evidence`);
  for (const e of finding.evidence) out.push(`- **${e.kind}**: ${e.summary}`);
  out.push("");
  if (finding.poc) {
    out.push(`## Impact`);
    out.push(finding.poc.expectedObservation);
    out.push("");
  }
  out.push(`## Remediation`);
  out.push(meta.remediation);
  return out.join("\n");
}

function renderPlain(finding: Finding, meta: { cwe: string; cvss: string; remediation: string }): string {
  return [
    `${finding.title} [${finding.severity.toUpperCase()}] ${meta.cwe}`,
    finding.reasoning,
    finding.poc?.curl ? `PoC: ${finding.poc.curl}` : "",
    `Fix: ${meta.remediation}`,
  ]
    .filter(Boolean)
    .join("\n");
}

/**
 * Render via a caller-supplied template string. Supported placeholders:
 * {{title}} {{severity}} {{cwe}} {{cvss}} {{summary}} {{curl}} {{remediation}}
 */
export function renderCustom(finding: Finding, template: string): string {
  const meta = TYPE_META[finding.type] ?? { cwe: "CWE-Unknown", cvss: "n/a", remediation: "" };
  const map: Record<string, string> = {
    title: finding.title,
    severity: finding.severity.toUpperCase(),
    cwe: meta.cwe,
    cvss: meta.cvss,
    summary: finding.reasoning,
    curl: finding.poc?.curl ?? "",
    remediation: meta.remediation,
  };
  return template.replace(/\{\{(\w+)\}\}/g, (_, k: string) => map[k] ?? "");
}

export function severityRank(s: Severity): number {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s];
}
