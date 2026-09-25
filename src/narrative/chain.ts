/**
 * Attack-chain synthesis — turn a pile of findings into a story.
 *
 * A raw curl proves a bug; a chain proves impact. We model each finding by the
 * capability it grants an attacker, then look for combinations where one
 * finding's capability feeds another — e.g. an info leak that enables user
 * enumeration, combined with an IDOR on an export endpoint, becomes
 * "dump every invoice without authentication".
 */

export interface NarrativeFinding {
  type: string; // "idor" | "xss" | "ssrf" | "sqli" | "cors" | "info-disclosure" | "user-enumeration" | ...
  endpoint: string;
  title?: string;
  severity?: string;
}

/** Capabilities a finding type grants an attacker. */
const CAPABILITIES: Record<string, string[]> = {
  cors: ["read-cross-origin", "enumeration"],
  "info-disclosure": ["enumeration", "recon"],
  "user-enumeration": ["enumeration"],
  idor: ["object-access"],
  bola: ["object-access"],
  sqli: ["data-read", "auth-bypass"],
  xss: ["session-theft", "ui-redress"],
  ssrf: ["internal-network", "metadata-access"],
  "auth-bypass": ["auth-bypass"],
};

export interface ChainRule {
  name: string;
  /** Ordered capability requirements; each must be met by some finding. */
  requires: string[];
  /** Endpoint keyword that makes the terminal finding high-impact (optional). */
  amplifierKeyword?: RegExp;
  buildNarrative: (steps: NarrativeFinding[]) => string;
}

const RULES: ChainRule[] = [
  {
    name: "Enumeration → IDOR bulk exposure",
    requires: ["enumeration", "object-access"],
    amplifierKeyword: /export|invoice|report|download|list|all|bulk/i,
    buildNarrative: (steps) => {
      const enumStep = steps.find((s) => grants(s, "enumeration"))!;
      const idorStep = steps.find((s) => grants(s, "object-access"))!;
      return (
        `An attacker first uses ${describe(enumStep)} to enumerate valid identifiers, ` +
        `then feeds those identifiers to the IDOR at \`${idorStep.endpoint}\` — ` +
        `iterating the enumerated set to extract every referenced object rather than a single one. ` +
        `Individually these look low/medium; chained, they yield bulk data exposure.`
      );
    },
  },
  {
    name: "SSRF → internal service / metadata reach",
    requires: ["internal-network"],
    buildNarrative: (steps) => {
      const ssrf = steps.find((s) => grants(s, "internal-network"))!;
      return (
        `The SSRF at \`${ssrf.endpoint}\` gives the attacker a request position inside the ` +
        `target's network. From there, internal-only services and cloud metadata endpoints ` +
        `(normally unreachable from outside) become candidates — turning an outbound-fetch bug ` +
        `into a pivot toward internal data. (Demonstrate reach with a controlled OOB endpoint; ` +
        `do not enumerate the target's real internal hosts.)`
      );
    },
  },
  {
    name: "XSS → session theft → account takeover",
    requires: ["session-theft"],
    buildNarrative: (steps) => {
      const xss = steps.find((s) => grants(s, "session-theft"))!;
      return (
        `The XSS at \`${xss.endpoint}\` executes attacker script in a victim's authenticated ` +
        `session. That script can read session material or act as the victim, escalating a ` +
        `"reflected string" into account takeover for anyone who opens the crafted link.`
      );
    },
  },
];

export interface AttackChain {
  rule: string;
  steps: NarrativeFinding[];
  narrative: string;
}

/** Find all attack chains supported by the given findings. */
export function chainFindings(findings: NarrativeFinding[]): AttackChain[] {
  const chains: AttackChain[] = [];
  for (const rule of RULES) {
    const steps: NarrativeFinding[] = [];
    let satisfied = true;
    for (const cap of rule.requires) {
      const match = findings.find((f) => grants(f, cap) && !steps.includes(f));
      if (!match) {
        satisfied = false;
        break;
      }
      steps.push(match);
    }
    if (!satisfied) continue;

    // If the rule wants an amplifier keyword, require some step to match it.
    if (rule.amplifierKeyword && !steps.some((s) => rule.amplifierKeyword!.test(s.endpoint))) {
      continue;
    }
    chains.push({ rule: rule.name, steps, narrative: rule.buildNarrative(steps) });
  }
  return chains;
}

function grants(finding: NarrativeFinding, capability: string): boolean {
  return (CAPABILITIES[finding.type] ?? []).includes(capability);
}

function describe(f: NarrativeFinding): string {
  return `${f.title ?? f.type} at \`${f.endpoint}\``;
}
