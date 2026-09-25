/**
 * Validation runner — orchestrates probes and partitions results by verdict.
 *
 * Reads a validation plan (targets + identities + OOB settings), runs the
 * relevant probes through the scope-gated client, and sorts findings into
 * confirmed / refuted / inconclusive. Only confirmed findings become a report.
 */

import { Scope } from "../config/scope.js";
import { ProbeClient } from "./http-client.js";
import { OobCollector } from "./oob.js";
import { validateSqli, type SqliTarget } from "./probes/sqli.js";
import { validateSsrf, type SsrfTarget } from "./probes/ssrf.js";
import { validateIdor, type IdorTarget, type Identity } from "./probes/idor.js";
import { validateXss, type XssTarget } from "./probes/xss.js";
import type { Finding, ValidationResult } from "./types.js";

export interface ValidationPlan {
  target: string;
  identities?: Record<string, Identity>;
  oob?: { publicBaseUrl: string; port: number };
  sqli?: SqliTarget[];
  ssrf?: SsrfTarget[];
  xss?: XssTarget[];
  idor?: Array<IdorTarget & { attacker: string; victim: string }>;
}

export async function runValidation(scope: Scope, plan: ValidationPlan): Promise<ValidationResult> {
  const client = new ProbeClient(scope);
  const startedAt = new Date().toISOString();
  const all: Finding[] = [];

  for (const t of plan.sqli ?? []) {
    all.push(await validateSqli(client, t));
  }

  for (const t of plan.xss ?? []) {
    all.push(await validateXss(scope, t));
  }

  if (plan.idor?.length) {
    for (const t of plan.idor) {
      const attacker = plan.identities?.[t.attacker];
      const victim = plan.identities?.[t.victim];
      if (!attacker || !victim) {
        throw new Error(`IDOR target references unknown identity '${t.attacker}' or '${t.victim}'`);
      }
      all.push(await validateIdor(client, attacker, victim, t));
    }
  }

  if (plan.ssrf?.length) {
    if (!plan.oob) throw new Error("ssrf targets require an 'oob' collector config");
    const oob = new OobCollector(plan.oob.publicBaseUrl, plan.oob.port);
    await oob.start();
    try {
      for (const t of plan.ssrf) all.push(await validateSsrf(client, oob, t));
    } finally {
      await oob.stop();
    }
  }

  return {
    target: plan.target,
    startedAt,
    finishedAt: new Date().toISOString(),
    findings: all.filter((f) => f.verdict === "CONFIRMED"),
    refuted: all.filter((f) => f.verdict === "REFUTED"),
    inconclusive: all.filter((f) => f.verdict === "INCONCLUSIVE"),
  };
}
