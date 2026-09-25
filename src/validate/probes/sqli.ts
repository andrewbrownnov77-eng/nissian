/**
 * Blind SQL injection validator (time-based), with error-based cross-check.
 *
 * Proof of exploitability, per the spec: make the target pause for a detectable,
 * repeatable delay we control. We send matched baseline (no delay) and delayed
 * payloads multiple times and require a statistically clean separation before
 * confirming. We also rule out the "it's just a stack trace" false positive.
 */

import { randomUUID } from "node:crypto";
import type { ProbeClient } from "../http-client.js";
import { analyzeTiming } from "../timing.js";
import { analyzeSqlError } from "../safety.js";
import { buildPoc } from "../../report/poc.js";
import type { Finding, Evidence } from "../types.js";

export interface SqliTarget {
  /** Full URL with the parameter to test, using {INJECT} as the marker. */
  urlTemplate: string;
  method?: string;
  headers?: Record<string, string>;
  /** Body template (also using {INJECT}) for POST/PUT. */
  bodyTemplate?: string;
}

const DELAY_MS = 3000;
const SAMPLES = 5;

/** A benign time-delay payload for a few common engines. Sleep is reversible/no-op. */
function delayPayload(): string {
  // Portable-ish: MySQL SLEEP, Postgres pg_sleep, MSSQL WAITFOR. We test one
  // engine-agnostic form; a real run would iterate per detected engine.
  return `1' AND SLEEP(${DELAY_MS / 1000})-- -`;
}
function baselinePayload(): string {
  return `1' AND SLEEP(0)-- -`;
}

export async function validateSqli(client: ProbeClient, target: SqliTarget): Promise<Finding> {
  const method = target.method ?? "GET";
  const id = randomUUID();

  const render = (payload: string) => ({
    url: target.urlTemplate.replace("{INJECT}", encodeURIComponent(payload)),
    body: target.bodyTemplate?.replace("{INJECT}", payload),
  });

  const baselineTimes: number[] = [];
  const delayedTimes: number[] = [];
  let baselineBody = "";
  let probedBody = "";

  for (let i = 0; i < SAMPLES; i++) {
    const base = render(baselinePayload());
    const baseRes = await client.send({
      url: base.url, method, headers: target.headers, body: base.body,
      testType: "reflected-input",
    });
    baselineTimes.push(baseRes.elapsedMs);
    baselineBody = baseRes.body;

    const del = render(delayPayload());
    const delRes = await client.send({
      url: del.url, method, headers: target.headers, body: del.body,
      testType: "reflected-input",
    });
    delayedTimes.push(delRes.elapsedMs);
    probedBody = delRes.body;
  }

  const timing = analyzeTiming(baselineTimes, delayedTimes, DELAY_MS);
  const sqlError = analyzeSqlError(baselineBody, probedBody);

  const evidence: Evidence[] = [
    {
      kind: "timing-differential",
      summary: timing.reasoning,
      detail: { ...timing },
    },
  ];
  if (sqlError.looksLikeDbError) {
    evidence.push({
      kind: "response-diff",
      summary: sqlError.triggeredByInjection
        ? `Injection introduced a ${sqlError.errorSignature} error not present in baseline.`
        : `A ${sqlError.errorSignature} error signature is present but also appears in baseline — not attributable to injection.`,
      detail: { ...sqlError },
    });
  }

  const confirmed = timing.confirmed;
  const inject = render(delayPayload());

  return {
    id,
    title: "Time-based blind SQL injection",
    type: "sqli",
    severity: confirmed ? "high" : "info",
    verdict: confirmed ? "CONFIRMED" : "REFUTED",
    endpoint: target.urlTemplate,
    method,
    evidence,
    reasoning: confirmed
      ? `Confirmed by repeatable timing differential. ${timing.reasoning}`
      : `Not confirmed. ${timing.reasoning}` +
        (sqlError.looksLikeDbError && !sqlError.triggeredByInjection
          ? " A DB error string is present but appears in baseline too, so it is a pre-existing stack trace, not proof of an injectable parameter."
          : ""),
    poc: confirmed
      ? buildPoc({
          method,
          url: inject.url,
          headers: target.headers,
          body: inject.body,
          expectedObservation: `Response takes ~${DELAY_MS}ms longer than the SLEEP(0) baseline, and the delay scales with the SLEEP() argument.`,
          extraSteps: [`Compare against the baseline payload SLEEP(0), which returns promptly.`],
        })
      : undefined,
  };
}
