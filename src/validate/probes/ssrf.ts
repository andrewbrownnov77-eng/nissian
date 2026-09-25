/**
 * SSRF validator via out-of-band interaction.
 *
 * Proof of exploitability, per the spec: inject a URL pointing at a collector we
 * control and prove the *target server* made the request — capturing the exact
 * inbound HTTP request as evidence. A reflected URL in the response is not
 * enough; the server actually reaching out is.
 */

import { randomUUID } from "node:crypto";
import type { ProbeClient } from "../http-client.js";
import type { OobCollector } from "../oob.js";
import { buildPoc } from "../../report/poc.js";
import type { Finding, Evidence } from "../types.js";

export interface SsrfTarget {
  /** URL whose parameter takes a URL; {INJECT} marks where the payload URL goes. */
  urlTemplate: string;
  method?: string;
  headers?: Record<string, string>;
  bodyTemplate?: string;
}

export async function validateSsrf(
  client: ProbeClient,
  oob: OobCollector,
  target: SsrfTarget,
  waitMs = 8000,
): Promise<Finding> {
  const id = randomUUID();
  const method = target.method ?? "GET";
  const { token, url: payloadUrl } = oob.mint();

  const injected = encodeURIComponent(payloadUrl);
  const url = target.urlTemplate.replace("{INJECT}", injected);
  const body = target.bodyTemplate?.replace("{INJECT}", payloadUrl);

  await client.send({ url, method, headers: target.headers, body, testType: "reflected-input" });

  const hits = await oob.waitFor(token, waitMs);
  const confirmed = hits.length > 0;

  const evidence: Evidence[] = confirmed
    ? [
        {
          kind: "oob-interaction",
          summary: `Target server made an out-of-band request to our collector at token ${token}.`,
          detail: { interactions: hits },
        },
      ]
    : [
        {
          kind: "oob-interaction",
          summary: `No out-of-band interaction received within ${waitMs}ms — the target did not fetch our URL.`,
          detail: { token, waitedMs: waitMs },
        },
      ];

  return {
    id,
    title: "Server-Side Request Forgery (SSRF)",
    type: "ssrf",
    severity: confirmed ? "high" : "info",
    verdict: confirmed ? "CONFIRMED" : "INCONCLUSIVE",
    endpoint: target.urlTemplate,
    method,
    evidence,
    reasoning: confirmed
      ? `Confirmed: the target server itself connected to our controlled endpoint, proving it fetches attacker-supplied URLs. The captured request (source IP, headers) is attached.`
      : `Not confirmed: no callback observed. Could be a firewalled egress, an async fetch beyond the wait window, or no SSRF. Marked inconclusive rather than reported.`,
    poc: confirmed
      ? buildPoc({
          method,
          url,
          headers: target.headers,
          body,
          expectedObservation: `The collector at ${payloadUrl} records an inbound HTTP request originating from the target's infrastructure, not from your machine.`,
        })
      : undefined,
  };
}
