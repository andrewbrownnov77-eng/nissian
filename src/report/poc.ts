/**
 * Proof-of-concept generation — the "60-second repro" deliverable.
 *
 * A confirmed finding is only useful if a first-year analyst can reproduce it
 * fast. This builds a single curl command plus minimal, ordered steps from the
 * exact request that produced the evidence.
 */

import type { ProofOfConcept } from "../validate/types.js";

export interface PocInput {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  expectedObservation: string;
  extraSteps?: string[];
}

export function buildPoc(input: PocInput): ProofOfConcept {
  return {
    curl: buildCurl(input),
    steps: [
      `Send the request below (the single curl command reproduces it).`,
      ...(input.extraSteps ?? []),
      `Observe: ${input.expectedObservation}`,
    ],
    expectedObservation: input.expectedObservation,
  };
}

function buildCurl(input: PocInput): string {
  const parts = [`curl -i -sS -X ${input.method}`];
  for (const [k, v] of Object.entries(input.headers ?? {})) {
    // Redact obvious secrets in the printed PoC; the reviewer supplies their own.
    const value = /authorization|cookie|token/i.test(k) ? "<YOUR_SESSION_TOKEN>" : v;
    parts.push(`-H ${shellQuote(`${k}: ${value}`)}`);
  }
  if (input.body) parts.push(`--data ${shellQuote(input.body)}`);
  parts.push(shellQuote(input.url));
  return parts.join(" \\\n  ");
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
