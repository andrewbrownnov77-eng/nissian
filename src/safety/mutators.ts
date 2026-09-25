/**
 * Safe-mode mutators — fuzz without poisoning the well.
 *
 * A fuzzer that writes real-looking values into an application can cause
 * expensive, embarrassing damage: deleting real records, upgrading a user to a
 * £5000 plan, blasting SMS to a triager. Safe mode restricts every generated
 * value to something unmistakably synthetic and self-identifying, so that even
 * if a write lands, it is obviously test data that is trivial to clean up.
 *
 * Rules:
 *   - identifiers are fresh random UUIDs, never harvested real ones
 *   - emails use the reserved example.com domain (RFC 2606) and a nonce
 *   - names/strings carry a "nissian-test-" prefix so they're greppable
 *   - numbers stay in a benign, clearly-fake band
 */

import { randomUUID, randomBytes } from "node:crypto";

/** A stable, greppable marker on every synthetic value. */
export const TEST_MARKER = "nissian-test";

export function safeUuid(): string {
  return randomUUID();
}

export function safeEmail(): string {
  return `${TEST_MARKER}-${randomBytes(4).toString("hex")}@example.com`;
}

export function safeName(kind = "name"): string {
  return `${TEST_MARKER}-${kind}-${randomBytes(3).toString("hex")}`;
}

/** A benign integer that won't look like a real price/quantity/id. */
export function safeNumber(): number {
  return 100000 + Math.floor(Math.random() * 1000);
}

/**
 * Decide whether a value looks REAL (and therefore unsafe to send as a mutation
 * target in safe mode). Used to refuse fuzzing a DELETE/PUT against an id that
 * wasn't minted by us.
 */
export function looksSynthetic(value: string): boolean {
  return value.includes(TEST_MARKER) || value.endsWith("@example.com");
}

/**
 * Build a synthetic body from a shape spec. Each field names the kind of value
 * to synthesize, so a caller can fuzz a real endpoint with guaranteed-safe data.
 */
export type FieldKind = "uuid" | "email" | "name" | "number" | "string";

export function synthesizeBody(shape: Record<string, FieldKind>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [field, kind] of Object.entries(shape)) {
    switch (kind) {
      case "uuid": out[field] = safeUuid(); break;
      case "email": out[field] = safeEmail(); break;
      case "name": out[field] = safeName(field); break;
      case "number": out[field] = safeNumber(); break;
      case "string": out[field] = safeName(field); break;
    }
  }
  return out;
}
