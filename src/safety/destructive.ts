/**
 * Destructive-action gating.
 *
 * Before any state-changing request goes out, we classify how dangerous it is
 * and refuse the dangerous ones unless the operator has explicitly opted in.
 * "Read-only until told otherwise" is the default posture; the operator has to
 * consciously arm destructive testing, and even then we prefer synthetic targets.
 */

import { looksSynthetic } from "./mutators.js";

export type DangerLevel = "safe" | "mutating" | "destructive";

export interface ClassifiedRequest {
  level: DangerLevel;
  category: string;
  reason: string;
}

const DESTRUCTIVE_PATH_HINTS = /(delete|remove|purge|drop|wipe|reset|cancel|deactivate|revoke|logout|invalidate)/i;
const NOTIFY_PATH_HINTS = /(notify|sms|email|invite|message|webhook|broadcast|send)/i;
const BILLING_PATH_HINTS = /(billing|payment|charge|subscribe|plan|upgrade|invoice|refund|payout)/i;

/**
 * Classify a request by method + path. This is intentionally conservative:
 * when unsure, it rates *up*, never down.
 */
export function classifyRequest(method: string, url: string): ClassifiedRequest {
  const m = method.toUpperCase();
  const path = safePath(url);

  if (m === "GET" || m === "HEAD" || m === "OPTIONS") {
    return { level: "safe", category: "read", reason: "read-only method" };
  }

  if (m === "DELETE" || DESTRUCTIVE_PATH_HINTS.test(path)) {
    return {
      level: "destructive",
      category: "delete/invalidate",
      reason: `${m} ${path} can destroy or invalidate state (deletes records, kills sessions, cancels resources)`,
    };
  }

  if (BILLING_PATH_HINTS.test(path)) {
    return {
      level: "destructive",
      category: "billing",
      reason: `${m} ${path} touches billing/subscription state — a mistaken write can incur real charges`,
    };
  }

  if (NOTIFY_PATH_HINTS.test(path)) {
    return {
      level: "destructive",
      category: "notification",
      reason: `${m} ${path} can trigger outbound notifications (SMS/email/webhook) — fuzzing it can spam real people`,
    };
  }

  // Remaining writes (POST/PUT/PATCH) mutate state but are not classed
  // destructive on their own.
  return {
    level: "mutating",
    category: "write",
    reason: `${m} ${path} changes server state`,
  };
}

export interface GuardPolicy {
  /** Operator opt-in to destructive tests. Default false. */
  allowDestructive: boolean;
  /** When true, destructive tests are only allowed against synthetic targets. */
  requireSyntheticTarget: boolean;
}

export class DestructiveActionBlocked extends Error {}

/**
 * Enforce the policy for a request. Throws DestructiveActionBlocked when a
 * request is not permitted. Returns the classification when allowed.
 *
 * @param targetIdentifiers identifiers embedded in the request (path/body) that
 *   the caller wants checked for "is this a real object or a synthetic one".
 */
export function enforcePolicy(
  method: string,
  url: string,
  policy: GuardPolicy,
  targetIdentifiers: string[] = [],
): ClassifiedRequest {
  const classified = classifyRequest(method, url);

  if (classified.level === "safe" || classified.level === "mutating") {
    return classified;
  }

  // destructive:
  if (!policy.allowDestructive) {
    throw new DestructiveActionBlocked(
      `blocked ${classified.category} action: ${classified.reason}. ` +
        `Set allowDestructive to opt in.`,
    );
  }

  if (policy.requireSyntheticTarget) {
    const allSynthetic =
      targetIdentifiers.length > 0 && targetIdentifiers.every(looksSynthetic);
    if (!allSynthetic) {
      throw new DestructiveActionBlocked(
        `blocked ${classified.category} action against a non-synthetic target: ${classified.reason}. ` +
          `In safe mode, destructive tests must target values minted by the safe-mode mutators.`,
      );
    }
  }

  return classified;
}

function safePath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
