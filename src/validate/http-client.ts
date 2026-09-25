/**
 * Scope-gated HTTP probe client.
 *
 * This is the hard gate for all *active* testing. Every outbound probe passes
 * through here, and here we re-verify — on every single request — that:
 *   1. the target host is in authorized scope, and
 *   2. the test type driving the request is allowed by the scope file.
 *
 * A probe cannot bypass this by holding its own fetch; the probes are given a
 * ProbeClient, not raw network access. Rate limiting is applied here too, so no
 * probe can flood a target.
 */

import { Scope, type TestType } from "../config/scope.js";
import { RateLimiter } from "../util/rate-limiter.js";

export interface ProbeResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  /** Wall-clock time for the request, used by timing-based probes. */
  elapsedMs: number;
}

export interface ProbeRequest {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  /** The test type this request is part of; checked against scope. */
  testType: TestType;
}

export class ProbeBlockedError extends Error {}

export class ProbeClient {
  private readonly limiter: RateLimiter;

  constructor(private readonly scope: Scope) {
    this.limiter = new RateLimiter(scope.config.rateLimit.maxRequestsPerSecond);
  }

  async send(req: ProbeRequest): Promise<ProbeResponse> {
    const host = hostOf(req.url);
    if (!host || !this.scope.isInScope(host)) {
      throw new ProbeBlockedError(
        `probe blocked: host '${host ?? req.url}' is not in authorized scope`,
      );
    }
    if (!this.scope.allows(req.testType)) {
      throw new ProbeBlockedError(
        `probe blocked: test type '${req.testType}' is not in allowedTestTypes for this program`,
      );
    }

    await this.limiter.acquire();

    const started = performance.now();
    const res = await fetch(req.url, {
      method: req.method ?? "GET",
      headers: req.headers,
      body: req.body,
      redirect: "manual",
    });
    const bodyText = await res.text();
    const elapsedMs = performance.now() - started;

    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));

    return { status: res.status, headers, body: bodyText, elapsedMs };
  }
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}
