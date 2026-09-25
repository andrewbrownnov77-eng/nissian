/**
 * Adaptive throttle — polite, load-aware pacing.
 *
 * The goal here is NOT to hide from a target's security team; it is to avoid
 * degrading the target and to keep our own results clean. When a target starts
 * signalling stress (429 Too Many Requests, 503, a Retry-After header), we slow
 * down; when it recovers, we speed back up toward the configured ceiling. We
 * can also refuse to run outside an allowed time window.
 *
 * This makes "don't hammer the target" a structural property, not a good
 * intention — which is exactly what keeps a researcher's access (and the
 * program) healthy.
 */

export interface ThrottleConfig {
  /** Upper bound on requests/sec; the adaptive rate never exceeds this. */
  maxRequestsPerSecond: number;
  /** Floor the adaptive rate won't drop below (keeps progress during pressure). */
  minRequestsPerSecond: number;
  /**
   * Optional allowed hours (local 0-23) to send traffic, e.g. avoid peak load.
   * Empty/undefined means "any time".
   */
  allowedHours?: number[];
}

export class AdaptiveThrottle {
  private currentRate: number;
  private tokens: number;
  private lastRefill = Date.now();
  /** When set (epoch ms), we must not send before this time (Retry-After). */
  private pausedUntil = 0;

  constructor(private readonly config: ThrottleConfig) {
    this.currentRate = config.maxRequestsPerSecond;
    this.tokens = this.currentRate;
  }

  /** Block until it is polite to send the next request. */
  async acquire(now: () => number = Date.now): Promise<void> {
    for (;;) {
      await this.waitForAllowedWindow(now);
      const t = now();
      if (t < this.pausedUntil) {
        await sleep(this.pausedUntil - t);
        continue;
      }
      this.refill(t);
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      await sleep(Math.ceil((1 - this.tokens) / this.currentRate * 1000));
    }
  }

  /**
   * Feed each response's signal back in. Backs off on pressure, eases up on
   * sustained success. Honors an explicit Retry-After.
   */
  observe(status: number, retryAfterSeconds?: number): void {
    if (retryAfterSeconds && retryAfterSeconds > 0) {
      this.pausedUntil = Date.now() + retryAfterSeconds * 1000;
    }
    if (status === 429 || status === 503) {
      // Multiplicative decrease: halve the rate, floored.
      this.currentRate = Math.max(this.config.minRequestsPerSecond, this.currentRate / 2);
    } else if (status < 400) {
      // Additive increase: creep back toward the ceiling.
      this.currentRate = Math.min(
        this.config.maxRequestsPerSecond,
        this.currentRate + this.config.maxRequestsPerSecond * 0.1,
      );
    }
  }

  get rate(): number {
    return Math.round(this.currentRate * 100) / 100;
  }

  private refill(now: number): void {
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.currentRate, this.tokens + elapsed * this.currentRate);
    this.lastRefill = now;
  }

  private async waitForAllowedWindow(now: () => number): Promise<void> {
    const hours = this.config.allowedHours;
    if (!hours || hours.length === 0) return;
    while (!hours.includes(new Date(now()).getHours())) {
      // Sleep in chunks until we re-enter an allowed hour.
      await sleep(60_000);
    }
  }
}

/** Parse a Retry-After header (delta-seconds or HTTP-date) to seconds. */
export function parseRetryAfter(value: string | undefined, now = Date.now()): number | undefined {
  if (!value) return undefined;
  const asNum = Number(value);
  if (Number.isFinite(asNum)) return Math.max(0, asNum);
  const asDate = Date.parse(value);
  if (Number.isFinite(asDate)) return Math.max(0, Math.round((asDate - now) / 1000));
  return undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
