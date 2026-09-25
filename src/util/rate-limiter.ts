/**
 * A minimal token-bucket rate limiter.
 *
 * Bug bounty programs treat "do not degrade our service" as a hard rule; a bot
 * that floods a target gets the researcher banned and can cause real harm. This
 * gate makes politeness structural rather than a thing we remember to do.
 */
export class RateLimiter {
  private tokens: number;
  private lastRefill: number;

  constructor(private readonly ratePerSecond: number) {
    this.tokens = ratePerSecond;
    this.lastRefill = Date.now();
  }

  /** Resolve once a token is available, throttling the caller. */
  async acquire(): Promise<void> {
    for (;;) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = Math.ceil((1 - this.tokens) / this.ratePerSecond * 1000);
      await sleep(waitMs);
    }
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.ratePerSecond, this.tokens + elapsed * this.ratePerSecond);
    this.lastRefill = now;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
