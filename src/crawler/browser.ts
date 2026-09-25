/**
 * Browser-driven crawler.
 *
 * Renders SPAs with a real Chromium engine (via Playwright), executes their
 * JavaScript, and captures every HTTP exchange the page makes — including the
 * XHR/fetch API calls that surface-level scanners miss entirely.
 *
 * Scope is enforced at the network layer: any request to a host that is not
 * in-scope is *aborted* (never sent) and recorded as a scope warning. In-scope
 * traffic is captured in full for downstream analysis.
 */

import { chromium, type Browser, type Page, type Route } from "playwright";
import { randomUUID } from "node:crypto";
import { Scope } from "../config/scope.js";
import { RateLimiter } from "../util/rate-limiter.js";
import type { CapturedRequest, ScopeWarning } from "../types.js";
import type { RawTokenSighting } from "../analysis/tokens.js";

const MAX_BODY_BYTES = 512 * 1024; // Cap captured bodies to keep memory sane.

export interface CrawlOptions {
  /** Seed URLs to start from. Must be in-scope or the crawl refuses to start. */
  seeds: string[];
  /** Max distinct in-scope pages to visit. */
  maxPages: number;
  /** Per-page settle time (ms) to let SPA JS finish its API calls. */
  settleMs: number;
}

export interface CrawlOutput {
  requests: CapturedRequest[];
  scopeWarnings: ScopeWarning[];
  tokenSightings: RawTokenSighting[];
}

export class Crawler {
  private readonly requests: CapturedRequest[] = [];
  private readonly warnings: ScopeWarning[] = [];
  private readonly warnedHosts = new Set<string>();
  private readonly tokenSightings: RawTokenSighting[] = [];
  private readonly limiter: RateLimiter;

  constructor(private readonly scope: Scope) {
    this.limiter = new RateLimiter(scope.config.rateLimit.maxRequestsPerSecond);
  }

  async run(opts: CrawlOptions): Promise<CrawlOutput> {
    this.assertSeedsInScope(opts.seeds);

    const browser: Browser = await chromium.launch({ headless: true });
    try {
      const context = await browser.newContext({ ignoreHTTPSErrors: true });
      const page = await context.newPage();
      await this.attachInterception(page);

      const queue = [...opts.seeds];
      const visited = new Set<string>();

      while (queue.length > 0 && visited.size < opts.maxPages) {
        const url = queue.shift()!;
        if (visited.has(url)) continue;
        visited.add(url);

        await this.visit(page, url, opts.settleMs);
        await this.harvestTokens(page);

        // Enqueue in-scope, same-origin links discovered on the page.
        for (const link of await this.extractLinks(page)) {
          if (!visited.has(link) && this.hostInScope(link)) queue.push(link);
        }
      }

      await context.close();
    } finally {
      await browser.close();
    }

    // Also harvest bearer tokens from captured Authorization headers.
    for (const req of this.requests) {
      const auth = req.requestHeaders["authorization"] ?? req.requestHeaders["Authorization"];
      const m = auth?.match(/^Bearer\s+(\S+)/i);
      if (m) this.tokenSightings.push({ source: "authorization-header", value: m[1] });
    }

    return {
      requests: this.requests,
      scopeWarnings: this.warnings,
      tokenSightings: this.tokenSightings,
    };
  }

  /** Pull candidate tokens out of the page's client-side storage. */
  private async harvestTokens(page: Page): Promise<void> {
    try {
      const found = await page.evaluate(() => {
        const out: Array<{ source: string; value: string }> = [];
        const scan = (store: Storage, source: string) => {
          for (let i = 0; i < store.length; i++) {
            const key = store.key(i);
            if (!key) continue;
            const value = store.getItem(key) ?? "";
            // Cheap JWT shape check: three dot-separated base64url segments.
            if (/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(value)) {
              out.push({ source, value: value.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/)![0] });
            }
          }
        };
        scan(localStorage, "localStorage");
        scan(sessionStorage, "sessionStorage");
        return out;
      });
      for (const f of found) {
        this.tokenSightings.push({ source: f.source as RawTokenSighting["source"], value: f.value });
      }
    } catch {
      // Page may have navigated away or blocked storage access; skip.
    }
  }

  /** Wire request interception: enforce scope, throttle, capture. */
  private async attachInterception(page: Page): Promise<void> {
    await page.route("**/*", async (route: Route) => {
      const req = route.request();
      const host = safeHost(req.url());

      if (!host || !this.scope.isInScope(host)) {
        this.recordWarning(req.url(), host, "out-of-scope host — request blocked, not sent");
        await route.abort();
        return;
      }

      await this.limiter.acquire();
      await route.continue();
    });

    page.on("response", async (response) => {
      const req = response.request();
      const host = safeHost(req.url());
      if (!host || !this.scope.isInScope(host)) return;

      let body: string | undefined;
      try {
        const buf = await response.body();
        if (buf.length <= MAX_BODY_BYTES) body = buf.toString("utf8");
        else body = buf.subarray(0, MAX_BODY_BYTES).toString("utf8") + "\n…[truncated]";
      } catch {
        // Some responses (redirects, opaque) have no readable body.
      }

      this.requests.push({
        id: randomUUID(),
        method: req.method(),
        url: req.url(),
        host,
        resourceType: req.resourceType(),
        requestHeaders: req.headers(),
        requestBody: req.postData() ?? undefined,
        status: response.status(),
        responseHeaders: response.headers(),
        responseBody: body,
        inScope: true,
        timestamp: Date.now(),
      });
    });
  }

  private async visit(page: Page, url: string, settleMs: number): Promise<void> {
    try {
      await page.goto(url, { waitUntil: "networkidle", timeout: 30_000 });
      // Give SPA frameworks time to fire their deferred API calls.
      await page.waitForTimeout(settleMs);
    } catch {
      // Navigation timeouts are expected on heavy SPAs; we keep whatever
      // traffic was captured before the timeout.
    }
  }

  private async extractLinks(page: Page): Promise<string[]> {
    try {
      return await page.$$eval("a[href]", (as) =>
        as.map((a) => (a as HTMLAnchorElement).href).filter(Boolean),
      );
    } catch {
      return [];
    }
  }

  private hostInScope(url: string): boolean {
    const host = safeHost(url);
    return !!host && this.scope.isInScope(host);
  }

  private assertSeedsInScope(seeds: string[]): void {
    for (const seed of seeds) {
      const host = safeHost(seed);
      if (!host || !this.scope.isInScope(host)) {
        throw new Error(
          `refusing to crawl seed '${seed}': host is not in authorized scope`,
        );
      }
    }
  }

  private recordWarning(url: string, host: string | null, reason: string): void {
    const h = host ?? "(unparseable)";
    if (this.warnedHosts.has(h)) return; // De-dupe: one warning per host.
    this.warnedHosts.add(h);
    this.warnings.push({ url, host: h, reason });
  }
}

function safeHost(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}
