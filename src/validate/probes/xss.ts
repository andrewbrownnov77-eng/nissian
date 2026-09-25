/**
 * Reflected XSS validator with real execution detection.
 *
 * Proof of exploitability, per the spec: a reflected string is NOT a finding.
 * We (1) check whether the target's CSP / X-XSS-Protection would block a naive
 * inline-script payload, then (2) render the page in real Chromium and confirm
 * our script actually *executed* (a unique marker fires). Only genuine
 * execution, not reflection, is confirmed.
 */

import { randomUUID, randomBytes } from "node:crypto";
import type { Browser } from "playwright";
import { chromium } from "playwright";
import { Scope } from "../../config/scope.js";
import { analyzeCsp, xssProtectionBlocks } from "../safety.js";
import { buildPoc } from "../../report/poc.js";
import type { Finding, Evidence } from "../types.js";

export interface XssTarget {
  /** URL with {INJECT} where the payload goes (query param, path, etc.). */
  urlTemplate: string;
}

export async function validateXss(scope: Scope, target: XssTarget): Promise<Finding> {
  const id = randomUUID();
  if (!scope.allows("reflected-input")) {
    throw new Error("reflected-input testing is not in allowedTestTypes for this program");
  }

  const marker = "xss_" + randomBytes(6).toString("hex");
  const payload = `"><script>window.__${marker}=1;document.title='${marker}'</script>`;
  const url = target.urlTemplate.replace("{INJECT}", encodeURIComponent(payload));

  const host = new URL(url).hostname.toLowerCase();
  if (!scope.isInScope(host)) {
    throw new Error(`XSS probe blocked: ${host} is not in authorized scope`);
  }

  const browser: Browser = await chromium.launch({ headless: true });
  let executed = false;
  let cspRaw: string | undefined;
  let xssProtBlocks = false;
  let cspBlocks = false;
  let reflected = false;

  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();

    const response = await page.goto(url, { waitUntil: "networkidle", timeout: 30_000 });
    const headers = response ? lower(response.headers()) : {};
    const csp = analyzeCsp(headers);
    cspRaw = csp.raw;
    cspBlocks = csp.blocksReflectedXss;
    xssProtBlocks = xssProtectionBlocks(headers);

    reflected = (await page.content()).includes(marker);
    // The definitive check: did our script actually run?
    executed = await page.evaluate((m) => (window as any)["__" + m] === 1, marker).catch(() => false);

    await context.close();
  } finally {
    await browser.close();
  }

  const confirmed = executed;
  const evidence: Evidence[] = [
    {
      kind: "script-execution",
      summary: executed
        ? `Injected script executed in a real browser (marker ${marker} set on window and document.title).`
        : reflected
          ? `Payload was reflected but did NOT execute — not exploitable as-is.`
          : `Payload was neither reflected nor executed.`,
      detail: { executed, reflected, marker },
    },
    {
      kind: "header-analysis",
      summary: `CSP blocks reflected inline script: ${cspBlocks}; X-XSS-Protection blocking: ${xssProtBlocks}.`,
      detail: { csp: cspRaw ?? null, cspBlocksReflectedXss: cspBlocks, xssProtectionBlocks: xssProtBlocks },
    },
  ];

  let reasoning: string;
  if (confirmed) {
    reasoning = `Confirmed reflected XSS: the injected script executed in a real browser, so this is exploitable regardless of reflection alone.`;
  } else if (reflected && cspBlocks) {
    reasoning = `Refuted for now: the payload reflects, but the site's CSP blocks inline-script execution, so a naive payload does not fire. A CSP-bypass would need to be demonstrated separately before reporting.`;
  } else if (reflected) {
    reasoning = `Refuted: payload reflects but does not execute (likely output-encoded or in a non-script context). Reflection alone is not a vulnerability.`;
  } else {
    reasoning = `Refuted: no reflection or execution observed.`;
  }

  return {
    id,
    title: "Reflected Cross-Site Scripting (XSS)",
    type: "xss",
    severity: confirmed ? "medium" : "info",
    verdict: confirmed ? "CONFIRMED" : "REFUTED",
    endpoint: target.urlTemplate,
    method: "GET",
    evidence,
    reasoning,
    poc: confirmed
      ? buildPoc({
          method: "GET",
          url,
          expectedObservation: `Opening the URL in a browser executes the injected script — the page title changes to "${marker}" and window.__${marker} is set.`,
        })
      : undefined,
  };
}

function lower(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = v;
  return out;
}
