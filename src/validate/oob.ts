/**
 * Out-of-band (OOB) interaction collector.
 *
 * For blind vulnerability classes (SSRF, blind XXE, some RCE), the proof is not
 * in the HTTP response — it's whether the *target server* reaches out to an
 * endpoint we control. This module runs a small HTTP listener that records
 * every inbound request keyed by a unique correlation token, so a probe can
 * inject a URL like `http://<collector>/<token>` and later prove the target hit
 * it, capturing the exact request as evidence.
 *
 * For real engagements the collector's public URL must be reachable by the
 * target (a public host or tunnel). The listener here is deliberately
 * transport-agnostic: point `publicBaseUrl` at wherever the target can reach it.
 */

import { createServer, type Server, type IncomingMessage } from "node:http";
import { randomBytes } from "node:crypto";

export interface OobInteraction {
  token: string;
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  sourceIp?: string;
  receivedAt: string;
}

export class OobCollector {
  private server?: Server;
  private readonly interactions = new Map<string, OobInteraction[]>();

  /**
   * @param publicBaseUrl How the *target* reaches this collector, e.g.
   *   "http://oob.researcher.example". Payload URLs are built from it.
   * @param port Local port to listen on.
   */
  constructor(
    private readonly publicBaseUrl: string,
    private readonly port: number,
  ) {}

  async start(): Promise<void> {
    this.server = createServer((req: IncomingMessage, res) => {
      const url = req.url ?? "/";
      // First path segment, with any query string stripped, is the token.
      const pathOnly = url.split("?")[0];
      const token = pathOnly.split("/").filter(Boolean)[0] ?? "";
      const record: OobInteraction = {
        token,
        method: req.method ?? "GET",
        path: url,
        headers: req.headers,
        sourceIp: req.socket.remoteAddress ?? undefined,
        receivedAt: new Date().toISOString(),
      };
      const list = this.interactions.get(token) ?? [];
      list.push(record);
      this.interactions.set(token, list);
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((resolve) => this.server!.listen(this.port, resolve));
  }

  async stop(): Promise<void> {
    if (this.server) await new Promise<void>((r) => this.server!.close(() => r()));
  }

  /** Mint a fresh correlation token and the payload URL that carries it. */
  mint(): { token: string; url: string } {
    const token = randomBytes(12).toString("hex");
    return { token, url: `${this.publicBaseUrl.replace(/\/$/, "")}/${token}` };
  }

  /** Any interactions recorded for this token (the proof of an OOB hit). */
  interactionsFor(token: string): OobInteraction[] {
    return this.interactions.get(token) ?? [];
  }

  /** Poll until an interaction arrives or the timeout elapses. */
  async waitFor(token: string, timeoutMs: number): Promise<OobInteraction[]> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const hits = this.interactionsFor(token);
      if (hits.length > 0) return hits;
      if (Date.now() >= deadline) return [];
      await new Promise((r) => setTimeout(r, 200));
    }
  }
}
