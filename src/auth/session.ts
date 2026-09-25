/**
 * Auth-flow intelligence.
 *
 * Authenticated testing breaks the moment a token expires or a session is
 * killed — and then every subsequent probe returns misleading 401s that look
 * like "not vulnerable". This manager keeps a valid credential in hand:
 *   - logs in on demand via a configured login routine,
 *   - detects an expiring JWT (from its own `exp` claim) and refreshes early,
 *   - detects a killed session (a probe unexpectedly returning 401/403) and
 *     re-authenticates,
 *   - lets a caller force a refresh BEFORE exercising a dangerous endpoint
 *     (e.g. a logout/invalidate-all route) so the run survives it.
 *
 * The actual login/refresh transport is injected, so this works against any
 * auth scheme without hard-coding one.
 */

export interface Credential {
  /** Header name/value to attach to authenticated requests. */
  headerName: string;
  headerValue: string;
  /** Epoch ms when this credential should be considered stale (from JWT exp). */
  expiresAt?: number;
}

export interface AuthTransport {
  /** Perform a fresh login and return a credential. */
  login(): Promise<Credential>;
  /** Optional refresh; falls back to login() when absent. */
  refresh?(current: Credential): Promise<Credential>;
}

/** Refresh this many ms before the token's own expiry, to avoid mid-flight expiry. */
const REFRESH_SKEW_MS = 30_000;

export class SessionManager {
  private credential?: Credential;

  constructor(private readonly transport: AuthTransport) {}

  /** Return a valid credential, logging in or refreshing as needed. */
  async getCredential(now = Date.now()): Promise<Credential> {
    if (!this.credential) {
      this.credential = await this.transport.login();
      return this.credential;
    }
    if (this.isStale(this.credential, now)) {
      this.credential = this.transport.refresh
        ? await this.transport.refresh(this.credential)
        : await this.transport.login();
    }
    return this.credential;
  }

  /**
   * Called with a probe's response status. If it indicates the session was
   * killed (401/403 where we expected auth), drop the credential so the next
   * getCredential() re-authenticates. Returns true if a re-auth was triggered.
   */
  noteResponse(status: number): boolean {
    if ((status === 401 || status === 403) && this.credential) {
      this.credential = undefined;
      return true;
    }
    return false;
  }

  /** Force a fresh credential now — call before hitting a session-invalidating endpoint. */
  async refreshBefore(): Promise<Credential> {
    this.credential = this.transport.refresh && this.credential
      ? await this.transport.refresh(this.credential)
      : await this.transport.login();
    return this.credential;
  }

  private isStale(cred: Credential, now: number): boolean {
    return cred.expiresAt !== undefined && now >= cred.expiresAt - REFRESH_SKEW_MS;
  }
}

/** Read a JWT's `exp` (seconds) and return epoch ms, or undefined. */
export function jwtExpiryMs(jwt: string): number | undefined {
  const parts = jwt.replace(/^Bearer\s+/i, "").split(".");
  if (parts.length !== 3) return undefined;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4 ? "=".repeat(4 - (b64.length % 4)) : "";
    const claims = JSON.parse(Buffer.from(b64 + pad, "base64").toString("utf8"));
    return typeof claims.exp === "number" ? claims.exp * 1000 : undefined;
  } catch {
    return undefined;
  }
}
