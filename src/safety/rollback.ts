/**
 * Rollback journal.
 *
 * Any active test that changes server state records an *inverse* action here
 * before (or immediately after) making the change. At the end of a session — or
 * on abort — the journal replays the inverses in reverse order, so created
 * resources are deleted and modified fields are restored. This is the safety
 * net that lets a run touch state without leaving a mess behind.
 *
 * The journal never invents inverses: the caller supplies them, because only
 * the caller knows how to undo its own action (delete the id it created,
 * PUT back the original field values it captured first).
 */

import type { ProbeClient, ProbeRequest } from "../validate/http-client.js";

export interface JournalEntry {
  description: string;
  /** The request that undoes the forward action. */
  inverse: ProbeRequest;
  recordedAt: string;
}

export interface RollbackReport {
  attempted: number;
  succeeded: number;
  failed: Array<{ description: string; error: string }>;
}

export class RollbackJournal {
  private readonly entries: JournalEntry[] = [];

  /**
   * Record how to undo an action. Call this BEFORE performing a create so an
   * abort mid-run can still clean up, and capture original values BEFORE an
   * update so the inverse can restore them.
   */
  record(description: string, inverse: ProbeRequest): void {
    this.entries.push({ description, inverse, recordedAt: new Date().toISOString() });
  }

  get pending(): number {
    return this.entries.length;
  }

  /** A human-readable manifest of what will be undone, for operator review. */
  manifest(): string[] {
    return this.entries.map((e) => `${e.inverse.method ?? "GET"} ${e.inverse.url} — ${e.description}`);
  }

  /**
   * Replay inverses newest-first (LIFO), so dependent resources are removed
   * before their parents. Continues past failures and reports them all, since
   * a half-rolled-back state is worse than a fully-attempted one.
   */
  async rollback(client: ProbeClient): Promise<RollbackReport> {
    const report: RollbackReport = { attempted: 0, succeeded: 0, failed: [] };
    // LIFO order.
    for (let i = this.entries.length - 1; i >= 0; i--) {
      const entry = this.entries[i];
      report.attempted++;
      try {
        const res = await client.send(entry.inverse);
        if (res.status < 400) {
          report.succeeded++;
        } else {
          report.failed.push({ description: entry.description, error: `HTTP ${res.status}` });
        }
      } catch (err) {
        report.failed.push({ description: entry.description, error: (err as Error).message });
      }
    }
    // Clear only the entries we successfully undid would be ideal, but since we
    // attempted all, keep failures visible by retaining the journal for a retry.
    if (report.failed.length === 0) this.entries.length = 0;
    return report;
  }
}
