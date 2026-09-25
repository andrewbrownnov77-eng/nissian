/**
 * MutationClient — the single doorway for state-changing probes.
 *
 * It composes the three Stage 5 safeguards so they cannot be forgotten:
 *   1. classify + gate the request (destructive actions need opt-in), then
 *   2. record the caller-supplied inverse in the rollback journal, then
 *   3. send it through the scope-gated ProbeClient.
 *
 * A probe that wants to mutate state goes through here, not the raw client, so
 * "did we gate this? did we record how to undo it?" is answered by construction.
 */

import type { ProbeClient, ProbeRequest, ProbeResponse } from "../validate/http-client.js";
import { enforcePolicy, type GuardPolicy, type ClassifiedRequest } from "./destructive.js";
import { RollbackJournal } from "./rollback.js";

export interface MutationRequest extends ProbeRequest {
  /** Identifiers embedded in this request, checked against synthetic-only policy. */
  targetIdentifiers?: string[];
  /** The request that undoes this one. Required for anything that creates/edits. */
  inverse?: ProbeRequest;
  /** Human description for the rollback manifest. */
  description?: string;
}

export class MutationClient {
  readonly journal = new RollbackJournal();

  constructor(
    private readonly client: ProbeClient,
    private readonly policy: GuardPolicy,
  ) {}

  /**
   * Gate, journal, then send. Throws (without sending) if the policy blocks it.
   */
  async mutate(req: MutationRequest): Promise<{ response: ProbeResponse; classified: ClassifiedRequest }> {
    const method = req.method ?? "GET";
    const classified = enforcePolicy(method, req.url, this.policy, req.targetIdentifiers ?? []);

    // Record the undo BEFORE we make the change, so an abort still cleans up.
    if (req.inverse) {
      this.journal.record(req.description ?? `undo ${method} ${req.url}`, req.inverse);
    }

    const response = await this.client.send(req);
    return { response, classified };
  }

  /** Undo everything recorded this session. */
  async rollbackAll() {
    return this.journal.rollback(this.client);
  }
}
