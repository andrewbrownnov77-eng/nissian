/**
 * IDOR / BOLA validator via cross-identity access.
 *
 * Proof of exploitability, per the spec: using the ATTACKER identity, access an
 * object that belongs to the VICTIM identity, and show the attacker receives
 * the victim's data. We rule out the false positives:
 *   - the endpoint returns the same thing to everyone (public data), and
 *   - the attacker just gets a 401/403/empty (properly authorized).
 *
 * Requires two authenticated identities supplied in config — never guessed.
 */

import { randomUUID } from "node:crypto";
import type { ProbeClient } from "../http-client.js";
import { buildPoc } from "../../report/poc.js";
import type { Finding, Evidence } from "../types.js";

export interface Identity {
  name: string;
  headers: Record<string, string>;
}

export interface IdorTarget {
  /** Endpoint that references the VICTIM's object, e.g. /api/user/{victimId}/orders */
  victimObjectUrl: string;
  method?: string;
  /** A stable fragment of the victim's data we expect to see if access leaks. */
  victimDataMarker: string;
}

export async function validateIdor(
  client: ProbeClient,
  attacker: Identity,
  victim: Identity,
  target: IdorTarget,
): Promise<Finding> {
  const id = randomUUID();
  const method = target.method ?? "GET";

  // 1. Victim fetches their own object (control: proves the marker is real).
  const victimRes = await client.send({
    url: target.victimObjectUrl, method, headers: victim.headers, testType: "idor-probe",
  });
  // 2. Attacker attempts the same object.
  const attackerRes = await client.send({
    url: target.victimObjectUrl, method, headers: attacker.headers, testType: "idor-probe",
  });
  // 3. Unauthenticated attempt (rules out "public data" false positive).
  const anonRes = await client.send({
    url: target.victimObjectUrl, method, testType: "idor-probe",
  });

  const victimHasMarker = victimRes.body.includes(target.victimDataMarker);
  const attackerHasMarker = attackerRes.body.includes(target.victimDataMarker);
  const anonHasMarker = anonRes.body.includes(target.victimDataMarker);
  const attackerAuthorizedResponse = attackerRes.status < 400;

  // CONFIRMED only if: the victim's marker is real, the attacker (a *different*
  // authenticated user) receives it with a success status, AND it isn't simply
  // public (anon didn't get it too).
  const confirmed =
    victimHasMarker && attackerHasMarker && attackerAuthorizedResponse && !anonHasMarker;

  const evidence: Evidence[] = [
    {
      kind: "cross-identity-access",
      summary:
        `victim(${victim.name}) marker=${victimHasMarker}; ` +
        `attacker(${attacker.name}) status=${attackerRes.status} marker=${attackerHasMarker}; ` +
        `anonymous status=${anonRes.status} marker=${anonHasMarker}`,
      detail: {
        victimStatus: victimRes.status,
        attackerStatus: attackerRes.status,
        anonStatus: anonRes.status,
        victimHasMarker,
        attackerHasMarker,
        anonHasMarker,
      },
    },
  ];

  let verdict: Finding["verdict"];
  let reasoning: string;
  if (confirmed) {
    verdict = "CONFIRMED";
    reasoning =
      `Confirmed IDOR: attacker '${attacker.name}' retrieved victim '${victim.name}'s data ` +
      `(marker present, HTTP ${attackerRes.status}) while an unauthenticated request did not, ` +
      `so the object is not public and the server failed to enforce object-level authorization.`;
  } else if (anonHasMarker) {
    verdict = "REFUTED";
    reasoning = `Refuted: the data is returned to unauthenticated requests too — it is public, not an IDOR.`;
  } else if (!attackerHasMarker || !attackerAuthorizedResponse) {
    verdict = "REFUTED";
    reasoning = `Refuted: the attacker identity received HTTP ${attackerRes.status} without the victim's data — object-level authorization appears enforced.`;
  } else {
    verdict = "INCONCLUSIVE";
    reasoning = `Inconclusive: could not establish a reliable victim marker; supply a more specific victimDataMarker.`;
  }

  return {
    id,
    title: "Insecure Direct Object Reference (IDOR / BOLA)",
    type: "idor",
    severity: confirmed ? "high" : "info",
    verdict,
    endpoint: target.victimObjectUrl,
    method,
    evidence,
    reasoning,
    poc: confirmed
      ? buildPoc({
          method,
          url: target.victimObjectUrl,
          headers: attacker.headers,
          expectedObservation: `Using attacker '${attacker.name}'s session, the response contains victim '${victim.name}'s data (marker: "${target.victimDataMarker}"). The same request unauthenticated is rejected.`,
        })
      : undefined,
  };
}
