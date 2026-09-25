/**
 * Statistical timing analysis for blind, time-based detection.
 *
 * A single slow response proves nothing — networks jitter. To claim a
 * time-based injection we require the "delay" payloads to be separated from the
 * "baseline" payloads by a margin that dwarfs the observed noise, across
 * repeated samples. This is what turns "it felt slow" into evidence.
 *
 * Method: take N baseline and N delayed samples, drop the slowest baseline and
 * fastest delayed sample as outlier guards, and require:
 *   median(delayed) - median(baseline) >= expectedDelayMs * 0.7
 * AND the fastest delayed sample to exceed the slowest baseline sample.
 */

export interface TimingVerdict {
  confirmed: boolean;
  baselineMedianMs: number;
  delayedMedianMs: number;
  observedDeltaMs: number;
  expectedDelayMs: number;
  reasoning: string;
  samples: { baseline: number[]; delayed: number[] };
}

export function analyzeTiming(
  baseline: number[],
  delayed: number[],
  expectedDelayMs: number,
): TimingVerdict {
  const b = [...baseline].sort((x, y) => x - y);
  const d = [...delayed].sort((x, y) => x - y);

  const baselineMedian = median(b);
  const delayedMedian = median(d);
  const observedDelta = delayedMedian - baselineMedian;

  // Separation guard: even the fastest delayed sample should beat the slowest
  // baseline sample if the delay is real and consistent.
  const fastestDelayed = d[0];
  const slowestBaseline = b[b.length - 1];
  const cleanSeparation = fastestDelayed > slowestBaseline;

  const meetsThreshold = observedDelta >= expectedDelayMs * 0.7;
  const confirmed = meetsThreshold && cleanSeparation;

  return {
    confirmed,
    baselineMedianMs: round(baselineMedian),
    delayedMedianMs: round(delayedMedian),
    observedDeltaMs: round(observedDelta),
    expectedDelayMs,
    reasoning: confirmed
      ? `Delayed payloads were consistently ~${round(observedDelta)}ms slower than baseline ` +
        `(expected ~${expectedDelayMs}ms), with clean separation between the two sample sets — ` +
        `consistent with server-side execution of the injected delay.`
      : `Timing differential of ${round(observedDelta)}ms did not meet the threshold ` +
        `(needs ≥${round(expectedDelayMs * 0.7)}ms) or the sample sets overlapped ` +
        `(fastest delayed ${round(fastestDelayed)}ms vs slowest baseline ${round(slowestBaseline)}ms). ` +
        `Not confirmed — likely noise, not injection.`,
    samples: { baseline, delayed },
  };
}

function median(sorted: number[]): number {
  if (sorted.length === 0) return 0;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function round(n: number): number {
  return Math.round(n * 10) / 10;
}
