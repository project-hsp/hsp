/**
 * Prior-receipt index — the stateful-admission input of §4.3.4 CR5 / §5.2 step 7.
 * Keyed by (adapterId, adapterInstanceKey, mandateHash). NOT part of the stateless
 * core and MUST NOT be folded into VerificationPolicy (§7.2). In-memory for M1.
 */

import { Outcome, type OutcomeValue } from '../core/index.js';
import type { Hex } from 'viem';

export interface Emission {
  seq: number;
  outcome: OutcomeValue;
  settledAt: number;
  receiptHash: Hex; // content hash for S4 equivocation detection
}

export interface PriorState {
  seen: boolean;
  maxSeq: number; // -1 when unseen
  disputed: boolean; // a DISPUTED has been admitted (terminal)
  settledSeq?: number; // highest-seq SETTLED emission (the one a DISPUTED would overturn)
  settledAt?: number;
}

export class SeqIndex {
  private readonly m = new Map<string, Emission[]>();

  private key(adapterId: Hex, instanceKey: Hex, mandateHash: Hex): string {
    return `${adapterId.toLowerCase()}:${instanceKey.toLowerCase()}:${mandateHash.toLowerCase()}`;
  }

  /** Summarize prior emissions for the 4-tuple (per §5.2 step 7 needs). */
  state(adapterId: Hex, instanceKey: Hex, mandateHash: Hex): PriorState {
    const es = this.m.get(this.key(adapterId, instanceKey, mandateHash)) ?? [];
    if (es.length === 0) return { seen: false, maxSeq: -1, disputed: false };
    let maxSeq = -1;
    let disputed = false;
    let settledSeq: number | undefined;
    let settledAt: number | undefined;
    for (const e of es) {
      if (e.seq > maxSeq) maxSeq = e.seq;
      if (e.outcome === Outcome.DISPUTED) disputed = true;
      if (e.outcome === Outcome.SETTLED && (settledSeq === undefined || e.seq > settledSeq)) {
        settledSeq = e.seq;
        settledAt = e.settledAt;
      }
    }
    return { seen: true, maxSeq, disputed, settledSeq, settledAt };
  }

  /** S4 (§2.2.3): same (adapterId, instanceKey, mandateHash, seq) with a different content hash. */
  isEquivocation(adapterId: Hex, instanceKey: Hex, mandateHash: Hex, seq: number, receiptHash: Hex): boolean {
    const es = this.m.get(this.key(adapterId, instanceKey, mandateHash)) ?? [];
    return es.some((e) => e.seq === seq && e.receiptHash.toLowerCase() !== receiptHash.toLowerCase());
  }

  /** Record an accepted emission (called only after §5.2 steps 1–7 pass). */
  record(adapterId: Hex, instanceKey: Hex, mandateHash: Hex, e: Emission): void {
    const k = this.key(adapterId, instanceKey, mandateHash);
    const arr = this.m.get(k) ?? [];
    arr.push(e);
    this.m.set(k, arr);
  }
}

/**
 * Observation-consumption index — the SECOND stateful-admission input of §5.2
 * step 7: one settlement-native observation (VerifyOutcome.observationId)
 * settles at most one mandate. Keyed (adapterId, observationId) — ACROSS
 * adapter instances, by design (two instances observing the same transfer must
 * not both consume it). Like the prior-receipt index, it is verifier-held
 * lifecycle state and MUST NOT be folded into VerificationPolicy.
 */
export class ObservationIndex {
  private readonly m = new Map<string, Hex>();

  private key(adapterId: Hex, observationId: Hex): string {
    return `${adapterId.toLowerCase()}:${observationId.toLowerCase()}`;
  }

  /** The mandateHash that consumed this observation, if any. */
  owner(adapterId: Hex, observationId: Hex): Hex | undefined {
    return this.m.get(this.key(adapterId, observationId));
  }

  /** Record consumption (called only after §5.2 step 7 passes in full). */
  record(adapterId: Hex, observationId: Hex, mandateHash: Hex): void {
    this.m.set(this.key(adapterId, observationId), mandateHash.toLowerCase() as Hex);
  }
}
