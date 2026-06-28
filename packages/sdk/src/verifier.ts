/**
 * HSPVerifier — independent verification for ANY relying party.
 *
 * verify() runs the FULL core verifier with a policy built from the caller's
 * OWN pinned trust config — never from the Coordinator's answers. "ACCEPT
 * means ship" therefore does not require trusting the Coordinator at all:
 * pin (chain constants, adapter observation address) once, out-of-band
 * (GET /chains at setup time, docs, or contract), and verify independently.
 *
 * The relying party is whoever acts on the payment — the protocol's wire
 * roles are {payer, payee, auditor}: a merchant shipping goods (the canonical
 * payee), a platform confirming a buyer paid a seller, or the payer
 * double-checking a receipt. Same class, same pinned-trust posture for all.
 *
 * Note: each verify() call uses a fresh SeqIndex/ObservationIndex — it judges
 * ONE (mandate, receipt) pair statelessly. Multi-receipt sequencing /
 * equivocation / observation-reuse history is the Coordinator's
 * stateful-admission concern; a relying party deciding on receipt STREAMS
 * should keep its own indices across calls (exposed as optional parameters).
 */

import type { Address } from 'viem';
import type { Attestation, Receipt, SignedMandate } from '@hsp/core';
import { verify, SeqIndex, ObservationIndex } from '@hsp/core/verifier/index';
import type { AcceptDecision } from '@hsp/core/verifier/contracts';
import { buildPublicPolicy } from '@hsp/core/policy/public';
import { buildCompliancePolicy, type CompliancePolicyOpts } from '@hsp/core/policy/compliance';
import { applyX402ToPolicy, type X402Facilitator } from '@hsp/core/policy/x402';
import type { ChainConfig } from '@hsp/core/chains/index';

export interface PinnedTrustConfig {
  chain: ChainConfig;
  /** The adapter's observation-signing address — PINNED out-of-band. */
  adapterAddress: Address;
  /** Pin trusted issuers + the required-cap floor to verify compliance payments. */
  compliance?: CompliancePolicyOpts;
  /** Pin trusted x402 Facilitators (their signing address + merchant-domain instanceKey)
   *  to verify self-settling adapter:x402 receipts. */
  x402Facilitators?: X402Facilitator[];
}

export class HSPVerifier {
  constructor(private readonly pinned: PinnedTrustConfig) {}

  async verify(
    mandate: SignedMandate,
    receipt: Receipt,
    attestations: Attestation[] = [],
    seqIndex: SeqIndex = new SeqIndex(),
    obsIndex: ObservationIndex = new ObservationIndex(),
  ): Promise<AcceptDecision> {
    const now = Math.floor(Date.now() / 1000);
    let policy;
    if (this.pinned.compliance) {
      policy = buildCompliancePolicy(this.pinned.chain, this.pinned.adapterAddress, now, this.pinned.compliance);
    } else {
      policy = buildPublicPolicy(this.pinned.chain, this.pinned.adapterAddress, now);
    }
    // x402 receipts are address-recipient + self-settling — register the pinned
    // Facilitators on top of whichever base policy applies (composes like the Coordinator's).
    if (this.pinned.x402Facilitators?.length) applyX402ToPolicy(policy, this.pinned.x402Facilitators);
    return verify(mandate, receipt, attestations, policy, seqIndex, obsIndex);
  }
}
