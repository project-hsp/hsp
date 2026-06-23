/**
 * x402 policy layer (A2) — registers the self-settling x402 adapter into a
 * deployment policy. Composable like compliance: layer it onto the public policy
 * so a deployment accepts BOTH wallet-settled (evm-transfer) and x402-settled
 * payments. The Facilitator's signing key is the trusted adapter key, keyed by
 * adapterInstanceKey = keccak256(merchantDomain). Reference: HSP-bindings.md §2.
 */

import type { Address, Hex } from 'viem';
import { adapterKey, schemaKey, type ReorgPolicy, type VerificationPolicy } from '../verifier/contracts.js';
import { X402_ADAPTER_ID } from '../adapter/x402.js';
import { x402ExactSchema, X402_EXACT_PROOF_SCHEMA_ID } from '../adapter/x402-exact.js';

/** §2.2: x402 allows ATTEMPTED, off-chain (not-applicable), 30s reversal window. */
export const X402_REORG_POLICY: ReorgPolicy = { allowsAttempted: true, chainObservation: 'not-applicable', disputeWindowMs: 30_000 };

export interface X402Facilitator {
  /** keccak256(merchantDomain.toLowerCase()) — see x402InstanceKey(). */
  instanceKey: Hex;
  /** the Facilitator / x402 server signing address (trusted adapter key). */
  address: Address;
}

/** Register the x402 exact-EVM schema + the given Facilitators' trust entries on a policy. */
export function applyX402ToPolicy(policy: VerificationPolicy, facilitators: X402Facilitator[]): VerificationPolicy {
  for (const f of facilitators) {
    policy.adapterTrust.set(adapterKey(X402_ADAPTER_ID, f.instanceKey), { address: f.address, reorgPolicy: X402_REORG_POLICY });
  }
  policy.proofSchemas.set(schemaKey(X402_ADAPTER_ID, X402_EXACT_PROOF_SCHEMA_ID), {
    schema: x402ExactSchema,
    allowedCapabilities: [],
    admission: 'accept-new',
    trustRoots: {},
  });
  return policy;
}
