/**
 * x402 adapter identity (`adapter:x402`). The conformant exact-EVM proof schema —
 * the EIP-3009 binding a verifier checks — lives in ./x402-exact.ts (proofSchemaId
 * `x402-exact.proof.v2`). This module is just the shared adapterId + the
 * merchant-domain instanceKey those receipts are signed under.
 *
 * (The pre-conformance v1 challenge/ack schema was retired once the stack aligned
 * with real Coinbase x402 — see docs/design/x402-alignment.md §6 P5.)
 */

import { keccak256, stringToBytes, type Hex } from 'viem';

export const X402_ADAPTER_ID: Hex = keccak256(stringToBytes('adapter:x402'));

/** adapterInstanceKey = keccak256(canonical lowercase merchant host). */
export function x402InstanceKey(merchantDomain: string): Hex {
  return keccak256(stringToBytes(merchantDomain.toLowerCase()));
}
