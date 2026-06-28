/**
 * Fixed role function — HSP.md §3.4. Not a plug-in; a deterministic function the
 * verifier computes once per (SignedExecution, SignerDecision) and consumes at
 * §5.2 step 5. Closed role set {payer, payee, auditor}; payer ≡ verified signer.
 */

import {
  decodeAbiParameters,
  encodeAbiParameters,
  getAddress,
  type Hex,
} from 'viem';
import { RecipientKind, type Recipient, type SignedExecution, type PartyRef } from '../core/index.js';
import { type RoleName } from '../core/capabilities.js';
import type { SignerDecision, VerificationPolicy } from './contracts.js';

export type RoleAssignment = Partial<Record<RoleName, PartyRef>>;

/** §3.4 decodeRecipient — profile-defined per Recipient.kind. */
export function decodeRecipient(recipient: Recipient): PartyRef {
  if (recipient.kind === RecipientKind.ADDRESS) {
    const address = decodeAbiParameters([{ type: 'address' }], recipient.payload)[0];
    return { scheme: 'evm-address', id: encodeAbiParameters([{ type: 'address' }], [getAddress(address)]) };
  }
  // COMMITMENT: abi.encode(bytes32 commitment, bytes32 derivationContext) — §2.1.4.
  // Profiles MAY return { scheme: "stealth-commitment", id: commitment } when hidden.
  const commitment = decodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32' }], recipient.payload)[0];
  return { scheme: 'stealth-commitment', id: commitment };
}

/**
 * §3.4 roleFunction. payer = signer subject (payer ≡ verified signer in v1);
 * payee decoded from recipient; auditor = policy.auditorSubject when configured
 * (RF3 fail-closes if a required role is unresolved; RF4: payer is filled from
 * nothing but signerDecision.resolvedSubject).
 */
export function roleFunction(
  mandate: SignedExecution,
  signerDecision: SignerDecision,
  policy: VerificationPolicy,
): RoleAssignment {
  const assignment: RoleAssignment = {
    payer: signerDecision.resolvedSubject,
    payee: decodeRecipient(mandate.body.recipient),
  };
  if (policy.auditorSubject) assignment.auditor = policy.auditorSubject;
  return assignment;
}
