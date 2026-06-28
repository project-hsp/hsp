/**
 * Fixed role function — HSP.md §3.4. Not a plug-in; a deterministic function the
 * verifier computes once per (SignedMandate, SignerDecision) and consumes at
 * §5.2 step 5. Closed role set {payer, payee, auditor}; payer ≡ verified signer.
 */

import {
  decodeAbiParameters,
  encodeAbiParameters,
  getAddress,
  type Hex,
} from 'viem';
import { RecipientKind, type Recipient, type SignedMandate, type PartyRef } from '../core/index.js';
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
  mandate: SignedMandate,
  signerDecision: SignerDecision,
  policy: VerificationPolicy,
  principalSubject?: PartyRef, // §3.4: delegated → payer = Principal; self-pay → omitted (payer = signer)
): RoleAssignment {
  const assignment: RoleAssignment = {
    payer: principalSubject ?? signerDecision.resolvedSubject,
    payee: decodeRecipient(mandate.body.recipient),
  };
  if (policy.auditorSubject) assignment.auditor = policy.auditorSubject;
  return assignment;
}

/** PartyRef equality — scheme + case-insensitive id (§4.1.3). */
export function partyRefEqual(a: PartyRef, b: PartyRef): boolean {
  return a.scheme === b.scheme && a.id.toLowerCase() === b.id.toLowerCase();
}
