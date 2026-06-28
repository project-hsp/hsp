/**
 * HSP wire-object types (HSP.md §2).
 *
 * This is the typed domain model the actors (payer / adapter / attestation issuer
 * / verifier) build and consume. The byte-level EIP-712 hashing of these structs
 * lives in ../derivations.ts (pinned to HSP.md by ../guard.ts); this module does
 * NOT re-implement any hashing — it composes on the derivation input shapes.
 */

import { keccak256, encodeAbiParameters, type Hex } from 'viem';
import type {
  DomainInput,
  SignerInput,
  RecipientInput,
  MandateInput,
  DelegationGrantInput,
  ReceiptInput,
} from '../derivations.js';

// =============================================================================
// §2.1 Mandate
// =============================================================================

/** §2.1.2 EIP-712 domain ({ name: "HSP", version: "1", chainId, verifyingContract }). */
export type Domain = DomainInput;

/** §2.1.3 Signer — opaque (profileId, payload); verified by the SignerProfile (§4.1). */
export type Signer = SignerInput;

/** §2.1.4 Recipient — tagged ADDRESS | COMMITMENT. */
export type Recipient = RecipientInput;

export const RecipientKind = { ADDRESS: 0, COMMITMENT: 1 } as const;
export type RecipientKindValue = (typeof RecipientKind)[keyof typeof RecipientKind];

/** §2.1.2 Mandate — the 8 EIP-712-signed fields. */
export type Mandate = MandateInput;

/** §2.1.1 SignedMandate envelope — only `body` is EIP-712 signed. */
export interface SignedMandate {
  body: Mandate;
  signerProof: Hex; // SignerProfile-defined; verified against mandateHash (§5.1 step 4)
  requiredCapabilities: Hex[]; // canonical cap-id set; wire order/dupes tolerated (§3.1.3 / §5.1 step 3)
}

/** §2.1.1 DelegationGrant — Principal-signed authorization of an Agent (delegated payments). */
export type DelegationGrant = DelegationGrantInput;

/** §2.1.1 SignedDelegationGrant envelope — only `body` is EIP-712 signed; principalProof is envelope-only. */
export interface SignedDelegationGrant {
  body: DelegationGrant;
  principalProof: Hex; // SignerProfile-defined; verified against grantHash (§5.1 step 4c-i)
}

// =============================================================================
// §2.2 Receipt
// =============================================================================

/** §2.2.2 Outcome — lifecycle states a Receipt is observed in. */
export const Outcome = { ATTEMPTED: 0, SETTLED: 1, FAILED: 2, DISPUTED: 3 } as const;
export type OutcomeValue = (typeof Outcome)[keyof typeof Outcome];

/**
 * §2.2.1 Receipt (9 wire fields) = the 8 receiptHash-preimage fields (ReceiptInput,
 * §2.4.2) PLUS `adapterSignature` (signed over receiptHash; not part of the preimage).
 */
export interface Receipt extends ReceiptInput {
  adapterSignature: Hex; // signed by the key registered for (adapterId, adapterInstanceKey) — §5.2 step 2
}

// =============================================================================
// §2.3 Attestation (third verifier input)
// =============================================================================

/** §2.3.1 / §2.3.2 PartyRef — the single party-reference type (issuers, subjects, authorities). */
export interface PartyRef {
  scheme: string; // "evm-address" | "did" | "x509" | "caip10" | "ens-name" | "smart-account-owner"
  id: Hex; // scheme-defined opaque encoding of the party's identity
}

/** §2.3.2 canonicalRefId(ref) = keccak256(abi.encode(string scheme, bytes id)). */
export function canonicalRefId(ref: PartyRef): Hex {
  return keccak256(
    encodeAbiParameters([{ type: 'string' }, { type: 'bytes' }], [ref.scheme, ref.id]),
  );
}

/** Two PartyRefs are equal iff their canonicalRefId values are bytes-equal (§2.3.2). */
export function partyRefEqual(a: PartyRef, b: PartyRef): boolean {
  return canonicalRefId(a) === canonicalRefId(b);
}

/** §2.3.1 Attestation — every field mandatory; per-entry authenticity via issuerSignature. */
export interface Attestation {
  capabilityId: Hex; // the cap this attestation is for
  schemaId: Hex; // identifies the `claims` structure + verification rules
  claims: Hex; // schema-defined structured claims (abi-encoded bytes)
  issuer: PartyRef; // canonical id via canonicalRefId
  issuerKeyId: Hex; // signing-key fingerprint (issuer MAY rotate keys)
  subjectBinding: PartyRef; // attested subject; checked == roleAssignment[role] (§5.2 step 5, CR2c)
  contextBinding: Hex; // bytes32(0) | mandateHash | receiptHash (§2.3.3)
  issuedAt: number; // Unix seconds
  expiresAt: number; // Unix seconds; 0 ⇔ no expiry
  issuerSignature: Hex; // over all fields above (§2.3.1)
}
