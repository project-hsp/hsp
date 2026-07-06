/**
 * Verifier plug-in contracts (HSP.md §4) + verification policy shape (§7).
 *
 * These are the interfaces the Verifier (§5) dispatches to: SignerProfile (§4.1),
 * AdapterProofSchema (§4.2), plus the wire-borne Attestation it validates
 * (§4.3, struct in ../core/types.ts). VerificationPolicy is the §7.2.1 five
 * dispatch tables + §7.2.2 predicates + scalars.
 *
 * NOTE (sync→async modeling). §4 writes `verify()` as synchronous (SP3/PS1
 * determinism is about input→output, not sync/async). Real implementations do
 * ECDSA recovery (viem) / ZK verification (snarkjs) asynchronously, so here the
 * two `verify()` methods return Promises and the orchestrator awaits them. This
 * is a JS modeling choice, not a protocol change — determinism is preserved.
 */

import type { Address, Hex } from 'viem';
import type { PartyRef, Mandate, Receipt, ParsedCapability } from '../core/index.js';

// =============================================================================
// §4.3.3 Verifier output
// =============================================================================

/** §8.0 normative coarse client action (pinned by CR5). */
export type OutcomeClass = 'ACCEPT' | 'RETRYABLE' | 'POLICY' | 'PERMANENT';

export interface AcceptDecision {
  ok: boolean; // the (mandate, receipt[, attestations]) tuple is admitted as valid HSP evidence (≠ "ship")
  outcomeClass: OutcomeClass; // NORMATIVE (§8.0)
  errorCode?: string; // informative §8 diagnostic
  errorDetail?: string; // informative free text
}

// =============================================================================
// §4.1 SignerProfile
// =============================================================================

export interface SignerDecision {
  granted: boolean;
  errorCode?: string;
  errorDetail?: string; // informative free text (e.g. recovered-vs-declared signer); surfaced via AcceptDecision.errorDetail
  resolvedSubject?: PartyRef; // stable PartyRef when granted == true (SP6)
  signerStateHash?: Hex; // for stateDependent profiles (SP7)
}

export interface SignerProfileDescription {
  profileId: string;
  signatureSchemes: string[];
  bindsRequiredCapabilitiesHash: boolean;
  supportsBatch: boolean;
  stateDependent: boolean; // true ⇒ verify() consults mutable state; gates §5.1 step 4b
}

export interface SignerStateAnchor {
  [k: string]: unknown; // deployment-pinned current-state source + staleness delta (profile-defined)
}

export interface SignerProfile {
  readonly profileId: string;
  readonly profileIdHash: Hex; // == keccak256(profileId); == Signer.profileId
  readonly description: SignerProfileDescription;
  decode(payload: Hex): PartyRef;
  // §4.1: the on-chain ACCOUNT whose value-moving operation (Transfer.from) binds the
  // payer. For an EOA this equals decode(payload); for a smart account (erc1271.v1) it
  // is the account address, NOT the agent/owner. §5.2 step 4 binds the settlement sender
  // to accountOf(principalSubject).
  accountOf(payload: Hex): PartyRef;
  // verify a proof against the bound HSP typed-data digest — mandateHash for a
  // Mandate signer, grantHash for a DelegationGrant principal (§5.1 step 4c-i).
  // `body` is the execution context (unused by eoa/erc1271 profiles; reserved).
  verify(payload: Hex, proof: Hex, digest: Hex, body: Mandate): Promise<SignerDecision>;
  isStateStale?(signerStateHash: Hex, stateAnchor: SignerStateAnchor, now: number): boolean;
}

// =============================================================================
// §4.2 AdapterProofSchema
// =============================================================================

export type AmountObservation =
  | { kind: 'exact'; value: bigint }
  | { kind: 'upper-bound'; value: bigint } // shielded but cap-bounded
  | { kind: 'hidden' }; // fully shielded; no comparable public value

export type RecipientObservation =
  | { kind: 'address'; address: Address }
  | { kind: 'stealth'; derivedFrom: Hex }
  | { kind: 'shielded'; boundTo?: Hex }; // boundTo: mandate commitment the schema cryptographically verified the settlement pays (§5.2 step 4); absent ⇔ no binding claim

/** §4.2.2 receipt fields excluding adapterProof. */
export type ReceiptHeader = Omit<Receipt, 'adapterProof'>;

/** Deployment-pinned per-adapter material (SPV/light-client/ZK keys, association-set policy). */
export interface AdapterTrustRoots {
  [k: string]: unknown;
}

export interface VerifyContext {
  proofBytes: Hex; // receipt.adapterProof
  body: Mandate;
  mandateHash: Hex;
  signerSubject: PartyRef; // SignerDecision.resolvedSubject — the SIGNER (Agent when delegated)
  payerAccount: PartyRef; // §4.1 accountOf(principal) — the on-chain account whose Transfer.from binds
  //   (the Agent/signer for self-pay, the smart account when delegated). §5.2 step-4 sender binding
  //   checks against THIS, never signerSubject or tx.from.
  receipt: ReceiptHeader;
  now: number; // Unix seconds; verifier-pinned
  trustRoots: AdapterTrustRoots;
}

export interface VerifyOutcome {
  ok: boolean;
  errorCode?: string; // HSP-PROOF-* / HSP-BIND-*
  proofSatisfiedCapabilities: Hex[]; // per-call; MUST ⊆ schema registration's static capabilities (§6.1)
  amountObservation: AmountObservation; // mandatory when ok == true
  recipientObservation: RecipientObservation; // mandatory when ok == true
  tokenObserved?: { kind: 'evm-address'; address: Address };
  chainIdObserved?: number;
  /**
   * Canonical identity of the settlement-native observation, derived
   * deterministically from the (signed) adapterProof. MUST be present when
   * ok=true for schemas whose settlement artifact is NOT cryptographically
   * bound to mandateHash (observation-based adapters); MAY be omitted when it
   * is (e.g. x402). Consumed by §5.2 step 7's observation-consumption index.
   */
  observationId?: Hex;
}

export interface AdapterProofSchema {
  verify(ctx: VerifyContext): Promise<VerifyOutcome>; // the single normative method
}

// =============================================================================
// §6.1.2 ReorgPolicy
// =============================================================================

export interface ReorgPolicy {
  allowsAttempted: boolean; // MAY emit non-terminal ATTEMPTED?
  chainObservation: 'required' | 'not-applicable';
  disputeWindowMs?: number; // post-SETTLED reversal window; absent ⇒ MUST NOT emit DISPUTED
}

// =============================================================================
// §6.1.1 / §7.2.1 registration entries
// =============================================================================

export type SchemaAdmission = 'accept-new' | 'accept-historical' | 'accept-dispute-only';

export interface AdapterTrustEntry {
  address: Address; // instance signing key; recovers from adapterSignature over receiptHash (§5.2 step 2)
  reorgPolicy: ReorgPolicy;
}

export interface SchemaRegistrationEntry {
  schema: AdapterProofSchema;
  allowedCapabilities: Hex[]; // static upper bound on proofSatisfiedCapabilities (§6.1.1)
  admission: SchemaAdmission;
  trustRoots: AdapterTrustRoots;
  proofPayloadStore?: string; // for hash-only / hybrid receipts (§6.1.7)
}

// =============================================================================
// §4.3.6 attestation trust anchors
// =============================================================================

export interface TrustAnchor {
  scheme: string; // "evm-key" | "did-key" | "x509" | ...
  identifier: Hex; // issuer signing-key ref
  acceptedSchemaIds: Hex[]; // which attestation schemas this anchor may sign
}

// =============================================================================
// §7 VerificationPolicy — five dispatch tables (fail-closed) + predicates + scalars
// =============================================================================

export interface SignerProfileEntry {
  profile: SignerProfile;
  stateAnchor?: SignerStateAnchor; // for SP7 state-dependent profiles
}

/** key helpers for the composite-keyed tables (lowercased for stability). */
export const adapterKey = (adapterId: Hex, adapterInstanceKey: Hex): string =>
  `${adapterId.toLowerCase()}:${adapterInstanceKey.toLowerCase()}`;
export const schemaKey = (adapterId: Hex, proofSchemaId: Hex): string =>
  `${adapterId.toLowerCase()}:${proofSchemaId.toLowerCase()}`;

export interface VerificationPolicy {
  verifyingContract: Address;
  acceptedVerifyingContracts: Set<string>; // lowercased addresses (§5.1 step 1b)
  domainVersion?: string; // §1.5 policy-pinned EIP-712 domain version; defaults to "1" (the only value this revision defines)

  // five dispatch tables (§7.2.1; fail-closed on miss)
  signerProfiles: Map<Hex, SignerProfileEntry>; // key = Signer.profileId (§5.1 s4)
  adapterTrust: Map<string, AdapterTrustEntry>; // key = adapterKey(...) (§5.2 s2, s7)
  proofSchemas: Map<string, SchemaRegistrationEntry>; // key = schemaKey(...) (§5.2 s3-4)
  capabilityRegistry: Map<Hex, ParsedCapability>; // §3.3.1 — cap id → structured registered cap (Base/Role)
  issuerTrustAnchors: Map<Hex, TrustAnchor[]>; // key = base attests cap id (§5.2 s5 CR2b)

  // predicates (§7.2.2) + scalars
  policyRequiredCapabilities?: Hex[]; // §5.1 step 3b
  contextBindingScope: Map<Hex, 'mandate' | 'receipt'>;
  auditorSubject?: PartyRef; // §3.4
  evaluationTime: number; // verifier-pinned `now` (CR5)
}
