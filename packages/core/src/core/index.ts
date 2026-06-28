/**
 * @hsp/core — the single import surface for the reference implementation.
 *
 * Re-exports the pinned hash derivations (../derivations.ts, guarded against
 * HSP.md by ../guard.ts) and the typed wire-object model (./types.ts). The
 * actors (profiles / adapter / attestation / verifier) import from here.
 */

// Typed wire-object model (§2): Domain, Signer, Recipient, Mandate,
// SignedMandate, Outcome, Receipt, PartyRef, Attestation,
// canonicalRefId, partyRefEqual, RecipientKind.
export * from './types.js';

// Capability tooling (§3): baseline registry, role wrap, human-form parse/format,
// canonical set form, monotone (§3.3.3) matching.
export * from './capabilities.js';

// Pinned EIP-712 / keccak derivations (§2.4, §3.1) + their field arrays.
export {
  capabilityId,
  canonicalParamsEncoding,
  requiredCapabilitiesHash,
  mandateHash,
  grantHash,
  receiptHash,
  preprocessInput,
  MANDATE_FIELDS,
  GRANT_FIELDS,
  RECEIPT_PREIMAGE_FIELDS,
  NESTED_TYPES,
} from '../derivations.js';

// Hashing-input shapes (the *Input names ../derivations.ts exports; ./types.ts
// aliases the wire-facing ones to Domain/Signer/Recipient/Mandate/Receipt).
export type {
  CapabilityIdInput,
  CanonicalParam,
  ParamType,
  DomainInput,
  SignerInput,
  RecipientInput,
  MandateInput,
  DelegationGrantInput,
  ReceiptInput,
} from '../derivations.js';
