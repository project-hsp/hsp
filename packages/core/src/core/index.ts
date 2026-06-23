/**
 * @hsp/core — the single import surface for the reference implementation.
 *
 * Re-exports the pinned hash derivations (../derivations.ts, guarded against
 * HSP.md by ../guard.ts) and the typed wire-object model (./types.ts). The
 * actors (profiles / adapter / attestation / verifier) import from here.
 */

// Typed wire-object model (§2): Domain, Signer, Recipient, MandateBody,
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
  receiptHash,
  preprocessInput,
  MANDATE_BODY_FIELDS,
  RECEIPT_PREIMAGE_FIELDS,
  NESTED_TYPES,
} from '../derivations.js';

// Hashing-input shapes (the *Input names ../derivations.ts exports; ./types.ts
// aliases the wire-facing ones to Domain/Signer/Recipient/MandateBody/Receipt).
export type {
  CapabilityIdInput,
  CanonicalParam,
  ParamType,
  DomainInput,
  SignerInput,
  RecipientInput,
  MandateBodyInput,
  ReceiptInput,
} from '../derivations.js';
