/**
 * HSP Phase-1 reference hash derivations.
 *
 * Each function pins ONE normative MUST from the single-doc spec (HSP.md):
 *   - capabilityId               HSP.md §3.1 (id) + §3.1.4 (canonical params)
 *   - requiredCapabilitiesHash   HSP.md §3.1.3
 *   - mandateHash                HSP.md §2.4.1
 *   - receiptHash                HSP.md §2.4.2
 *
 * The EIP-712 field set/order/types below are pinned to HSP.md by src/guard.ts
 * (run as part of `npm run verify`): if the spec's MANDATE_TYPEHASH moves,
 * the guard fails until this file is updated and fixtures are re-frozen.
 *
 * If you find a discrepancy between this file and the spec, the spec wins —
 * fix the function and re-freeze fixtures, then explain in the PR which side moved.
 */

import {
  keccak256,
  encodeAbiParameters,
  hashTypedData,
  type Hex,
  type Address,
} from 'viem';

// =============================================================================
// capabilityId   HSP.md §3.1 (id) + §3.1.4 (canonical params)
// =============================================================================

export type ParamType = 'string' | 'uint256' | 'bytes32' | 'bool' | 'address';

export interface CanonicalParam {
  key: string;
  type: ParamType;
  value: string | number | boolean;
}

export interface CapabilityIdInput {
  namespace: string;
  name: string;
  version: string;
  params: CanonicalParam[];
}

/**
 * §2.4: canonical(params)
 *   1. Sort entries by key (bytes lexicographic).
 *   2. abi.encode each entry as (string key, T value) for the declared type T.
 *   3. Concatenate.
 *
 * Empty params → empty bytes "0x".
 */
export function canonicalParamsEncoding(params: CanonicalParam[]): Hex {
  if (params.length === 0) return '0x';
  const sorted = [...params].sort((a, b) =>
    a.key < b.key ? -1 : a.key > b.key ? 1 : 0,
  );
  const parts = sorted.map((p) => {
    const value = coerceParamValue(p);
    return encodeAbiParameters(
      [{ type: 'string' }, { type: p.type }],
      [p.key, value],
    );
  });
  // Concatenate hex strings (strip "0x" from each, join, re-prefix).
  return ('0x' + parts.map((h) => h.slice(2)).join('')) as Hex;
}

type AbiParamValue = string | bigint | boolean | Hex | Address;

function coerceParamValue(p: CanonicalParam): AbiParamValue {
  switch (p.type) {
    case 'string':
      if (typeof p.value !== 'string') throw new Error(`param ${p.key}: expected string`);
      return p.value;
    case 'uint256':
      // Accept decimal string OR number; convert to bigint.
      return BigInt(typeof p.value === 'number' ? p.value : String(p.value));
    case 'bytes32':
      if (typeof p.value !== 'string' || !p.value.startsWith('0x')) {
        throw new Error(`param ${p.key}: bytes32 must be 0x-prefixed hex`);
      }
      return p.value as Hex;
    case 'bool':
      return Boolean(p.value);
    case 'address':
      if (typeof p.value !== 'string' || !p.value.startsWith('0x')) {
        throw new Error(`param ${p.key}: address must be 0x-prefixed hex`);
      }
      return p.value as Address;
  }
}

/**
 * §2.1: capabilityId = keccak256(abi.encode(
 *           bytes(namespace), bytes(name), bytes(version), keccak256(canonical(params))
 *       ))
 *
 * NOTE: `bytes` and `string` ABI encodings are byte-identical for the same content;
 * we use `string` here because inputs are naturally JS strings.
 */
export function capabilityId(input: CapabilityIdInput): Hex {
  const paramsCanon = canonicalParamsEncoding(input.params);
  const paramsHash = keccak256(paramsCanon);
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'bytes32' },
      ],
      [input.namespace, input.name, input.version, paramsHash],
    ),
  );
}

// =============================================================================
// requiredCapabilitiesHash   HSP.md §3.1.3
// =============================================================================

const ZERO_HASH: Hex = ('0x' + '00'.repeat(32)) as Hex;

/**
 * §2.3:
 *   canonicalize(envelope.requiredCapabilities) → bytes32[]
 *     1. multiset of ids
 *     2. dedupe (keep one copy)
 *     3. sort lexicographically as bytes32 (ascending byte order)
 *
 *   requiredCapabilitiesHash =
 *     bytes32(0)                       if canon is empty
 *     keccak256(abi.encode(canon))     otherwise
 */
export function requiredCapabilitiesHash(capabilities: Hex[]): Hex {
  // Normalize hex case to lowercase before dedup so 0xAB and 0xab don't survive both.
  const normalized = capabilities.map((c) => c.toLowerCase() as Hex);
  const dedup = Array.from(new Set(normalized));
  // Lexicographic byte-order sort: hex-string compare on lowercased 0x-prefixed values
  // is byte-equivalent (each pair of hex chars is one byte; '0'-'9' < 'a'-'f' lexically
  // already matches the byte-value ordering for normalized lowercase).
  const sorted = [...dedup].sort();
  if (sorted.length === 0) return ZERO_HASH;
  return keccak256(encodeAbiParameters([{ type: 'bytes32[]' }], [sorted]));
}

// =============================================================================
// EIP-712: mandateHash   HSP.md §2.4.1
// =============================================================================

export interface DomainInput {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: Address;
}

export interface SignerInput {
  profileId: Hex;
  payload: Hex;
}

export interface RecipientInput {
  kind: number;
  payload: Hex;
}

export interface MandateInput {
  nonce: Hex;
  signer: SignerInput;
  grantRef?: Hex;                  // §2.1.2; NONE (ZERO32) for self-pay — defaults below
  requirementRef?: Hex;            // NONE when no PayeeRequirement is bound
  recipient: RecipientInput;
  token: Address;                  // bare EVM ERC-20 contract address (HSP.md §2.1.2)
  amount: string;
  chainId: number | string;
  deadline: number;
  settlementBinding?: Hex;         // NONE unless proves:settlement-bound via=onchain-ref
  requiredCapabilitiesHash: Hex;
}

// NONE sentinel for the three optional Mandate refs (self-pay leaves them ZERO32).
const NONE32: Hex = `0x${'00'.repeat(32)}`;

export const NESTED_TYPES = {
  // §2.4.1: nested types appended in lexicographic order by struct name.
  Recipient: [
    { name: 'kind', type: 'uint8' },
    { name: 'payload', type: 'bytes' },
  ],
  Signer: [
    { name: 'profileId', type: 'bytes32' },
    { name: 'payload', type: 'bytes' },
  ],
} as const;

// Mandate field order — MUST match HSP.md §2.4.1 MANDATE_TYPEHASH.
// v-next spec: 11 fields (v0 MandateBody was 8; grantRef/requirementRef/settlementBinding added).
// (Field set/order/types pinned to the spec by src/guard.ts.)
export const MANDATE_FIELDS = [
  { name: 'nonce', type: 'bytes32' },
  { name: 'signer', type: 'Signer' },
  { name: 'grantRef', type: 'bytes32' },
  { name: 'requirementRef', type: 'bytes32' },
  { name: 'recipient', type: 'Recipient' },
  { name: 'token', type: 'address' },
  { name: 'amount', type: 'uint256' },
  { name: 'chainId', type: 'uint256' },
  { name: 'deadline', type: 'uint64' },
  { name: 'settlementBinding', type: 'bytes32' },
  { name: 'requiredCapabilitiesHash', type: 'bytes32' },
] as const;

function bodyMessage(b: MandateInput): Record<string, unknown> {
  return {
    nonce: b.nonce,
    signer: { profileId: b.signer.profileId, payload: b.signer.payload },
    grantRef: b.grantRef ?? NONE32,
    requirementRef: b.requirementRef ?? NONE32,
    recipient: { kind: b.recipient.kind, payload: b.recipient.payload },
    token: b.token,
    amount: BigInt(b.amount),
    chainId: BigInt(b.chainId),
    deadline: BigInt(b.deadline),
    settlementBinding: b.settlementBinding ?? NONE32,
    requiredCapabilitiesHash: b.requiredCapabilitiesHash,
  };
}

// viem's hashTypedData has strict generic constraints; for our dynamic-from-JSON
// inputs, we narrow at the call site via `as never`-style casts on the args object.
// The runtime behavior is exercised by the fixture pack, not by TS types.

type HashTypedDataArgs = Parameters<typeof hashTypedData>[0];

export function mandateHash(domain: DomainInput, body: MandateInput): Hex {
  return hashTypedData({
    domain,
    types: {
      Mandate: [...MANDATE_FIELDS],
      ...NESTED_TYPES,
    },
    primaryType: 'Mandate',
    message: bodyMessage(body),
  } as unknown as HashTypedDataArgs);
}

// =============================================================================
// EIP-712: grantHash   HSP.md §2.4.1a (delegated payments)
//   The Principal signs grantHash; Mandate.grantRef commits to it.
//   GRANT_TYPEHASH covers every field EXCEPT principalProof (envelope-only, §2.1.1).
// =============================================================================

export interface DelegationGrantInput {
  principal: SignerInput;          // account/fund owner; typically erc1271.v1 (a smart account)
  agent: SignerInput;              // the identity authorized to sign Mandates
  onchainPermissionRef: Hex;       // bytes32 — ERC-7715 permissionId / ERC-4337 session-key ref
  payerRequiredCaps: Hex[];        // payer-side FLOOR every execution MUST cover
  payerAllowedCaps: Hex[];         // payer-side CEILING the Agent may declare
  notBefore: number;
  expiry: number;
  nonce: Hex;
}

// DelegationGrant field order — MUST match HSP.md §2.4.1a GRANT_TYPEHASH.
// Only `Signer` is a referenced struct (bytes32[] arrays carry no nested type).
export const GRANT_FIELDS = [
  { name: 'principal', type: 'Signer' },
  { name: 'agent', type: 'Signer' },
  { name: 'onchainPermissionRef', type: 'bytes32' },
  { name: 'payerRequiredCaps', type: 'bytes32[]' },
  { name: 'payerAllowedCaps', type: 'bytes32[]' },
  { name: 'notBefore', type: 'uint64' },
  { name: 'expiry', type: 'uint64' },
  { name: 'nonce', type: 'bytes32' },
] as const;

function grantMessage(g: DelegationGrantInput): Record<string, unknown> {
  return {
    principal: { profileId: g.principal.profileId, payload: g.principal.payload },
    agent: { profileId: g.agent.profileId, payload: g.agent.payload },
    onchainPermissionRef: g.onchainPermissionRef,
    payerRequiredCaps: g.payerRequiredCaps,
    payerAllowedCaps: g.payerAllowedCaps,
    notBefore: BigInt(g.notBefore),
    expiry: BigInt(g.expiry),
    nonce: g.nonce,
  };
}

export function grantHash(domain: DomainInput, grant: DelegationGrantInput): Hex {
  return hashTypedData({
    domain,
    types: {
      DelegationGrant: [...GRANT_FIELDS],
      Signer: NESTED_TYPES.Signer,
    },
    primaryType: 'DelegationGrant',
    message: grantMessage(grant),
  } as unknown as HashTypedDataArgs);
}

// =============================================================================
// receiptHash   HSP.md §2.4.2
//   EIP-712 typed-data digest over RECEIPT_PREIMAGE_TYPEHASH; the adapter signs it
//   (Receipt.adapterSignature). Same EIP-712 domain as the mandate (§5.2 step 2).
//   adapterProof enters the struct as keccak256(bytes) per note D2 — fixed-width.
// =============================================================================

export interface ReceiptInput {
  mandateHash: Hex;
  adapterId: Hex;
  adapterInstanceKey: Hex;
  seq: number | string;
  outcome: number;                 // 0=ATTEMPTED, 1=SETTLED, 2=FAILED, 3=DISPUTED (§2.2.2)
  settledAt: number | string;
  proofSchemaId: Hex;
  adapterProof: Hex;               // raw adapter bytes; hashed internally per D2
}

// ReceiptPreimage field order — MUST match HSP.md §2.4.2 RECEIPT_PREIMAGE_TYPEHASH.
// 8 fields; the dynamic `adapterProof` enters as bytes32 `adapterProofHash`
// (= keccak256(adapterProof), D2). Field set/order/types pinned to the spec by
// src/guard.ts (RECEIPT_PREIMAGE_TYPEHASH check). No nested struct types.
export const RECEIPT_PREIMAGE_FIELDS = [
  { name: 'mandateHash', type: 'bytes32' },
  { name: 'adapterId', type: 'bytes32' },
  { name: 'adapterInstanceKey', type: 'bytes32' },
  { name: 'seq', type: 'uint64' },
  { name: 'outcome', type: 'uint8' },
  { name: 'settledAt', type: 'uint64' },
  { name: 'proofSchemaId', type: 'bytes32' },
  { name: 'adapterProofHash', type: 'bytes32' },
] as const;

export function receiptHash(domain: DomainInput, receipt: ReceiptInput): Hex {
  const adapterProofHash = keccak256(receipt.adapterProof);
  return hashTypedData({
    domain,
    types: { ReceiptPreimage: [...RECEIPT_PREIMAGE_FIELDS] },
    primaryType: 'ReceiptPreimage',
    message: {
      mandateHash: receipt.mandateHash,
      adapterId: receipt.adapterId,
      adapterInstanceKey: receipt.adapterInstanceKey,
      seq: BigInt(receipt.seq),
      outcome: receipt.outcome,
      settledAt: BigInt(receipt.settledAt),
      proofSchemaId: receipt.proofSchemaId,
      adapterProofHash,
    },
  } as unknown as HashTypedDataArgs);
}

// =============================================================================
// Fixture preprocessing: resolve _inline_* helpers in the JSON `input` payload
// before dispatching to a derivation. Keeps fixtures readable.
// =============================================================================

export function preprocessInput(
  derivation: string,
  input: Record<string, unknown>,
): Record<string, unknown> {
  switch (derivation) {
    case 'requiredCapabilitiesHash':
      return preprocessRequiredCapsInput(input);
    case 'mandateHash':
      return preprocessMandateLikeInput(input);
    default:
      // No preprocessing for other derivations.
      return input;
  }
}

function preprocessRequiredCapsInput(input: Record<string, unknown>): Record<string, unknown> {
  const inline = input['_inline_capability_ids'] as CapabilityIdInput[] | undefined;
  // Two valid shapes:
  //   (a) `_inline_capability_ids`: the runner computes each id and uses inline order as wire order.
  //   (b) literal `capabilities[]`: bytes32 hex strings used as-is.
  // Exactly one MUST be present.
  if (inline) {
    if (input['capabilities'] !== undefined) {
      throw new Error(
        '_inline_capability_ids and capabilities[] are mutually exclusive; pick one.',
      );
    }
    const computed = inline.map((c) => capabilityId(c));
    return { capabilities: computed };
  }
  if (input['capabilities'] === undefined) {
    throw new Error('input must have either _inline_capability_ids or capabilities[]');
  }
  return { capabilities: input['capabilities'] };
}

function preprocessMandateLikeInput(input: Record<string, unknown>): Record<string, unknown> {
  const body = { ...(input['body'] as Record<string, unknown>) };
  const inlineRecipient = input['_inline_recipient_payload'] as
    | { commitment: Hex; derivationContext: Hex }
    | undefined;
  if (inlineRecipient) {
    const encoded = encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'bytes32' }],
      [inlineRecipient.commitment, inlineRecipient.derivationContext],
    );
    const oldRecipient = body['recipient'] as Record<string, unknown>;
    body['recipient'] = { ...oldRecipient, payload: encoded };
  }
  return { domain: input['domain'], body };
}
