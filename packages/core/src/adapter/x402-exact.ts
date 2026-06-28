/**
 * x402 `exact`-EVM proof schema v2 (`adapter:x402`, proofSchemaId
 * `x402-exact.proof.v2`) — the conformant-x402 bridge. See docs/design/
 * x402-alignment.md §4–§5.
 *
 * Unlike the v1 challenge/ack schema, v2 binds directly to the EIP-3009
 * authorization the payer signed under the TOKEN's domain. The payer binding is
 * CRYPTOGRAPHIC (the authorization signature recovers to `from`, which MUST equal
 * the HSP mandate signer); only the *fact that settlement executed* (the txHash)
 * rests on the facilitator's operator signature (§4 operator-trust boundary). So
 * even an untrusted facilitator cannot make a payment satisfy caps it didn't —
 * it cannot forge the payer's authorization or mandate.
 *
 *   payer A  signs:  HSP mandate (eip712-eoa over mandateHash)
 *                    EIP-3009 TransferWithAuthorization (token domain)  ── same EOA A
 *   facilitator      relays transferWithAuthorization, signs the Receipt (adapterSignature)
 *
 * Settlement model = self-settling (the EIP-3009 signature chain is the
 * authority; the facilitator only relays + asserts the txHash). adapterId is the
 * SAME `adapter:x402` as v1 — only the proofSchemaId is new, so both coexist
 * until v1 retires (P5).
 */

import {
  keccak256,
  stringToBytes,
  encodeAbiParameters,
  decodeAbiParameters,
  getAddress,
  recoverTypedDataAddress,
  type Hex,
  type Address,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  receiptHash as computeReceiptHash,
  RecipientKind,
  Outcome,
  type OutcomeValue,
  type Receipt,
  type ReceiptInput,
  type DomainInput,
} from '../core/index.js';
import type { AdapterProofSchema, VerifyContext, VerifyOutcome } from '../verifier/contracts.js';
import { X402_ADAPTER_ID } from './x402.js';
import { transferObservationId } from './mock-evm-transfer.js';

export { X402_ADAPTER_ID };
export const X402_EXACT_PROOF_SCHEMA_ID: Hex = keccak256(stringToBytes('x402-exact.proof.v2'));
const ZERO32: Hex = `0x${'00'.repeat(32)}`;

/** EIP-712 types for EIP-3009 TransferWithAuthorization (the token's domain). */
const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const;

/**
 * The exact-EVM settlement the facilitator attests: the payer-signed EIP-3009
 * authorization + the token's EIP-712 domain {name, version} (so the verifier can
 * re-derive the signature) + the settlement coordinates (chainId, txHash). The
 * observed transfer == the authorization (the token contract enforces it at
 * settle), so from/to/value are the authorization's, not separately carried.
 */
export interface X402ExactProof {
  from: Address; // authorization.from == the payer (mandate signer)
  to: Address; // authorization.to == the merchant (mandate recipient)
  value: bigint; // authorization.value == mandate.amount
  validAfter: number;
  validBefore: number;
  nonce: Hex;
  signature: Hex; // payer's EIP-712 signature over the authorization (token domain)
  token: Address; // verifyingContract == asset == mandate.token
  tokenName: string; // token EIP-712 domain name (from PaymentRequirements.extra)
  tokenVersion: string; // token EIP-712 domain version
  chainId: number; // == mandate.chainId == settlement chain
  txHash: Hex; // settlement transaction (observationId source)
}

const PROOF_ABI = [
  { type: 'address' }, // from
  { type: 'address' }, // to
  { type: 'uint256' }, // value
  { type: 'uint256' }, // validAfter
  { type: 'uint256' }, // validBefore
  { type: 'bytes32' }, // nonce
  { type: 'bytes' }, // signature
  { type: 'address' }, // token
  { type: 'string' }, // tokenName
  { type: 'string' }, // tokenVersion
  { type: 'uint256' }, // chainId
  { type: 'bytes32' }, // txHash
] as const;

export function encodeX402ExactProof(p: X402ExactProof): Hex {
  return encodeAbiParameters(PROOF_ABI, [
    getAddress(p.from),
    getAddress(p.to),
    BigInt(p.value),
    BigInt(p.validAfter),
    BigInt(p.validBefore),
    p.nonce,
    p.signature,
    getAddress(p.token),
    p.tokenName,
    p.tokenVersion,
    BigInt(p.chainId),
    p.txHash,
  ]);
}

export function decodeX402ExactProof(bytes: Hex): X402ExactProof {
  const [from, to, value, validAfter, validBefore, nonce, signature, token, tokenName, tokenVersion, chainId, txHash] =
    decodeAbiParameters(PROOF_ABI, bytes);
  return {
    from,
    to,
    value,
    validAfter: Number(validAfter),
    validBefore: Number(validBefore),
    nonce,
    signature,
    token,
    tokenName,
    tokenVersion,
    chainId: Number(chainId),
    txHash,
  };
}

/** Settlement-native observation identity — same (chainId, token, txHash) shape as the wallet-settled path. */
export const x402ExactObservationId = transferObservationId;

function fail(errorCode: string): VerifyOutcome {
  return { ok: false, errorCode, proofSatisfiedCapabilities: [], amountObservation: { kind: 'hidden' }, recipientObservation: { kind: 'shielded' } };
}

export const x402ExactSchema: AdapterProofSchema = {
  async verify(ctx: VerifyContext): Promise<VerifyOutcome> {
    let p: X402ExactProof;
    try {
      p = decodeX402ExactProof(ctx.proofBytes);
    } catch {
      return fail('HSP-RCPT-PROOF');
    }

    // recipient (merchant) MUST be an ADDRESS — exact-EVM payTo is an address, not a role label
    if (ctx.body.recipient.kind !== RecipientKind.ADDRESS) return fail('HSP-RCPT-PROOF');
    let merchant: Address;
    try {
      merchant = getAddress(decodeAbiParameters([{ type: 'address' }], ctx.body.recipient.payload)[0]);
    } catch {
      return fail('HSP-RCPT-PROOF');
    }
    // payer = the HSP mandate signer (eip712-eoa); x402's authorization.from MUST equal it
    if (ctx.signerSubject.scheme !== 'evm-address') return fail('HSP-RCPT-PROOF');
    let payer: Address;
    try {
      payer = getAddress(decodeAbiParameters([{ type: 'address' }], ctx.signerSubject.id)[0]);
    } catch {
      return fail('HSP-RCPT-PROOF');
    }

    // §4 signature fail-closed: the authorization signature MUST EIP-712-verify to `from`
    // under the token's domain (else the carried authorization is forged/mismatched).
    let recovered: Address;
    try {
      recovered = await recoverTypedDataAddress({
        domain: { name: p.tokenName, version: p.tokenVersion, chainId: p.chainId, verifyingContract: getAddress(p.token) },
        types: TRANSFER_WITH_AUTHORIZATION_TYPES,
        primaryType: 'TransferWithAuthorization',
        message: {
          from: getAddress(p.from),
          to: getAddress(p.to),
          value: BigInt(p.value),
          validAfter: BigInt(p.validAfter),
          validBefore: BigInt(p.validBefore),
          nonce: p.nonce,
        },
        signature: p.signature,
      });
    } catch {
      return fail('HSP-RCPT-PROOF');
    }
    if (getAddress(recovered) !== getAddress(p.from)) return fail('HSP-RCPT-PROOF');

    // §4 binding table (every row fail-closed → HSP-RCPT-PROOF)
    if (getAddress(p.from) !== payer) return fail('HSP-RCPT-PROOF'); // signer ↔ authorization.from
    if (getAddress(p.to) !== merchant) return fail('HSP-RCPT-PROOF'); // recipient ↔ authorization.to
    if (getAddress(p.token) !== getAddress(ctx.body.token)) return fail('HSP-RCPT-PROOF'); // token (×4 collapsed)
    if (BigInt(p.value) !== BigInt(ctx.body.amount)) return fail('HSP-RCPT-PROOF'); // amount exact
    if (p.chainId !== Number(ctx.body.chainId)) return fail('HSP-RCPT-PROOF'); // chain (×4 collapsed)
    // deadline (settledAt ≤ deadline) is enforced globally at §5.2 step 7; the EIP-3009 window
    // is enforced by the token at settle (a successful settlement proves it held).

    return {
      ok: true,
      proofSatisfiedCapabilities: [], // operator-trusted (default): no proves:settlement-verified
      amountObservation: { kind: 'exact', value: BigInt(p.value) },
      recipientObservation: { kind: 'address', address: merchant },
      tokenObserved: { kind: 'evm-address', address: getAddress(p.token) },
      chainIdObserved: p.chainId,
      observationId: x402ExactObservationId(p), // consumed once across instances (§5.2 step 7)
    };
  },
};

export interface BuildX402ExactReceiptArgs {
  domain: DomainInput;
  mandateHash: Hex;
  proof: X402ExactProof;
  adapterPrivateKey: Hex; // the facilitator / x402 server key (trusted adapter key)
  adapterInstanceKey: Hex; // keccak256(merchantDomain)
  settledAt: number; // settlement time (≤ deadline); §2.2 outcome-effective time
  seq?: number;
  outcome?: OutcomeValue;
}

/** Facilitator side: assemble + sign the v2 Receipt. */
export async function buildAndSignX402ExactReceipt(args: BuildX402ExactReceiptArgs): Promise<Receipt> {
  const core: ReceiptInput = {
    mandateHash: args.mandateHash,
    adapterId: X402_ADAPTER_ID,
    adapterInstanceKey: args.adapterInstanceKey ?? ZERO32,
    seq: args.seq ?? 0,
    outcome: args.outcome ?? Outcome.SETTLED,
    settledAt: args.settledAt,
    proofSchemaId: X402_EXACT_PROOF_SCHEMA_ID,
    adapterProof: encodeX402ExactProof(args.proof),
  };
  const rHash = computeReceiptHash(args.domain, core);
  const adapterSignature = await privateKeyToAccount(args.adapterPrivateKey).sign({ hash: rHash });
  return { ...core, adapterSignature };
}
