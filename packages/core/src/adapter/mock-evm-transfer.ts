/**
 * Public EVM-transfer adapter (`adapter:evm-transfer`) — M1 mock.
 *
 * The §4.2.1 operator-signature trust baseline (A1–A3): the adapterProof is an
 * operator-attested observation of an ERC-20 Transfer; the adapter signs the Receipt
 * (receiptHash). No trust-minimization (`proves:settlement-verified` is M4). This
 * module is the Adapter Operator's receipt builder + the AdapterProofSchema the
 * Verifier calls at §5.2 step 4. "Mock" = the Transfer observation is supplied
 * directly rather than scraped from a live anvil chain (that wiring lands with foundry).
 */

import {
  keccak256,
  stringToBytes,
  encodeAbiParameters,
  decodeAbiParameters,
  getAddress,
  type Hex,
  type Address,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  receiptHash as computeReceiptHash,
  Outcome,
  RecipientKind,
  type OutcomeValue,
  type Receipt,
  type ReceiptInput,
  type DomainInput,
} from '../core/index.js';
import type { AdapterProofSchema, VerifyContext, VerifyOutcome } from '../verifier/contracts.js';

export const EVM_TRANSFER_ADAPTER_ID: Hex = keccak256(stringToBytes('adapter:evm-transfer'));
export const EVM_TRANSFER_PROOF_SCHEMA_ID: Hex = keccak256(stringToBytes('evm-transfer.proof.v1'));
const ZERO32: Hex = `0x${'00'.repeat(32)}`;

export interface TransferObservation {
  from: Address;
  to: Address;
  token: Address;
  value: bigint;
  chainId: number;
  txHash: Hex;
  blockNumber: bigint;
}

const PROOF_ABI = [
  { type: 'address' }, // from
  { type: 'address' }, // to
  { type: 'address' }, // token
  { type: 'uint256' }, // value
  { type: 'uint256' }, // chainId
  { type: 'bytes32' }, // txHash
  { type: 'uint256' }, // blockNumber
] as const;

export function encodeTransferProof(o: TransferObservation): Hex {
  return encodeAbiParameters(PROOF_ABI, [o.from, o.to, o.token, o.value, BigInt(o.chainId), o.txHash, o.blockNumber]);
}

export function decodeTransferProof(bytes: Hex): TransferObservation {
  const [from, to, token, value, chainId, txHash, blockNumber] = decodeAbiParameters(PROOF_ABI, bytes);
  return { from, to, token, value, chainId: Number(chainId), txHash, blockNumber };
}

/**
 * Settlement-native observation identity (§5.2 step 7 observation-consumption
 * index): one on-chain transfer is consumable by at most one mandate. Shared by
 * every schema observing bare ERC-20 transfers under this adapterId.
 */
export function transferObservationId(o: Pick<TransferObservation, 'chainId' | 'token' | 'txHash'>): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: 'uint256' }, { type: 'address' }, { type: 'bytes32' }],
      [BigInt(o.chainId), getAddress(o.token), o.txHash],
    ),
  );
}

// On a failure result the observations are never read by the verifier; placeholders satisfy the type.
function fail(errorCode: string): VerifyOutcome {
  return {
    ok: false,
    errorCode,
    proofSatisfiedCapabilities: [],
    amountObservation: { kind: 'hidden' },
    recipientObservation: { kind: 'shielded' },
  };
}

/** §4.2 AdapterProofSchema for the public adapter. Public payment → proofSatisfiedCapabilities = []. */
export const evmTransferSchema: AdapterProofSchema = {
  async verify(ctx: VerifyContext): Promise<VerifyOutcome> {
    let o: TransferObservation;
    try {
      o = decodeTransferProof(ctx.proofBytes);
    } catch {
      return fail('HSP-RCPT-PROOF');
    }
    // COMMITMENT recipients need a derivation/binding claim this plain-transfer schema
    // cannot make (§5.2 step 4) — fail closed.
    if (ctx.body.recipient.kind !== RecipientKind.ADDRESS) return fail('HSP-RCPT-PROOF');
    // §5.2 step 4 sender binding: the settlement-observed sender MUST be the payer's ACCOUNT
    // (accountOf(principal) — the signer itself for self-pay, the smart account when delegated),
    // never the Agent/signer and never tx.from.
    if (ctx.payerAccount.scheme !== 'evm-address') return fail('HSP-RCPT-PROOF');
    let payerAddr: Address;
    try {
      payerAddr = getAddress(decodeAbiParameters([{ type: 'address' }], ctx.payerAccount.id)[0]);
    } catch {
      return fail('HSP-RCPT-PROOF');
    }
    if (getAddress(o.from) !== payerAddr) return fail('HSP-RCPT-PROOF');

    return {
      ok: true,
      proofSatisfiedCapabilities: [],
      amountObservation: { kind: 'exact', value: o.value },
      recipientObservation: { kind: 'address', address: getAddress(o.to) },
      tokenObserved: { kind: 'evm-address', address: getAddress(o.token) },
      chainIdObserved: o.chainId,
      observationId: transferObservationId(o), // observation-based adapter (§5.2 step 7)
    };
  },
};

export interface BuildReceiptArgs {
  domain: DomainInput;
  mandateHash: Hex;
  observation: TransferObservation;
  adapterPrivateKey: Hex;
  adapterInstanceKey?: Hex;
  seq?: number;
  outcome?: OutcomeValue;
  settledAt: number;
}

/** Adapter Operator side: assemble + sign a Receipt (adapterSignature over receiptHash). */
export async function buildAndSignReceipt(args: BuildReceiptArgs): Promise<Receipt> {
  const core: ReceiptInput = {
    mandateHash: args.mandateHash,
    adapterId: EVM_TRANSFER_ADAPTER_ID,
    adapterInstanceKey: args.adapterInstanceKey ?? ZERO32,
    seq: args.seq ?? 0,
    outcome: args.outcome ?? Outcome.SETTLED,
    settledAt: args.settledAt,
    proofSchemaId: EVM_TRANSFER_PROOF_SCHEMA_ID,
    adapterProof: encodeTransferProof(args.observation),
  };
  const rHash = computeReceiptHash(args.domain, core);
  const adapterSignature = await privateKeyToAccount(args.adapterPrivateKey).sign({ hash: rHash });
  return { ...core, adapterSignature };
}
