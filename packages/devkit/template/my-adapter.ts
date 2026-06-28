/**
 * ── ADAPTER TEMPLATE ─────────────────────────────────────────────────────────
 * Copy this file, rename everything `my-adapter`, and make it settle YOUR way
 * (another chain, Lightning, a points system, …). It compiles and passes
 * conformance as-is (it's a minimal ERC-20-transfer-with-memo adapter), so you
 * always start from green.
 *
 * THE FOUR DUTIES of an AdapterProofSchema.verify() — keep every one:
 *  [D1] DECODE + VALIDATE the proof bytes; any malformed input → ok:false.
 *  [D2] BIND THE SETTLING PARTY: if your settlement exposes who paid, it MUST
 *       equal the mandate signer (ctx.signerSubject) — else anyone's settlement
 *       could satisfy anyone's mandate.
 *  [D3] SURFACE TRUE OBSERVATIONS: amount/recipient/token/chain exactly as your
 *       settlement system shows them — the verifier compares them to the
 *       mandate (§5.2 step 4); never echo the mandate fields back.
 *  [D4] EMIT observationId for observation-based settlement (a hash of your
 *       settlement-native identity, e.g. (chainId, token, txHash)) so one
 *       settlement can never satisfy two mandates. Omit ONLY if your artifact
 *       is cryptographically bound to executionHash (x402-style).
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
  type OutcomeValue,
  type Receipt,
  type ReceiptInput,
  type DomainInput,
} from '@hsp/core';
import type { AdapterProofSchema, VerifyContext, VerifyOutcome } from '@hsp/core/verifier/contracts';

// TODO: rename — these ids ARE your adapter's identity (immutable once registered).
export const MY_ADAPTER_ID: Hex = keccak256(stringToBytes('adapter:my-adapter'));
export const MY_PROOF_SCHEMA_ID: Hex = keccak256(stringToBytes('my-adapter.proof.v1'));
const ZERO32: Hex = `0x${'00'.repeat(32)}`;

// TODO: your settlement observation — everything verify() needs, nothing more.
export interface MyObservation {
  from: Address;
  to: Address;
  token: Address;
  value: bigint;
  chainId: number;
  txHash: Hex;
  memo: string; // ← example extra field; replace with your settlement's data
}

const PROOF_ABI = [
  { type: 'address' }, // from
  { type: 'address' }, // to
  { type: 'address' }, // token
  { type: 'uint256' }, // value
  { type: 'uint256' }, // chainId
  { type: 'bytes32' }, // txHash
  { type: 'string' }, // memo
] as const;

export function encodeMyProof(o: MyObservation): Hex {
  return encodeAbiParameters(PROOF_ABI, [o.from, o.to, o.token, o.value, BigInt(o.chainId), o.txHash, o.memo]);
}

function decodeMyProof(bytes: Hex): MyObservation {
  const [from, to, token, value, chainId, txHash, memo] = decodeAbiParameters(PROOF_ABI, bytes);
  return { from, to, token, value, chainId: Number(chainId), txHash, memo };
}

function fail(errorCode: string): VerifyOutcome {
  return { ok: false, errorCode, proofSatisfiedCapabilities: [], amountObservation: { kind: 'hidden' }, recipientObservation: { kind: 'shielded' } };
}

export const myAdapterSchema: AdapterProofSchema = {
  async verify(ctx: VerifyContext): Promise<VerifyOutcome> {
    // [D1] decode + validate
    let o: MyObservation;
    try {
      o = decodeMyProof(ctx.proofBytes);
    } catch {
      return fail('HSP-RCPT-PROOF');
    }

    // [D2] settling party == mandate signer
    if (ctx.signerSubject.scheme !== 'evm-address') return fail('HSP-RCPT-PROOF');
    let signerAddr: Address;
    try {
      signerAddr = getAddress(decodeAbiParameters([{ type: 'address' }], ctx.signerSubject.id)[0]);
    } catch {
      return fail('HSP-RCPT-PROOF');
    }
    if (getAddress(o.from) !== signerAddr) return fail('HSP-RCPT-PROOF');

    // TODO: any adapter-specific validity rules go here (e.g. memo format).

    return {
      ok: true,
      // TODO: structural caps your proof witnesses (⊆ your registered allowedCapabilities)
      proofSatisfiedCapabilities: [],
      // [D3] true observations from YOUR settlement system
      amountObservation: { kind: 'exact', value: o.value },
      recipientObservation: { kind: 'address', address: getAddress(o.to) },
      tokenObserved: { kind: 'evm-address', address: getAddress(o.token) },
      chainIdObserved: o.chainId,
      // [D4] settlement-native identity — one settlement, at most one mandate
      observationId: keccak256(
        encodeAbiParameters([{ type: 'uint256' }, { type: 'address' }, { type: 'bytes32' }], [BigInt(o.chainId), getAddress(o.token), o.txHash]),
      ),
    };
  },
};

export interface BuildMyReceiptArgs {
  domain: DomainInput;
  executionHash: Hex;
  observation: MyObservation;
  adapterPrivateKey: Hex;
  adapterInstanceKey?: Hex;
  seq?: number;
  outcome?: OutcomeValue;
  settledAt: number;
}

/** Operator side: assemble + sign the Receipt over receiptHash (§2.4.2). */
export async function buildAndSignMyReceipt(args: BuildMyReceiptArgs): Promise<Receipt> {
  const core: ReceiptInput = {
    executionHash: args.executionHash,
    adapterId: MY_ADAPTER_ID,
    adapterInstanceKey: args.adapterInstanceKey ?? ZERO32,
    seq: args.seq ?? 0,
    outcome: args.outcome ?? Outcome.SETTLED,
    settledAt: args.settledAt,
    proofSchemaId: MY_PROOF_SCHEMA_ID,
    adapterProof: encodeMyProof(args.observation),
  };
  const rHash = computeReceiptHash(args.domain, core);
  const adapterSignature = await privateKeyToAccount(args.adapterPrivateKey).sign({ hash: rHash });
  return { ...core, adapterSignature };
}
