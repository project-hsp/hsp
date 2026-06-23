/**
 * x402 `exact` scheme on EVM — EIP-3009 `TransferWithAuthorization`.
 *
 * The client signs the authorization under the TOKEN's EIP-712 domain (name/version
 * from `paymentRequirements.extra`, chainId, verifyingContract = the token). The
 * facilitator verifies that signature + the requirement fields, then settles by
 * submitting `transferWithAuthorization` to the token. Mirrors x402's exact-EVM
 * verify steps (signature, amount, recipient, asset, network, time window).
 */

import { getAddress, recoverTypedDataAddress, type Address, type Hex } from 'viem';
import type { Eip3009Authorization, ExactEvmPayload, PaymentPayload, PaymentRequirements, VerifyResponse } from './types.js';
import { parseCaip2 } from './caip2.js';

/** EIP-712 types for EIP-3009 TransferWithAuthorization. */
export const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const;

export interface TokenDomain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: Address;
}

/** The token's EIP-712 domain — name/version come from `paymentRequirements.extra`. */
export function tokenDomainFrom(req: PaymentRequirements): TokenDomain {
  const name = req.extra?.['name'];
  const version = req.extra?.['version'];
  if (typeof name !== 'string' || typeof version !== 'string') {
    throw new Error('paymentRequirements.extra must carry the token EIP-712 {name, version}');
  }
  return { name, version, chainId: parseCaip2(req.network), verifyingContract: getAddress(req.asset) };
}

function asExactEvmPayload(p: Record<string, unknown>): ExactEvmPayload | undefined {
  const sig = p['signature'];
  const auth = p['authorization'] as Record<string, unknown> | undefined;
  if (typeof sig !== 'string' || !auth) return undefined;
  const need = ['from', 'to', 'value', 'validAfter', 'validBefore', 'nonce'];
  if (!need.every((k) => auth[k] !== undefined)) return undefined;
  return { signature: sig, authorization: auth as unknown as Eip3009Authorization };
}

function fail(reason: string, message?: string, payer?: string): VerifyResponse {
  return { isValid: false, invalidReason: reason, ...(message ? { invalidMessage: message } : {}), ...(payer ? { payer } : {}) };
}

/**
 * Verify an exact-EVM payment against its requirements (no chain I/O — signature + field
 * checks; balance/simulation are the settle step's concern). `expectedChainId` is the
 * facilitator's chain. `now` is unix seconds.
 */
export async function verifyExactEvm(args: {
  paymentPayload: PaymentPayload;
  paymentRequirements: PaymentRequirements;
  expectedChainId: number;
  now: number;
}): Promise<VerifyResponse> {
  const { paymentRequirements: req, paymentPayload: pp, expectedChainId, now } = args;
  if (req.scheme !== 'exact') return fail('unsupported_scheme', `expected "exact", got "${req.scheme}"`);
  const ev = asExactEvmPayload(pp.payload);
  if (!ev) return fail('invalid_payload', 'payload is not a well-formed exact-EVM authorization');
  const a = ev.authorization;

  let chainId: number;
  try {
    chainId = parseCaip2(req.network);
  } catch (e) {
    return fail('unsupported_network', (e as Error).message);
  }
  if (chainId !== expectedChainId) return fail('network_mismatch', `requirements network ${req.network} != facilitator chain ${expectedChainId}`);

  // signature → payer
  let payer: Address;
  try {
    payer = await recoverTypedDataAddress({
      domain: tokenDomainFrom(req),
      types: TRANSFER_WITH_AUTHORIZATION_TYPES,
      primaryType: 'TransferWithAuthorization',
      message: {
        from: getAddress(a.from),
        to: getAddress(a.to),
        value: BigInt(a.value),
        validAfter: BigInt(a.validAfter),
        validBefore: BigInt(a.validBefore),
        nonce: a.nonce as Hex,
      },
      signature: ev.signature as Hex,
    });
  } catch (e) {
    return fail('invalid_signature', (e as Error).message);
  }
  if (getAddress(payer) !== getAddress(a.from)) return fail('invalid_signature', 'signature does not recover to authorization.from');

  // field checks (exact scheme = exact amount)
  if (BigInt(a.value) !== BigInt(req.amount)) return fail('amount_mismatch', `value ${a.value} != required ${req.amount}`, payer);
  if (getAddress(a.to) !== getAddress(req.payTo)) return fail('recipient_mismatch', `to ${a.to} != payTo ${req.payTo}`, payer);

  // time window
  if (now < Number(a.validAfter)) return fail('not_yet_valid', `now ${now} < validAfter ${a.validAfter}`, payer);
  if (now >= Number(a.validBefore)) return fail('expired', `now ${now} >= validBefore ${a.validBefore}`, payer);

  return { isValid: true, payer };
}

/** Split a 65-byte EIP-712 signature into {v, r, s} for the contract call (normalizes v∈{0,1}→{27,28}). */
export function splitSignature(signature: Hex): { v: number; r: Hex; s: Hex } {
  const sig = signature.slice(2);
  if (sig.length !== 130) throw new Error('signature must be 65 bytes');
  let v = parseInt(sig.slice(128, 130), 16);
  if (v === 0 || v === 1) v += 27;
  return { v, r: `0x${sig.slice(0, 64)}`, s: `0x${sig.slice(64, 128)}` };
}
