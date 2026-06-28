/**
 * HSPSigner — normalizes three signer backends to the 65-byte r‖s‖v (v ∈ {27,28},
 * low-s) signature over the EIP-712 mandate digest that eip712-eoa.v1 requires:
 *
 *  - privateKey   : dev/demo — signs the digest directly (core signMandateHash)
 *  - viemAccount  : any viem LocalAccount (account.sign({ hash }))
 *  - eip1193      : browser/agent wallets — wallets cannot sign raw digests, so
 *                   we send eth_signTypedData_v4 with typed data built from the
 *                   SAME field arrays core hashes with (digest equality is
 *                   asserted before the wallet is asked to sign).
 *
 * The signing account is ALSO the settling account (wallet-settling adapter:
 * Transfer.from MUST equal body.signer), so walletClientFor() builds the
 * broadcast client from the same backend.
 */

import {
  createWalletClient,
  custom,
  defineChain,
  hashTypedData,
  http,
  type Account,
  type Address,
  type EIP1193Provider,
  type Hex,
  type WalletClient,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  mandateHash as computeMandateHash,
  grantHash as computeGrantHash,
  MANDATE_FIELDS,
  GRANT_FIELDS,
  NESTED_TYPES,
  type DomainInput,
  type Mandate,
  type DelegationGrantInput,
  type SignedDelegationGrant,
} from '@hsp/core';
import { signMandateHash } from '@hsp/core/profiles/signer/eip712-eoa';

export type HSPSigner =
  | { kind: 'privateKey'; privateKey: Hex }
  | { kind: 'viemAccount'; account: Account }
  | { kind: 'eip1193'; provider: EIP1193Provider; address: Address };

export function signerAddress(s: HSPSigner): Address {
  switch (s.kind) {
    case 'privateKey':
      return privateKeyToAccount(s.privateKey).address;
    case 'viemAccount':
      return s.account.address;
    case 'eip1193':
      return s.address;
  }
}

/** EIP-712 typed data whose digest equals core mandateHash(domain, body). */
// NONE sentinel for the optional Mandate refs — MUST match core bodyMessage
// (derivations.ts) so the SDK's typed-data digest equals core mandateHash().
const NONE32 = `0x${'00'.repeat(32)}` as Hex;

export function mandateTypedData(domain: DomainInput, body: Mandate) {
  return {
    domain: {
      name: domain.name,
      version: domain.version,
      chainId: Number(domain.chainId),
      verifyingContract: domain.verifyingContract as Address,
    },
    types: { Mandate: [...MANDATE_FIELDS], ...NESTED_TYPES },
    primaryType: 'Mandate' as const,
    // Default the three optional refs to NONE so the 11-field message is complete
    // for self-pay (grantRef/requirementRef/settlementBinding absent) — viem validates
    // every typed-data field, and this must mirror core's bodyMessage defaulting.
    message: {
      ...body,
      grantRef: body.grantRef ?? NONE32,
      requirementRef: body.requirementRef ?? NONE32,
      settlementBinding: body.settlementBinding ?? NONE32,
    } as unknown as Record<string, unknown>,
  };
}

/** Some wallets return v ∈ {0,1}; eip712-eoa.v1 requires v ∈ {27,28}. */
function normalizeV(sig: Hex): Hex {
  const hex = sig.slice(2);
  if (hex.length !== 130) return sig;
  const v = parseInt(hex.slice(128, 130), 16);
  if (v === 0 || v === 1) return `0x${hex.slice(0, 128)}${(v + 27).toString(16)}` as Hex;
  return sig;
}

export async function signMandateBody(
  signer: HSPSigner,
  domain: DomainInput,
  body: Mandate,
): Promise<{ mandateHash: Hex; signerProof: Hex }> {
  const mh = computeMandateHash(domain, body);
  switch (signer.kind) {
    case 'privateKey':
      return { mandateHash: mh, signerProof: await signMandateHash(signer.privateKey, mh) };
    case 'viemAccount': {
      if (!signer.account.sign) throw new Error('viemAccount must be a local account exposing sign({ hash })');
      return { mandateHash: mh, signerProof: await signer.account.sign({ hash: mh }) };
    }
    case 'eip1193': {
      const td = mandateTypedData(domain, body);
      const digest = hashTypedData(td as Parameters<typeof hashTypedData>[0]);
      if (digest.toLowerCase() !== mh.toLowerCase()) {
        throw new Error('typed-data digest does not reproduce core mandateHash — refusing to request a wallet signature');
      }
      const raw = (await signer.provider.request({
        method: 'eth_signTypedData_v4',
        params: [signer.address, JSON.stringify(td)],
      })) as Hex;
      return { mandateHash: mh, signerProof: normalizeV(raw) };
    }
  }
}

/** EIP-712 typed data whose digest equals core grantHash(domain, grant) — mirrors
 *  derivations.ts grantMessage so a wallet's eth_signTypedData_v4 reproduces the digest. */
export function grantTypedData(domain: DomainInput, grant: DelegationGrantInput) {
  return {
    domain: {
      name: domain.name,
      version: domain.version,
      chainId: Number(domain.chainId),
      verifyingContract: domain.verifyingContract as Address,
    },
    types: { DelegationGrant: [...GRANT_FIELDS], Signer: NESTED_TYPES.Signer },
    primaryType: 'DelegationGrant' as const,
    message: {
      principal: { profileId: grant.principal.profileId, payload: grant.principal.payload },
      agent: { profileId: grant.agent.profileId, payload: grant.agent.payload },
      onchainPermissionRef: grant.onchainPermissionRef,
      payerRequiredCaps: grant.payerRequiredCaps,
      payerAllowedCaps: grant.payerAllowedCaps,
      notBefore: BigInt(grant.notBefore),
      expiry: BigInt(grant.expiry),
      nonce: grant.nonce,
    } as unknown as Record<string, unknown>,
  };
}

/**
 * Sign a DelegationGrant as the PRINCIPAL (delegated payments). The principal is
 * typically an erc1271 smart account whose OWNER key signs `grantHash` — the
 * account's `isValidSignature` validates it on-chain at verify time. The signing
 * mechanic is identical to signing an execution, only over `grantHash`.
 */
export async function signGrant(
  principalSigner: HSPSigner,
  domain: DomainInput,
  grant: DelegationGrantInput,
): Promise<SignedDelegationGrant> {
  const gh = computeGrantHash(domain, grant);
  switch (principalSigner.kind) {
    case 'privateKey':
      return { body: grant, principalProof: await signMandateHash(principalSigner.privateKey, gh) };
    case 'viemAccount': {
      if (!principalSigner.account.sign) throw new Error('viemAccount must be a local account exposing sign({ hash })');
      return { body: grant, principalProof: await principalSigner.account.sign({ hash: gh }) };
    }
    case 'eip1193': {
      const td = grantTypedData(domain, grant);
      const digest = hashTypedData(td as Parameters<typeof hashTypedData>[0]);
      if (digest.toLowerCase() !== gh.toLowerCase()) {
        throw new Error('typed-data digest does not reproduce core grantHash — refusing to request a wallet signature');
      }
      const raw = (await principalSigner.provider.request({
        method: 'eth_signTypedData_v4',
        params: [principalSigner.address, JSON.stringify(td, (_k, v) => (typeof v === 'bigint' ? v.toString() : v))],
      })) as Hex;
      return { body: grant, principalProof: normalizeV(raw) };
    }
  }
}

/** EIP-3009 TransferWithAuthorization typed data (FiatTokenV2 / USDC). */
export interface Eip3009Authorization {
  from: Address;
  to: Address;
  value: bigint;
  validAfter: number;
  validBefore: number;
  nonce: Hex; // bytes32, single-use
}

export function eip3009TypedData(
  token: { name: string; version: string; chainId: number; address: Address },
  auth: Eip3009Authorization,
) {
  return {
    domain: { name: token.name, version: token.version, chainId: token.chainId, verifyingContract: token.address },
    types: {
      TransferWithAuthorization: [
        { name: 'from', type: 'address' },
        { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' },
        { name: 'nonce', type: 'bytes32' },
      ],
    },
    primaryType: 'TransferWithAuthorization' as const,
    message: {
      from: auth.from,
      to: auth.to,
      value: auth.value,
      validAfter: BigInt(auth.validAfter),
      validBefore: BigInt(auth.validBefore),
      nonce: auth.nonce,
    },
  };
}

/** Sign an EIP-3009 transfer authorization (the x402 client-pull settlement). */
export async function signEip3009Authorization(
  signer: HSPSigner,
  token: { name: string; version: string; chainId: number; address: Address },
  auth: Eip3009Authorization,
): Promise<Hex> {
  const td = eip3009TypedData(token, auth);
  switch (signer.kind) {
    case 'privateKey':
      return privateKeyToAccount(signer.privateKey).signTypedData(td as Parameters<Account['signTypedData'] & object>[0] as never);
    case 'viemAccount': {
      if (!signer.account.signTypedData) throw new Error('viemAccount must expose signTypedData');
      return signer.account.signTypedData(td as never);
    }
    case 'eip1193': {
      const raw = (await signer.provider.request({
        method: 'eth_signTypedData_v4',
        params: [signer.address, JSON.stringify(td, (_k, v) => (typeof v === 'bigint' ? v.toString() : v))],
      })) as Hex;
      return raw;
    }
  }
}

/** Broadcast client from the SAME backend (signer == settling party). */
export function walletClientFor(signer: HSPSigner, rpcUrl: string, chainId: number): WalletClient {
  const chain = defineChain({
    id: chainId,
    name: `hsp-${chainId}`,
    nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
  switch (signer.kind) {
    case 'privateKey':
      return createWalletClient({ account: privateKeyToAccount(signer.privateKey), chain, transport: http(rpcUrl) });
    case 'viemAccount':
      return createWalletClient({ account: signer.account, chain, transport: http(rpcUrl) });
    case 'eip1193':
      return createWalletClient({ account: signer.address, chain, transport: custom(signer.provider) });
  }
}
