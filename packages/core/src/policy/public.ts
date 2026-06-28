/**
 * Public-path VerificationPolicy builder — the §7.2.1 dispatch tables for a
 * deployment that admits exactly the eip712-eoa.v1 signer profile and the
 * evm-transfer adapter (trivial-public MVP; capability/issuer tables empty).
 *
 * Shared by the Coordinator (its own verifier) and merchant-side independent
 * verification (@hsp/sdk HSPVerifier.verify with a PINNED adapter key): both sides
 * build the same policy shape from a pinned (chain, adapterAddress) pair, so a
 * merchant never has to trust the Coordinator's status API.
 *
 * Ported from the reference wiring in tests/runners/ts/src/e2e/anvil-public.ts.
 */

import { keccak256, stringToBytes, type Address, type Hex } from 'viem';
import { eip712EoaSigner } from '../profiles/signer/eip712-eoa.js';
import { adapterKey, schemaKey, type ReorgPolicy, type VerificationPolicy } from '../verifier/contracts.js';
import { evmTransferSchema, EVM_TRANSFER_ADAPTER_ID, EVM_TRANSFER_PROOF_SCHEMA_ID } from '../adapter/mock-evm-transfer.js';
import type { ChainConfig } from '../chains/index.js';

export const EVM_TRANSFER_REORG_POLICY: ReorgPolicy = {
  allowsAttempted: true,
  chainObservation: 'required',
  disputeWindowMs: 30_000,
};

export function buildPublicPolicy(
  chain: ChainConfig,
  adapterAddress: Address,
  evaluationTime: number,
): VerificationPolicy {
  return {
    verifyingContract: chain.verifyingContract,
    acceptedVerifyingContracts: new Set([chain.verifyingContract.toLowerCase()]),
    signerProfiles: new Map([[eip712EoaSigner.profileIdHash, { profile: eip712EoaSigner }]]),
    adapterTrust: new Map([
      [
        adapterKey(EVM_TRANSFER_ADAPTER_ID, chain.adapterInstanceKey),
        { address: adapterAddress, reorgPolicy: EVM_TRANSFER_REORG_POLICY },
      ],
    ]),
    proofSchemas: new Map([
      [
        schemaKey(EVM_TRANSFER_ADAPTER_ID, EVM_TRANSFER_PROOF_SCHEMA_ID),
        { schema: evmTransferSchema, allowedCapabilities: [], admission: 'accept-new' as const, trustRoots: {} },
      ],
    ]),
    capabilityRegistry: new Map(),
    issuerTrustAnchors: new Map(),
    contextBindingScope: new Map(),
    evaluationTime,
  };
}

// =============================================================================
// §7.7 PayeeRequirement advertisement (format normative — HSP.md §7.7)
// =============================================================================

/** Deterministic JSON (recursively sorted object keys) for content hashing. */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const rec = value as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(rec[k])}`).join(',')}}`;
}

export interface PayeeRequirement {
  hspVersion: string;
  policyHash: Hex; // §7.5 content hash — cache/version key ONLY, never a trust anchor
  expiresAt: number; // soft expiry; payer should re-fetch past this
  domain: { verifyingContract: Address; chainIds: number[] }; // chainIds = routing HINT, not an admission rule
  signerProfiles: string[];
  policyRequiredCapabilities: string[];
  offeredCapabilities: string[];
  issuers: Record<string, { scheme: string; identifier: string; acceptedSchemaIds: Hex[] }[]>;
  contextBindingScope: Record<string, 'mandate' | 'receipt'>;
  adapters: {
    adapterId: string;
    adapterInstanceKey: Hex;
    proofSchemaId: Hex;
    schemaAdmission: 'accept-new' | 'accept-historical' | 'accept-dispute-only';
    allowedCapabilities: string[];
    reorgPolicy: ReorgPolicy;
  }[];
}

/**
 * A deployment's §7.7 projection for one chain. `policyHash` covers everything
 * except itself and `expiresAt` (volatile serve-time fields). The trivial-public
 * path passes only `{ expiresAt }`; compliance deployments additionally pass
 * `policyRequiredCapabilities` / `offeredCapabilities` / `issuers` so payers
 * learn which caps to declare and which issuers are accepted.
 */
export function buildPublicRequirements(
  chain: ChainConfig,
  opts: {
    expiresAt: number;
    policyRequiredCapabilities?: string[];
    offeredCapabilities?: string[];
    issuers?: PayeeRequirement['issuers'];
    /** Additional adapters the deployment admits (§7.7 completeness). */
    extraAdapters?: PayeeRequirement['adapters'];
  },
): PayeeRequirement {
  const core = {
    hspVersion: '1',
    domain: { verifyingContract: chain.verifyingContract, chainIds: [chain.chainId] },
    signerProfiles: ['eip712-eoa.v1'],
    policyRequiredCapabilities: opts.policyRequiredCapabilities ?? [],
    offeredCapabilities: opts.offeredCapabilities ?? [],
    issuers: opts.issuers ?? {},
    contextBindingScope: {} as PayeeRequirement['contextBindingScope'],
    adapters: [
      {
        adapterId: 'adapter:evm-transfer',
        adapterInstanceKey: chain.adapterInstanceKey,
        proofSchemaId: EVM_TRANSFER_PROOF_SCHEMA_ID,
        schemaAdmission: 'accept-new' as const,
        allowedCapabilities: [] as string[],
        reorgPolicy: EVM_TRANSFER_REORG_POLICY,
      },
      ...(opts.extraAdapters ?? []),
    ],
  };
  const policyHash = keccak256(stringToBytes(stableStringify(core)));
  return { ...core, policyHash, expiresAt: opts.expiresAt };
}
