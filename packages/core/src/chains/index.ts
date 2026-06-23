/**
 * Chain registry — per-chain deployment DATA for the HSP ecosystem tools.
 *
 * Pure data + a resolver; no env reads here (core stays runtime-agnostic — the
 * Coordinator reads `rpcUrlEnv` from its own environment and passes overrides).
 * `stablecoin` doubles as the deployment's token allowlist for the public
 * evm-transfer path: the MVP rejects tokens other than the chain's pinned entry.
 *
 * Verified facts (2026-06-10):
 *  - HashKey Chain mainnet chainId 177, public RPC https://mainnet.hsk.xyz
 *    (chainlist.org/chain/177, docs.hsk.xyz).
 *  - Ethereum-mainnet USDC 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 6 decimals
 *    (developers.circle.com/stablecoins/usdc-contract-addresses).
 *  - HashKey Chain mainnet bridged USDC (user-provided 2026-06-10, RPC-verified
 *    on chain 177): 0x054ed45810DbBAb8B27668922D110669c9D88D0a — symbol()
 *    "USDC.e", decimals() 6.
 *  - HashKey Chain TESTNET chainId 133 (chainlist.org/chain/133), public RPC
 *    https://testnet.hsk.xyz; USDC (user-provided 2026-06-11, RPC-verified on
 *    chain 133): 0x8FE3cB719Ee4410E236Cd6b72ab1fCDC06eF53c6 — symbol() "USDC",
 *    decimals() 6.
 */

import { getAddress, type Address, type Hex } from 'viem';
import type { DomainInput } from '../core/index.js';

export type ChainName = 'ethereum' | 'hashkey' | 'hashkey-testnet' | 'anvil-dev';

export interface StablecoinConfig {
  address: Address;
  symbol: string;
  decimals: number;
}

/** Resolved, ready-to-use per-chain runtime config. */
export interface ChainConfig {
  name: ChainName;
  chainId: number;
  rpcUrl: string;
  stablecoin: StablecoinConfig;
  /** Confirmations the observer waits before treating a tx as observable. */
  confirmations: number;
  /** EIP-712 domain pin — a deployment constant, not necessarily a deployed contract. */
  verifyingContract: Address;
  adapterInstanceKey: Hex;
}

export const ZERO32: Hex = `0x${'00'.repeat(32)}` as Hex;

/** Domain-separation pin of this reference deployment (all chains). */
export const HSP_VERIFYING_CONTRACT: Address = getAddress('0x0000000000000000000000000000000000000001');

export interface ChainDefaults {
  name: ChainName;
  chainId: number;
  /** Conventional env var the Coordinator reads for the RPC endpoint. */
  rpcUrlEnv: string;
  /** Public default endpoint, when one exists. */
  defaultRpcUrl?: string;
  /** Absent → must be injected via resolveChain overrides (fail closed). */
  stablecoin?: StablecoinConfig;
  confirmations: number;
  verifyingContract: Address;
  adapterInstanceKey: Hex;
}

export const CHAIN_DEFAULTS: Record<ChainName, ChainDefaults> = {
  ethereum: {
    name: 'ethereum',
    chainId: 1,
    rpcUrlEnv: 'HSP_RPC_ETHEREUM',
    stablecoin: {
      address: getAddress('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'),
      symbol: 'USDC',
      decimals: 6,
    },
    confirmations: 2,
    verifyingContract: HSP_VERIFYING_CONTRACT,
    adapterInstanceKey: ZERO32,
  },
  hashkey: {
    name: 'hashkey',
    chainId: 177,
    rpcUrlEnv: 'HSP_RPC_HASHKEY',
    defaultRpcUrl: 'https://mainnet.hsk.xyz',
    stablecoin: {
      address: getAddress('0x054ed45810DbBAb8B27668922D110669c9D88D0a'),
      symbol: 'USDC.e',
      decimals: 6,
    },
    confirmations: 5,
    verifyingContract: HSP_VERIFYING_CONTRACT,
    adapterInstanceKey: ZERO32,
  },
  'hashkey-testnet': {
    name: 'hashkey-testnet',
    chainId: 133,
    rpcUrlEnv: 'HSP_RPC_HASHKEY_TESTNET',
    defaultRpcUrl: 'https://testnet.hsk.xyz',
    stablecoin: {
      address: getAddress('0x8FE3cB719Ee4410E236Cd6b72ab1fCDC06eF53c6'),
      symbol: 'USDC',
      decimals: 6,
    },
    confirmations: 2,
    verifyingContract: HSP_VERIFYING_CONTRACT,
    adapterInstanceKey: ZERO32,
  },
  'anvil-dev': {
    name: 'anvil-dev',
    chainId: 31337,
    rpcUrlEnv: 'HSP_RPC_ANVIL',
    defaultRpcUrl: 'http://127.0.0.1:8545',
    // stablecoin per-run: pass the freshly deployed MockERC20 as an override.
    confirmations: 0,
    verifyingContract: HSP_VERIFYING_CONTRACT,
    adapterInstanceKey: ZERO32,
  },
};

export interface ChainOverrides {
  rpcUrl?: string;
  stablecoin?: StablecoinConfig;
  confirmations?: number;
}

/** Merge defaults + overrides into a runtime ChainConfig; fail closed on gaps. */
export function resolveChain(name: ChainName, overrides: ChainOverrides = {}): ChainConfig {
  const d = CHAIN_DEFAULTS[name];
  const rpcUrl = overrides.rpcUrl ?? d.defaultRpcUrl;
  if (!rpcUrl) {
    throw new Error(`chain '${name}': no rpcUrl — pass overrides.rpcUrl (Coordinator: read ${d.rpcUrlEnv})`);
  }
  const stablecoin = overrides.stablecoin ?? d.stablecoin;
  if (!stablecoin) {
    throw new Error(
      `chain '${name}': no verified stablecoin pinned — inject overrides.stablecoin ` +
        `(hashkey: verify the official bridged-USDC address first; anvil-dev: pass the deployed MockERC20)`,
    );
  }
  return {
    name: d.name,
    chainId: d.chainId,
    rpcUrl,
    stablecoin,
    confirmations: overrides.confirmations ?? d.confirmations,
    verifyingContract: d.verifyingContract,
    adapterInstanceKey: d.adapterInstanceKey,
  };
}

/** "0xaddr:SYMBOL:decimals" → StablecoinConfig (env-injection / CLI format). */
export function parseStablecoin(spec: string): StablecoinConfig {
  const [address, symbol, decimals] = spec.split(':');
  if (!address || !symbol || !decimals || Number.isNaN(Number(decimals))) {
    throw new Error(`bad stablecoin spec '${spec}' — expected address:symbol:decimals`);
  }
  return { address: getAddress(address), symbol, decimals: Number(decimals) };
}

/** The EIP-712 domain this deployment signs/verifies under (§2.1). */
export function chainDomain(c: Pick<ChainConfig, 'chainId' | 'verifyingContract'>): DomainInput {
  return { name: 'HSP', version: '1', chainId: c.chainId, verifyingContract: c.verifyingContract };
}
