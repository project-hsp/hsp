/**
 * MCP server env config. The agent key (HSP_AGENT_PRIVATE_KEY) is DEMO /
 * small-amount scoped: cap it with HSP_MAX_AMOUNT_BASE_UNITS +
 * HSP_DAILY_CAP_BASE_UNITS (+ optional HSP_RECIPIENT_ALLOWLIST). A production
 * deployment swaps in an EIP-1193 / custody signer instead of a raw key.
 */

import type { Address, Hex } from 'viem';
import { CHAIN_DEFAULTS, resolveChain, type ChainConfig, type ChainName } from '@hsp/core/chains/index';
import { parseStablecoin } from '@hsp/core/chains/index';
import { HSPClient } from '@hsp/sdk';
import { SpendGuard } from './guard.js';
import type { McpDeps } from './server.js';

export function depsFromEnv(env: NodeJS.ProcessEnv = process.env): McpDeps {
  const agentKey = env.HSP_AGENT_PRIVATE_KEY as Hex | undefined;
  if (!agentKey) throw new Error('HSP_AGENT_PRIVATE_KEY is required (demo/small-amount key; cap it via HSP_MAX_AMOUNT_BASE_UNITS)');
  const coordinatorUrl = env.HSP_COORDINATOR_URL ?? 'http://127.0.0.1:8787';
  const chainName = (env.HSP_CHAIN ?? 'anvil-dev') as ChainName;
  if (!(chainName in CHAIN_DEFAULTS)) throw new Error(`unknown chain '${chainName}'`);
  const stableSpec = env[`HSP_STABLECOIN_${chainName.toUpperCase().replace(/-/g, '_')}`];
  const overrides: Parameters<typeof resolveChain>[1] = {};
  const rpc = env[CHAIN_DEFAULTS[chainName].rpcUrlEnv];
  if (rpc) overrides.rpcUrl = rpc;
  if (stableSpec) overrides.stablecoin = parseStablecoin(stableSpec);
  const chain: ChainConfig = resolveChain(chainName, overrides);

  const hspOpts: ConstructorParameters<typeof HSPClient>[0] = {
    coordinatorUrl,
    signer: { kind: 'privateKey', privateKey: agentKey },
    chain,
  };
  if (env.HSP_API_KEY) hspOpts.apiKey = env.HSP_API_KEY;
  if (env.HSP_ISSUER_URL) hspOpts.issuerUrl = env.HSP_ISSUER_URL;

  const guard = new SpendGuard(
    env.HSP_MAX_AMOUNT_BASE_UNITS ? BigInt(env.HSP_MAX_AMOUNT_BASE_UNITS) : undefined,
    env.HSP_DAILY_CAP_BASE_UNITS ? BigInt(env.HSP_DAILY_CAP_BASE_UNITS) : undefined,
    env.HSP_RECIPIENT_ALLOWLIST
      ? new Set(env.HSP_RECIPIENT_ALLOWLIST.split(',').map((a) => a.trim().toLowerCase()).filter(Boolean))
      : undefined,
  );

  const deps: McpDeps = { hsp: new HSPClient(hspOpts), chain, coordinatorUrl, guard };
  if (env.HSP_PINNED_ADAPTER_ADDRESS) deps.pinnedAdapterAddress = env.HSP_PINNED_ADAPTER_ADDRESS as Address;
  return deps;
}
