/**
 * MCP server env config — PURE / key-less. No agent key, no spend guard: this MCP
 * only reasons over HSP wire objects (it moves no money). It needs the chain (for
 * verify / build_* / hashing), and OPTIONALLY the pinned adapter signing address +
 * x402 merchant domains + a trusted compliance issuer (to verify x402 / compliant
 * receipts). To actually pay, use @hsp/sdk instead.
 */

import type { Address } from 'viem';
import { CHAIN_DEFAULTS, resolveChain, parseStablecoin, type ChainConfig, type ChainName } from '@hsp/core/chains/index';
import { resolveComplianceCaps, type ComplianceTag } from '@hsp/sdk';
import type { McpDeps } from './server.js';

export function depsFromEnv(env: NodeJS.ProcessEnv = process.env): McpDeps {
  const chainName = (env.HSP_CHAIN ?? 'anvil-dev') as ChainName;
  if (!(chainName in CHAIN_DEFAULTS)) throw new Error(`unknown chain '${chainName}'`);
  const stableSpec = env[`HSP_STABLECOIN_${chainName.toUpperCase().replace(/-/g, '_')}`];
  const overrides: Parameters<typeof resolveChain>[1] = {};
  const rpc = env[CHAIN_DEFAULTS[chainName].rpcUrlEnv];
  if (rpc) overrides.rpcUrl = rpc;
  if (stableSpec) overrides.stablecoin = parseStablecoin(stableSpec);
  const chain: ChainConfig = resolveChain(chainName, overrides);

  const deps: McpDeps = { chain };
  // for hsp_prepare_payment / hsp_submit_payment — a Coordinator URL + write key (NOT a signing key)
  if (env.HSP_COORDINATOR_URL) deps.coordinatorUrl = env.HSP_COORDINATOR_URL;
  if (env.HSP_API_KEY) deps.apiKey = env.HSP_API_KEY;
  if (env.HSP_PINNED_ADAPTER_ADDRESS) deps.pinnedAdapterAddress = env.HSP_PINNED_ADAPTER_ADDRESS as Address;
  if (env.HSP_X402_DOMAINS) deps.x402Domains = env.HSP_X402_DOMAINS.split(',').map((d) => d.trim()).filter(Boolean);
  if (env.HSP_COMPLIANCE_ISSUER) {
    const issuerAddress = env.HSP_COMPLIANCE_ISSUER as Address;
    deps.compliance = {
      trustedIssuers: [
        { family: 'attests:kyc:v1', issuerAddress },
        { family: 'attests:sanctions:v1', issuerAddress },
      ],
      policyRequiredCaps: resolveComplianceCaps(['kyc', 'sanctions'] as ComplianceTag[]),
    };
  }
  return deps;
}
