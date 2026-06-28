/**
 * Cross-check a deployment's ADVERTISED config against what you actually intend to
 * trust — before you pin it. A Coordinator's /requirements + /chains are discovery,
 * NOT a trust root: a verifier owns its own policy. This turns "fetch and blindly
 * adopt the advertised values" into "fetch and verify them against my own policy,
 * refuse on divergence". Call it once at setup, then build your PinnedTrustConfig
 * from values you have vetted.
 */

import { getAddress, type Address, type Hex } from 'viem';
import { evmIssuerKeyId } from '@hsp/core/attestation/issuer';
import type { ComplianceFamily } from '@hsp/core/policy/compliance';
import { fetchRequirements, type PayeeRequirement } from './requirements.js';

export interface ExpectedTrust {
  /** A §7.7 policyHash you have vetted — the live policyHash MUST equal it (a content
   *  hash of the WHOLE policy: domain, issuers, adapters, required caps). */
  policyHash?: Hex;
  /** The adapter-operator signing address you expect (published at /chains). */
  adapterAddress?: Address;
  /** The stablecoin token address you expect (published at /chains). */
  stablecoin?: Address;
  /** Issuers you expect to be advertised, per family — each MUST appear in /requirements. */
  issuers?: { family: ComplianceFamily; address: Address }[];
}

export class DeploymentMismatchError extends Error {
  constructor(readonly mismatches: string[]) {
    super('HSP deployment config does not match what you expected:\n  - ' + mismatches.join('\n  - '));
    this.name = 'DeploymentMismatchError';
  }
}

interface ChainsEntry {
  name: string;
  stablecoin: { address: Address };
  adapterAddress: Address;
}

/**
 * Fetch a deployment's advertised config (/requirements + /chains) and ASSERT it matches
 * `expected`. Throws DeploymentMismatchError listing every divergence; on success returns
 * the advertised PayeeRequirement (now vetted). Pin from values you trust, not from
 * whatever the deployment happens to advertise.
 */
export async function assertDeployment(
  coordinatorUrl: string,
  chain: string,
  expected: ExpectedTrust,
): Promise<PayeeRequirement> {
  const base = coordinatorUrl.replace(/\/$/, '');
  const req = await fetchRequirements(coordinatorUrl, chain);
  const mismatches: string[] = [];

  if (expected.policyHash && (req.policyHash ?? '').toLowerCase() !== expected.policyHash.toLowerCase()) {
    mismatches.push(`policyHash ${req.policyHash} != expected ${expected.policyHash}`);
  }

  if (expected.adapterAddress || expected.stablecoin) {
    const chains = (await (await fetch(`${base}/chains`)).json()) as ChainsEntry[];
    const c = chains.find((x) => x.name === chain);
    if (!c) {
      mismatches.push(`chain '${chain}' is not advertised by /chains`);
    } else {
      if (expected.adapterAddress && getAddress(c.adapterAddress) !== getAddress(expected.adapterAddress)) {
        mismatches.push(`adapterAddress ${c.adapterAddress} != expected ${expected.adapterAddress}`);
      }
      if (expected.stablecoin && getAddress(c.stablecoin.address) !== getAddress(expected.stablecoin)) {
        mismatches.push(`stablecoin ${c.stablecoin.address} != expected ${expected.stablecoin}`);
      }
    }
  }

  for (const exp of expected.issuers ?? []) {
    const keyId = evmIssuerKeyId(getAddress(exp.address)).toLowerCase();
    const advertised = (req.issuers?.[exp.family] ?? []).map((i) => i.identifier.toLowerCase());
    if (!advertised.includes(keyId)) {
      mismatches.push(`issuer ${exp.address} (${exp.family}) is not in the advertised trusted set`);
    }
  }

  if (mismatches.length) throw new DeploymentMismatchError(mismatches);
  return req;
}
