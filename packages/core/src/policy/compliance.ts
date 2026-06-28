/**
 * Compliance policy layer (scenario 2: KYC / AML) — shared by the Coordinator's
 * verifier and merchant-side independent verification, so both build the SAME
 * policy and §7.7 projection from the same (trusted-issuer, required-cap) config.
 *
 * The protocol mechanism is already complete (§3.2 attests:* path, CR2 attestation
 * walk, §3.3.3 monotone narrowing, §5.1 step 3b policy-required floor); this module
 * only wires it: a fixed payer-roled cap vocabulary, the issuer trust-anchor table,
 * and the §7.7 issuers/policyRequiredCapabilities fields. Reference: e2e/compliance.ts.
 */

import { type Address, type Hex } from 'viem';
import { makeCap, buildCapabilityRegistry, familyCapId, Roles, type ParsedCapability } from '../core/capabilities.js';
import { evmIssuerKeyId } from '../attestation/issuer.js';
import { KYC_SCHEMA_ID, SANCTIONS_SCHEMA_ID } from '../attestation/schemas.js';
import type { TrustAnchor, VerificationPolicy } from '../verifier/contracts.js';
import type { ChainConfig } from '../chains/index.js';
import { buildPublicPolicy, buildPublicRequirements, type PayeeRequirement } from './public.js';

// Payer-roled compliance caps — the fixed v1 vocabulary this deployment understands.
export const KYC_FULL: ParsedCapability = makeCap('attests:kyc:v1', { level: 'full' }, Roles.payer);
export const KYC_BASIC: ParsedCapability = makeCap('attests:kyc:v1', { level: 'basic' }, Roles.payer);
export const SANCTIONS: ParsedCapability = makeCap('attests:sanctions:v1', {}, Roles.payer);

/** Registry vocabulary — basic registered too so kyc[full] monotone-satisfies kyc[basic] (§3.3.3). */
export const COMPLIANCE_REGISTRY_CAPS: ParsedCapability[] = [KYC_BASIC, KYC_FULL, SANCTIONS];

export type ComplianceTag = 'kyc' | 'kyc-basic' | 'sanctions';

const TAG_TO_CAP: Record<ComplianceTag, ParsedCapability> = {
  kyc: KYC_FULL,
  'kyc-basic': KYC_BASIC,
  sanctions: SANCTIONS,
};

/** SDK side: profile tags → the payer-roled caps to sign into requiredCapabilities. */
export function resolveComplianceCaps(tags: ComplianceTag[]): ParsedCapability[] {
  return tags.map((t) => {
    const c = TAG_TO_CAP[t];
    if (!c) throw new Error(`unknown compliance tag: ${t}`);
    return c;
  });
}

export type ComplianceFamily = 'attests:kyc:v1' | 'attests:sanctions:v1';

export interface TrustedIssuer {
  family: ComplianceFamily;
  issuerAddress: Address;
}

const FAMILY_SCHEMA: Record<ComplianceFamily, Hex> = {
  'attests:kyc:v1': KYC_SCHEMA_ID,
  'attests:sanctions:v1': SANCTIONS_SCHEMA_ID,
};

export interface CompliancePolicyOpts {
  trustedIssuers: TrustedIssuer[];
  /** Deployment floor the mandate MUST declare (§5.1 step 3b); omit to merely accept-when-offered. */
  policyRequiredCaps?: ParsedCapability[];
}

/**
 * Layer compliance onto an EXISTING policy (mutates + returns it): merges the
 * compliance cap vocabulary into the registry, appends issuer trust anchors, and
 * extends the step-3b floor. Composable — apply it on top of any base policy
 * (public or x402). Preserves whatever caps/adapters the base policy already
 * registered.
 */
export function applyComplianceToPolicy(policy: VerificationPolicy, opts: CompliancePolicyOpts): VerificationPolicy {
  for (const c of COMPLIANCE_REGISTRY_CAPS) policy.capabilityRegistry.set(c.id, c);
  for (const ti of opts.trustedIssuers) {
    const key = familyCapId(ti.family);
    const list = policy.issuerTrustAnchors.get(key) ?? [];
    list.push({ scheme: 'evm-key', identifier: evmIssuerKeyId(ti.issuerAddress), acceptedSchemaIds: [FAMILY_SCHEMA[ti.family]] });
    policy.issuerTrustAnchors.set(key, list);
  }
  if (opts.policyRequiredCaps && opts.policyRequiredCaps.length > 0) {
    policy.policyRequiredCapabilities = [...(policy.policyRequiredCapabilities ?? []), ...opts.policyRequiredCaps.map((c) => c.id)];
  }
  return policy;
}

export function buildCompliancePolicy(
  chain: ChainConfig,
  adapterAddress: Address,
  evaluationTime: number,
  opts: CompliancePolicyOpts,
): VerificationPolicy {
  return applyComplianceToPolicy(buildPublicPolicy(chain, adapterAddress, evaluationTime), opts);
}

/** §7.7 projection of a compliance deployment (issuers + the declared floor). */
export function buildComplianceRequirements(
  chain: ChainConfig,
  opts: { expiresAt: number; extraAdapters?: PayeeRequirement['adapters']; extraOffered?: string[] } & CompliancePolicyOpts,
): PayeeRequirement {
  const issuers: PayeeRequirement['issuers'] = {};
  for (const ti of opts.trustedIssuers) {
    const k = ti.family; // human family id; payer strips role + matches by base (§2.3.1)
    (issuers[k] ??= []).push({
      scheme: 'evm-key',
      identifier: evmIssuerKeyId(ti.issuerAddress),
      acceptedSchemaIds: [FAMILY_SCHEMA[ti.family]],
    });
  }
  const offered = [...COMPLIANCE_REGISTRY_CAPS.map((c) => c.id as string), ...(opts.extraOffered ?? [])];
  const required = (opts.policyRequiredCaps ?? []).map((c) => c.id as string);
  return buildPublicRequirements(chain, {
    expiresAt: opts.expiresAt,
    policyRequiredCapabilities: required,
    offeredCapabilities: offered,
    issuers,
    ...(opts.extraAdapters ? { extraAdapters: opts.extraAdapters } : {}),
  });
}
