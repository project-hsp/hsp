/**
 * @hsp/sdk — developer-facing surface over @hsp/core + the Coordinator API.
 *
 *   payer:         new HSPClient({ coordinatorUrl, signer, chain }).pay({ to, amount })
 *   relying party: new HSPVerifier({ chain, adapterAddress }).verify(m, r)
 *                  (payee shipping goods, auditor, platform — anyone who acts on a payment)
 *   payee invoice: buildPaymentRequest(chain, { to, amount })
 */

export { HSPClient, type HSPClientOptions, type PayParams, type PayProfile, type PayHandle, type PaymentSnapshot } from './client.js';
export { HSPVerifier, type PinnedTrustConfig } from './verifier.js';
export {
  resolveComplianceCaps,
  buildCompliancePolicy,
  buildComplianceRequirements,
  type ComplianceTag,
  type TrustedIssuer,
  type CompliancePolicyOpts,
} from '@hsp/core/policy/compliance';
export {
  signMandateBody,
  signGrant,
  signerAddress,
  mandateTypedData,
  grantTypedData,
  eip3009TypedData,
  walletClientFor,
  type HSPSigner,
  type Eip3009Authorization,
} from './signer.js';
export {
  buildDelegationGrant,
  erc1271OwnerExecutor,
  type AccountExecutor,
  type BuildDelegationGrantOpts,
} from './delegation.js';
export { fetchRequirements, buildPaymentRequest, type PayeeRequirement, type PaymentRequest } from './requirements.js';
export { assertDeployment, DeploymentMismatchError, type ExpectedTrust } from './assert.js';
export {
  x402Gate,
  buildPaymentRequired,
  fetchWithX402,
  wrapFetchWithX402,
  type X402GateOptions,
  type X402GateResult,
  type X402PayerOptions,
  type X402PaidResponse,
} from './x402.js';
