/**
 * Compliant payment (scenario 3) — KYC + sanctions, enforced by the verifier.
 *
 * The compliance tags resolve to capability ids that are SIGNED INTO the
 * mandate's required set; the SDK fetches matching attestations for your
 * address from the mock issuer and submits them with the registration. On a
 * deployment with a compliance policy floor, a mandate WITHOUT these caps is
 * rejected up front (HSP-MAND-REQ-INSUFFICIENT).
 *
 * Env: HSP_COORDINATOR_URL, HSP_API_KEY, HSP_PRIVATE_KEY, HSP_CHAIN,
 *      HSP_ISSUER_URL (mock issuer, e.g. http://127.0.0.1:8788),
 *      and for anvil-dev: HSP_STABLECOIN_ANVIL_DEV=0xTOKEN:MUSDC:6.
 *
 *   npx tsx examples/compliance-pay-demo.ts 0xRecipient 1000000
 */

import type { Address, Hex } from 'viem';
import { resolveChain, type ChainName } from '@hsp/core/chains/index';
import { HSPClient } from '@hsp/sdk';
import { parseStablecoin } from '@hsp/core/chains/index';

const [to, amount] = process.argv.slice(2);
if (!to || !amount) throw new Error('usage: tsx examples/compliance-pay-demo.ts <recipient> <amount-base-units>');
if (!process.env.HSP_ISSUER_URL) throw new Error('HSP_ISSUER_URL required (the mock issuer, default sandbox port :8788)');

const chainName = (process.env.HSP_CHAIN ?? 'anvil-dev') as ChainName;
const stableSpec = process.env[`HSP_STABLECOIN_${chainName.toUpperCase().replace(/-/g, '_')}`];
const chain = resolveChain(chainName, stableSpec ? { stablecoin: parseStablecoin(stableSpec) } : {});

const client = new HSPClient({
  coordinatorUrl: process.env.HSP_COORDINATOR_URL ?? 'http://127.0.0.1:8787',
  signer: { kind: 'privateKey', privateKey: process.env.HSP_PRIVATE_KEY as Hex },
  chain,
  issuerUrl: process.env.HSP_ISSUER_URL,
  ...(process.env.HSP_API_KEY ? { apiKey: process.env.HSP_API_KEY } : {}),
});

const handle = await client.pay({
  to: to as Address,
  amount: BigInt(amount),
  profile: { compliance: ['kyc', 'sanctions'] },
});
console.log(`paymentId ${handle.paymentId}\ntxHash    ${handle.txHash}\nstatus    ${handle.status}`);
const final = await handle.awaitSettled();
console.log(`final     ${final.status}`);
console.log(`\nopen the decision trace: ${(process.env.HSP_COORDINATOR_URL ?? 'http://127.0.0.1:8787').replace(/\/$/, '')}/explorer?id=${handle.paymentId}`);
console.log('→ two attests:* capabilities required, each satisfied by an issuer attestation');
