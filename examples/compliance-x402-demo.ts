/**
 * Compliant machine-to-machine payment (scenario 4) — KYC + sanctions over x402.
 *
 * Like compliance-pay-demo, but settled via the conformant x402 facilitator: the
 * `attests:kyc` + `attests:sanctions` caps are signed into the mandate, the
 * attestations are fetched and registered with the COORDINATOR directly (the
 * facilitator never sees them), and the facilitator settles the EIP-3009 transfer
 * (your funds move, zero gas for you).
 *
 * Env: HSP_COORDINATOR_URL, HSP_API_KEY, HSP_PRIVATE_KEY, HSP_CHAIN,
 *      HSP_ISSUER_URL (mock issuer), HSP_FACILITATOR_URL (e.g. http://127.0.0.1:8789),
 *      HSP_X402_MERCHANT (payout address),
 *      and for anvil-dev: HSP_STABLECOIN_ANVIL_DEV=0xTOKEN:MUSDC:6.
 *
 *   npx tsx examples/compliance-x402-demo.ts 10000
 */

import type { Address, Hex } from 'viem';
import { resolveChain, type ChainName } from '@hsp/core/chains/index';
import { HSPClient } from '@hsp/sdk';
import { parseStablecoin } from '@hsp/core/chains/index';

const [amount] = process.argv.slice(2);
if (!amount) throw new Error('usage: tsx examples/compliance-x402-demo.ts <amount-base-units>');
const merchant = process.env.HSP_X402_MERCHANT as Address;
if (!merchant) throw new Error('HSP_X402_MERCHANT required (the merchant payout address)');
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

const handle = await client.payX402({
  merchant,
  facilitatorUrl: process.env.HSP_FACILITATOR_URL ?? 'http://127.0.0.1:8789',
  amount: BigInt(amount),
  profile: { compliance: ['kyc', 'sanctions'] },
});
console.log(`paymentId ${handle.paymentId}\nsettleTx  ${handle.txHash}\nstatus    ${handle.status}`);
const final = await handle.awaitSettled();
console.log(`final     ${final.status}`);
console.log(`\nopen the decision trace: ${(process.env.HSP_COORDINATOR_URL ?? 'http://127.0.0.1:8787').replace(/\/$/, '')}/explorer?id=${handle.paymentId}`);
console.log('→ adapter:x402 receipt + two attests:* caps, each satisfied by an issuer attestation');
