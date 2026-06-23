/**
 * Machine-to-machine payment (scenario 2) — pay a merchant directly via a
 * conformant x402 Facilitator (real Coinbase x402 v2, self-settling).
 *
 * Flow: sign an HSP mandate + an EIP-3009 exact-EVM authorization → one
 * `POST /settle` → the facilitator submits `transferWithAuthorization` (YOUR funds
 * move, zero gas for you), signs a v2 adapter:x402 receipt, and bridges it to the
 * Coordinator. (To pay an x402-GATED HTTP resource instead, see x402-fetch-demo.ts.)
 *
 * Requires a FiatTokenV2-style token (exposes name()/version()).
 *
 * Env: HSP_COORDINATOR_URL, HSP_API_KEY, HSP_PRIVATE_KEY, HSP_CHAIN,
 *      HSP_FACILITATOR_URL (e.g. http://127.0.0.1:8789),
 *      HSP_X402_MERCHANT (payout address),
 *      and for anvil-dev: HSP_STABLECOIN_ANVIL_DEV=0xTOKEN:MUSDC:6.
 *
 *   npx tsx examples/x402-pay-demo.ts 10000
 */

import type { Address, Hex } from 'viem';
import { resolveChain, type ChainName } from '@hsp/core/chains/index';
import { HSPClient } from '@hsp/sdk';
import { parseStablecoin } from '@hsp/core/chains/index';

const [amount] = process.argv.slice(2);
if (!amount) throw new Error('usage: tsx examples/x402-pay-demo.ts <amount-base-units>');
const merchant = process.env.HSP_X402_MERCHANT as Address;
if (!merchant) throw new Error('HSP_X402_MERCHANT required (the merchant payout address)');

const chainName = (process.env.HSP_CHAIN ?? 'anvil-dev') as ChainName;
const stableSpec = process.env[`HSP_STABLECOIN_${chainName.toUpperCase().replace(/-/g, '_')}`];
const chain = resolveChain(chainName, stableSpec ? { stablecoin: parseStablecoin(stableSpec) } : {});

const client = new HSPClient({
  coordinatorUrl: process.env.HSP_COORDINATOR_URL ?? 'http://127.0.0.1:8787',
  signer: { kind: 'privateKey', privateKey: process.env.HSP_PRIVATE_KEY as Hex },
  chain,
  ...(process.env.HSP_API_KEY ? { apiKey: process.env.HSP_API_KEY } : {}),
});

const handle = await client.payX402({
  merchant,
  facilitatorUrl: process.env.HSP_FACILITATOR_URL ?? 'http://127.0.0.1:8789',
  amount: BigInt(amount),
});
console.log(`paymentId ${handle.paymentId}\nsettleTx  ${handle.txHash}\nstatus    ${handle.status}`);
const final = await handle.awaitSettled();
console.log(`final     ${final.status}`);
