/**
 * 10-line HSP payment — the hackathon hello-world.
 *
 * Prereqs: a Coordinator URL (the hosted sandbox) and a funded key.
 * Env: HSP_COORDINATOR_URL, HSP_API_KEY, HSP_PRIVATE_KEY, HSP_CHAIN (registry
 * name), and for anvil-dev: HSP_STABLECOIN_ANVIL_DEV=0xTOKEN:MUSDC:6.
 *
 *   npx tsx examples/pay-demo.ts 0xRecipient 1000000
 */

import type { Address, Hex } from 'viem';
import { resolveChain, type ChainName } from '@hsp/core/chains/index';
import { HSPClient } from '@hsp/sdk';
import { parseStablecoin } from '@hsp/core/chains/index';

const [to, amount] = process.argv.slice(2);
if (!to || !amount) throw new Error('usage: tsx examples/pay-demo.ts <recipient> <amount-base-units>');

const chainName = (process.env.HSP_CHAIN ?? 'anvil-dev') as ChainName;
const stableSpec = process.env[`HSP_STABLECOIN_${chainName.toUpperCase().replace(/-/g, '_')}`];
const chain = resolveChain(chainName, stableSpec ? { stablecoin: parseStablecoin(stableSpec) } : {});

const client = new HSPClient({
  coordinatorUrl: process.env.HSP_COORDINATOR_URL ?? 'http://127.0.0.1:8787',
  signer: { kind: 'privateKey', privateKey: process.env.HSP_PRIVATE_KEY as Hex },
  chain,
  ...(process.env.HSP_API_KEY ? { apiKey: process.env.HSP_API_KEY } : {}),
});

const handle = await client.pay({ to: to as Address, amount: BigInt(amount) });
console.log(`paymentId ${handle.paymentId}\ntxHash    ${handle.txHash}\nstatus    ${handle.status}`);
const final = await handle.awaitSettled();
console.log(`final     ${final.status}`);
