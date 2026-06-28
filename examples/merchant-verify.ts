/**
 * Merchant-side INDEPENDENT verification — "ACCEPT means ship" without
 * trusting the Coordinator: pin the adapter's observation address once
 * (GET /chains → adapterAddress, then hardcode/pin it), fetch the triple,
 * and run the core verifier yourself.
 *
 *   npx tsx examples/merchant-verify.ts <paymentId>
 *
 * Env: HSP_COORDINATOR_URL, HSP_CHAIN, HSP_PINNED_ADAPTER_ADDRESS,
 * and for anvil-dev: HSP_STABLECOIN_ANVIL_DEV=0xTOKEN:MUSDC:6.
 */

import type { Address } from 'viem';
import type { Receipt, SignedExecution } from '@hsp/core';
import { resolveChain, type ChainName } from '@hsp/core/chains/index';
import { HSPVerifier } from '@hsp/sdk';
import { parseStablecoin } from '@hsp/core/chains/index';

const [paymentId] = process.argv.slice(2);
if (!paymentId) throw new Error('usage: tsx examples/merchant-verify.ts <paymentId>');

const chainName = (process.env.HSP_CHAIN ?? 'anvil-dev') as ChainName;
const stableSpec = process.env[`HSP_STABLECOIN_${chainName.toUpperCase().replace(/-/g, '_')}`];
const chain = resolveChain(chainName, stableSpec ? { stablecoin: parseStablecoin(stableSpec) } : {});
const adapterAddress = process.env.HSP_PINNED_ADAPTER_ADDRESS as Address;
if (!adapterAddress) throw new Error('HSP_PINNED_ADAPTER_ADDRESS required (pin it out-of-band — GET /chains once)');

const base = (process.env.HSP_COORDINATOR_URL ?? 'http://127.0.0.1:8787').replace(/\/$/, '');
const snap = (await (await fetch(`${base}/payments/${paymentId}`)).json()) as {
  mandate: SignedExecution;
  receipts: { receipt: Receipt }[];
};
if (!snap.receipts?.length) throw new Error('no admitted receipts yet');

const verifier = new HSPVerifier({ chain, adapterAddress });
const decision = await verifier.verify(snap.mandate, snap.receipts[snap.receipts.length - 1]!.receipt);
console.log(JSON.stringify(decision, null, 2));
console.log(decision.ok && decision.outcomeClass === 'ACCEPT' ? '→ SHIP' : '→ DO NOT SHIP');
