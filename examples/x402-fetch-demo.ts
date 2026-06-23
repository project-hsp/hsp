/**
 * Pay an x402-gated HTTP resource as a CLIENT (scenario 2, client side). Works against ANY conformant
 * x402 server — our resource gate, or a stock one (e.g. a CDP-backed resource on
 * Base Sepolia). On `402` it signs the exact-EVM (EIP-3009) authorization and
 * retries; set HSP_HSP=1 to also attach an HSP mandate so settlement yields a
 * verifiable HSP receipt (the facilitator bridges it).
 *
 * Env: X402_URL (the gated resource to GET) · HSP_PRIVATE_KEY (signs the payment) ·
 *      HSP_CHAIN (default hashkey-testnet; for the HSP mandate domain) ·
 *      HSP_HSP=1 (attach an HSP mandate) · X402_MAX_AMOUNT (optional cap, atomic units).
 *
 *   X402_URL=https://api.example/paid HSP_PRIVATE_KEY=0x… npx tsx examples/x402-fetch-demo.ts
 */

import type { Hex } from 'viem';
import { resolveChain, type ChainName } from '@hsp/core/chains/index';
import { fetchWithX402 } from '@hsp/sdk';

const url = process.env.X402_URL;
if (!url) throw new Error('X402_URL required (the x402-gated resource URL)');
const privateKey = process.env.HSP_PRIVATE_KEY as Hex;
if (!privateKey) throw new Error('HSP_PRIVATE_KEY required (signs the EIP-3009 authorization)');
const chainName = (process.env.HSP_CHAIN ?? 'hashkey-testnet') as ChainName;
const withHsp = process.env.HSP_HSP === '1';
const maxAmount = process.env.X402_MAX_AMOUNT ? BigInt(process.env.X402_MAX_AMOUNT) : undefined;

const res = await fetchWithX402(url, undefined, {
  signer: { kind: 'privateKey', privateKey },
  ...(withHsp ? { hsp: { chain: resolveChain(chainName) } } : {}),
  ...(maxAmount !== undefined ? { maxAmount } : {}),
});

console.log(`status ${res.response.status} · paid ${res.paid}`);
if (res.settleResponse) console.log(`settled ${res.settleResponse.success} · tx ${res.settleResponse.transaction} · ${res.settleResponse.network}`);
if (res.paymentId) console.log(`HSP paymentId ${res.paymentId}`);
console.log('body:', await res.response.text());
