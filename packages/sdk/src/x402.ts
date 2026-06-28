/**
 * x402 resource-server gate (P3). Framework-agnostic: it operates on Web-standard
 * `Request`/`Response`, so it plugs into hono (`x402Gate(c.req.raw, opts)`), Bun,
 * Deno, Cloudflare Workers, or Next.js route handlers without a framework dep.
 *
 * The resource server prices a route in x402 terms; the gate emits the `402` +
 * `PAYMENT-REQUIRED` challenge, then verifies (and settles) a returned
 * `PAYMENT-SIGNATURE` via the facilitator. HSP rides `extensions.hsp`: an HSP-aware
 * payer carries its SignedMandate there, and the facilitator bridges it to a
 * verifiable HSP receipt at settle (P2) — a stock x402 payer simply omits it and
 * still pays. See docs/design/x402-alignment.md §6 (P3).
 *
 *   hono usage:
 *     app.use('/paid/*', async (c, next) => {
 *       const r = await x402Gate(c.req.raw, gateOpts);
 *       if (!r.paid) return r.response;            // 402 PAYMENT-REQUIRED
 *       for (const [k, v] of Object.entries(r.headers)) c.header(k, v); // PAYMENT-RESPONSE
 *       c.set('x402Payer', r.payer);
 *       await next();                              // serve the protected content
 *     });
 */

import { encodeAbiParameters, getAddress, toHex, type Address, type Hex } from 'viem';
import {
  HEADER,
  encodePaymentRequired,
  decodePaymentRequired,
  decodePaymentPayload,
  encodePaymentPayload,
  encodeSettleResponse,
  decodeSettleResponse,
  parseCaip2,
  type PaymentRequired,
  type PaymentRequirements,
  type PaymentPayload,
  type ResourceInfo,
  type VerifyResponse,
  type SettleResponse,
} from '@hsp/core/x402/index';
import { requiredCapabilitiesHash, type Mandate, type SignedMandate } from '@hsp/core';
import { eip712EoaSigner } from '@hsp/core/profiles/signer/eip712-eoa';
import { chainDomain, type ChainConfig } from '@hsp/core/chains/index';
import { signEip3009Authorization, signerAddress, signMandateBody, type HSPSigner } from './signer.js';

export interface X402GateOptions {
  /** Facilitator base URL (POST /verify + /settle). */
  facilitatorUrl: string;
  payTo: Address;
  asset: Address;
  /** Price in atomic units. */
  amount: bigint | string;
  /** CAIP-2 network, e.g. "eip155:133". */
  network: string;
  /** The token's EIP-712 domain {name, version} (exact-EVM `extra`). */
  tokenDomain: { name: string; version: string };
  maxTimeoutSeconds?: number;
  resource?: ResourceInfo;
  /** Settle on accept (default true). false ⇒ verify only (deferred settlement). */
  settle?: boolean;
  /** Advisory HSP terms surfaced in PaymentRequired.extensions.hsp (e.g. requiredCapabilities, mandateDomain). */
  hsp?: Record<string, unknown>;
  /** Bridge an HSP-aware payment (payload.extensions.hsp.mandate) to a verifiable adapter:x402
   *  receipt at the Coordinator after settling — the COORDINATOR is the adapter operator: it
   *  reads the chain and signs the receipt. Set this to make the gate register the mandate +
   *  submit the EIP-3009 proof + txHash to the Coordinator. */
  hspBridge?: { coordinatorUrl: string; coordinatorApiKey: string; chainName: string; merchantDomain: string };
  /** Injectable fetch (tests). */
  fetchImpl?: typeof fetch;
}

export type X402GateResult =
  | { paid: false; response: Response }
  | { paid: true; payer: Address; settleResponse?: SettleResponse; headers: Record<string, string>; hsp?: unknown };

function requirementsOf(opts: X402GateOptions): PaymentRequirements {
  return {
    scheme: 'exact',
    network: opts.network,
    asset: opts.asset,
    amount: typeof opts.amount === 'bigint' ? opts.amount.toString() : opts.amount,
    payTo: opts.payTo,
    maxTimeoutSeconds: opts.maxTimeoutSeconds ?? 60,
    extra: { name: opts.tokenDomain.name, version: opts.tokenDomain.version },
  };
}

/** Build the conformant `402` body (also base64 in the `PAYMENT-REQUIRED` header). */
export function buildPaymentRequired(opts: X402GateOptions, error?: string): PaymentRequired {
  return {
    x402Version: 2,
    ...(error ? { error } : {}),
    resource: opts.resource ?? { url: '' },
    accepts: [requirementsOf(opts)],
    ...(opts.hsp ? { extensions: { hsp: opts.hsp } } : {}),
  };
}

function paymentRequiredResponse(opts: X402GateOptions, error?: string): Response {
  const pr = buildPaymentRequired(opts, error);
  return new Response(JSON.stringify(pr), {
    status: 402,
    headers: { 'content-type': 'application/json', [HEADER.required]: encodePaymentRequired(pr) },
  });
}

/**
 * Gate a request behind x402. Returns either a `402` Response (no/invalid/failed
 * payment — return it verbatim) or a paid result (attach `headers` to your `200`
 * and serve the content). The gate verifies against ITS OWN requirements, never the
 * client-asserted `accepted`.
 */
export async function x402Gate(req: Request, opts: X402GateOptions): Promise<X402GateResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const sigHeader = req.headers.get(HEADER.signature) ?? req.headers.get(HEADER.v1Payment);
  if (!sigHeader) return { paid: false, response: paymentRequiredResponse(opts) };

  let paymentPayload;
  try {
    paymentPayload = decodePaymentPayload(sigHeader);
  } catch {
    return { paid: false, response: paymentRequiredResponse(opts, 'malformed PAYMENT-SIGNATURE') };
  }
  const paymentRequirements = requirementsOf(opts);
  const base = opts.facilitatorUrl.replace(/\/$/, '');
  const post = (path: string): Promise<Response> =>
    doFetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements }) });

  const verify = (await (await post('/verify')).json()) as VerifyResponse;
  if (!verify.isValid) return { paid: false, response: paymentRequiredResponse(opts, verify.invalidReason ?? 'invalid payment') };

  if (opts.settle === false) return { paid: true, payer: verify.payer as Address, headers: {} };

  const settleResponse = (await (await post('/settle')).json()) as SettleResponse;
  if (!settleResponse.success) return { paid: false, response: paymentRequiredResponse(opts, settleResponse.errorReason ?? 'settlement failed') };

  const result: X402GateResult = {
    paid: true,
    payer: (settleResponse.payer ?? verify.payer) as Address,
    settleResponse,
    headers: { [HEADER.response]: encodeSettleResponse(settleResponse) },
  };
  // the COORDINATOR is the adapter:x402 operator — bridge the HSP mandate (if the payer rode one)
  // to a verifiable receipt: register it + submit the EIP-3009 proof + txHash for the Coordinator to sign.
  const mandate = (paymentPayload.extensions?.['hsp'] as { mandate?: SignedMandate } | undefined)?.mandate;
  if (opts.hspBridge && mandate && settleResponse.transaction) {
    result.hsp = await bridgeGateToHsp(opts.hspBridge, mandate, paymentPayload, paymentRequirements, settleResponse, doFetch);
  }
  return result;
}

/** Gate-side HSP bridge: register the payer's mandate + submit the x402 settlement evidence to the
 * Coordinator (the adapter:x402 operator), which reads the chain and signs the receipt itself. */
async function bridgeGateToHsp(
  cfg: { coordinatorUrl: string; coordinatorApiKey: string; chainName: string; merchantDomain: string },
  mandate: SignedMandate,
  payload: PaymentPayload,
  req: PaymentRequirements,
  settle: SettleResponse,
  doFetch: typeof fetch,
): Promise<Record<string, unknown>> {
  const base = cfg.coordinatorUrl.replace(/\/$/, '');
  const headers = { 'content-type': 'application/json', authorization: `Bearer ${cfg.coordinatorApiKey}` };
  const reg = await doFetch(`${base}/payments`, { method: 'POST', headers, body: JSON.stringify({ chain: cfg.chainName, mandate }) });
  const regJson = (await reg.json().catch(() => ({}))) as { paymentId?: Hex };
  if (!regJson.paymentId) return { bridged: false, error: 'mandate registration failed' };
  const ev = payload.payload as { signature: Hex; authorization: unknown };
  const sub = await doFetch(`${base}/payments/${regJson.paymentId}/x402-observe`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      authorization: ev.authorization,
      signature: ev.signature,
      tokenName: req.extra?.['name'],
      tokenVersion: req.extra?.['version'],
      txHash: settle.transaction,
      merchantDomain: cfg.merchantDomain,
    }),
  });
  const subJson = (await sub.json().catch(() => ({}))) as Record<string, unknown>;
  return { paymentId: regJson.paymentId, bridged: sub.ok, ...subJson };
}

// ─────────────────────────── x402 payer client (P4) ───────────────────────────

export interface X402PayerOptions {
  /** Signs the EIP-3009 authorization (and, if `hsp` is set, the HSP mandate). */
  signer: HSPSigner;
  /** Attach an HSP mandate in `extensions.hsp` so settlement also yields a verifiable
   *  HSP receipt (the facilitator bridges it, P2). Requires the chain for the mandate
   *  domain; its chainId MUST match the chosen requirement's CAIP-2 network. */
  hsp?: { chain: ChainConfig };
  /** Refuse to pay more than this many atomic units (safety rail). */
  maxAmount?: bigint;
  fetchImpl?: typeof fetch;
}

export interface X402PaidResponse {
  /** The final response (the resource's 200 if payment succeeded, else the last response). */
  response: Response;
  /** True once a payment was constructed and the resource accepted it. */
  paid: boolean;
  /** Decoded `PAYMENT-RESPONSE` (settlement result), when present. */
  settleResponse?: SettleResponse;
  /** The HSP paymentId (mandateHash) when an HSP mandate was attached. */
  paymentId?: Hex;
}

/** Pick the exact-EVM requirement this payer can satisfy (eip155 / exact). */
function selectRequirement(pr: PaymentRequired): PaymentRequirements | undefined {
  return pr.accepts.find((r) => r.scheme === 'exact' && /^eip155:\d+$/.test(r.network) && r.extra?.['name'] !== undefined);
}

function buildHspMandate(signer: HSPSigner, chain: ChainConfig, req: PaymentRequirements, deadline: number): Mandate {
  return {
    nonce: toHex(crypto.getRandomValues(new Uint8Array(32))),
    signer: { profileId: eip712EoaSigner.profileIdHash, payload: encodeAbiParameters([{ type: 'address' }], [signerAddress(signer)]) },
    recipient: { kind: 0, payload: encodeAbiParameters([{ type: 'address' }], [getAddress(req.payTo)]) },
    token: getAddress(req.asset),
    amount: req.amount,
    chainId: parseCaip2(req.network),
    deadline,
    requiredCapabilitiesHash: requiredCapabilitiesHash([]),
  };
}

/**
 * Pay an x402-gated resource. Mirrors x402-fetch: make the request; on `402`, read
 * `PAYMENT-REQUIRED`, sign the exact-EVM authorization (and optionally an HSP
 * mandate), retry with `PAYMENT-SIGNATURE`, and return the resource's response. Works
 * against ANY conformant x402 server (our gate, or a stock one) — two-way interop.
 */
export async function fetchWithX402(input: string | URL, init: RequestInit | undefined, opts: X402PayerOptions): Promise<X402PaidResponse> {
  const doFetch = opts.fetchImpl ?? fetch;
  const first = await doFetch(input, init);
  if (first.status !== 402) return { response: first, paid: false };

  // read the challenge (header first, then JSON body)
  let pr: PaymentRequired;
  const hdr = first.headers.get(HEADER.required);
  if (hdr) pr = decodePaymentRequired(hdr);
  else pr = (await first.clone().json()) as PaymentRequired;

  const req = selectRequirement(pr);
  if (!req) throw new Error('no exact-EVM (eip155) payment requirement this payer can satisfy');
  if (opts.maxAmount !== undefined && BigInt(req.amount) > opts.maxAmount) {
    throw new Error(`x402 price ${req.amount} exceeds maxAmount ${opts.maxAmount}`);
  }

  const from = signerAddress(opts.signer);
  const validBefore = Math.floor(Date.now() / 1000) + (req.maxTimeoutSeconds || 60);
  const nonce = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const tokenDomain = { name: String(req.extra?.['name']), version: String(req.extra?.['version']), chainId: parseCaip2(req.network), address: getAddress(req.asset) };
  const signature = await signEip3009Authorization(opts.signer, tokenDomain, {
    from, to: getAddress(req.payTo), value: BigInt(req.amount), validAfter: 0, validBefore, nonce,
  });
  const authorization = { from, to: getAddress(req.payTo), value: req.amount, validAfter: '0', validBefore: String(validBefore), nonce };

  // optional HSP mandate (yields a verifiable HSP receipt via the facilitator bridge)
  let extensions: Record<string, unknown> | undefined;
  let paymentId: Hex | undefined;
  if (opts.hsp) {
    if (opts.hsp.chain.chainId !== tokenDomain.chainId) throw new Error('hsp.chain.chainId does not match the x402 requirement network');
    const body = buildHspMandate(opts.signer, opts.hsp.chain, req, validBefore);
    const { mandateHash, signerProof } = await signMandateBody(opts.signer, chainDomain(opts.hsp.chain), body);
    const mandate: SignedMandate = { body, signerProof, requiredCapabilities: [] };
    extensions = { hsp: { mandate } };
    paymentId = mandateHash;
  }

  const pp: PaymentPayload = { x402Version: 2, accepted: req, payload: { signature, authorization }, ...(extensions ? { extensions } : {}) };
  const headers = new Headers(init?.headers);
  headers.set(HEADER.signature, encodePaymentPayload(pp));
  const response = await doFetch(input, { ...init, headers });

  const respHdr = response.headers.get(HEADER.response);
  const settleResponse = respHdr ? decodeSettleResponse(respHdr) : undefined;
  return { response, paid: response.ok, settleResponse, paymentId };
}

/** x402-fetch-style wrapper: returns a `fetch`-compatible function that auto-pays `402`s. */
export function wrapFetchWithX402(opts: X402PayerOptions): (input: string | URL, init?: RequestInit) => Promise<Response> {
  return async (input, init) => (await fetchWithX402(input, init, opts)).response;
}
