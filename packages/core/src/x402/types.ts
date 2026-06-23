/**
 * x402 v2 wire types — verbatim from the shipped TS types
 * (coinbase/x402 `typescript/packages/core/src/types/`), the interop ground truth
 * (the prose spec drifts from the implementation). We model v2; a thin v1 reader
 * lives in `./v1.ts`. Scheme covered: `exact` on EVM (EIP-3009).
 *
 * These are pure wire shapes — no HSP concepts. HSP rides the top-level
 * `extensions` field (never `extra`, which is scheme/network-specific).
 */

export interface ResourceInfo {
  url: string;
  description?: string;
  mimeType?: string;
}

/** One acceptable payment method. `extra` is scheme/network-specific (exact-EVM: token EIP-712 domain). */
export interface PaymentRequirements {
  scheme: string; // "exact"
  network: string; // CAIP-2, e.g. "eip155:133"
  asset: string; // token contract address (exact-EVM)
  amount: string; // atomic units
  payTo: string; // recipient address (exact-EVM)
  maxTimeoutSeconds: number;
  extra?: Record<string, unknown>; // exact-EVM: { name, version } of the token's EIP-712 domain
}

/** The 402 body (base64 in the `PAYMENT-REQUIRED` header, v1: in the JSON body). */
export interface PaymentRequired {
  x402Version: number; // 2
  error?: string;
  resource: ResourceInfo;
  accepts: PaymentRequirements[];
  extensions?: Record<string, unknown>; // HSP rides here under `hsp`
}

/** The EIP-3009 authorization the client signs (exact-EVM `payload`). */
export interface Eip3009Authorization {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: string; // bytes32
}

/** exact-EVM scheme payload. */
export interface ExactEvmPayload {
  signature: string; // EIP-712 sig over `authorization` under the TOKEN's domain
  authorization: Eip3009Authorization;
}

/** The client's payment (base64 in the `PAYMENT-SIGNATURE` header, v1: `X-PAYMENT`). */
export interface PaymentPayload {
  x402Version: number;
  resource?: ResourceInfo;
  accepted: PaymentRequirements; // the chosen requirements (carries scheme/network)
  payload: Record<string, unknown>; // exact-EVM: ExactEvmPayload
  extensions?: Record<string, unknown>; // HSP mandate ref echoes here under `hsp`
}

/** Facilitator `POST /verify` + `POST /settle` request. */
export interface FacilitatorRequest {
  x402Version: number;
  paymentPayload: PaymentPayload;
  paymentRequirements: PaymentRequirements;
}

/** Facilitator `POST /verify` response. */
export interface VerifyResponse {
  isValid: boolean;
  invalidReason?: string;
  invalidMessage?: string;
  payer?: string;
}

/** Facilitator `POST /settle` response (returned in the `PAYMENT-RESPONSE` header). */
export interface SettleResponse {
  success: boolean;
  errorReason?: string;
  errorMessage?: string;
  payer?: string;
  transaction: string; // settle tx hash ("" on failure)
  network: string; // CAIP-2 (required)
  amount?: string;
  extensions?: Record<string, unknown>;
}

export const X402_VERSION = 2;
