/**
 * x402 HTTP header (de)serialization. v2 uses base64 JSON in `PAYMENT-*` headers;
 * v1 (legacy) used `X-PAYMENT` / `X-PAYMENT-RESPONSE`. Node-side (the x402 wire is
 * server/SDK only — the browser console does not speak x402).
 */

import type { PaymentPayload, PaymentRequired, SettleResponse } from './types.js';

export const HEADER = {
  // v2
  required: 'PAYMENT-REQUIRED',
  signature: 'PAYMENT-SIGNATURE',
  response: 'PAYMENT-RESPONSE',
  // v1 legacy
  v1Payment: 'X-PAYMENT',
  v1Response: 'X-PAYMENT-RESPONSE',
} as const;

function b64encode(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64');
}

function b64decode<T>(b64: string): T {
  return JSON.parse(Buffer.from(b64, 'base64').toString('utf8')) as T;
}

export const encodePaymentRequired = (pr: PaymentRequired): string => b64encode(pr);
export const decodePaymentRequired = (b64: string): PaymentRequired => b64decode<PaymentRequired>(b64);

export const encodePaymentPayload = (pp: PaymentPayload): string => b64encode(pp);
export const decodePaymentPayload = (b64: string): PaymentPayload => b64decode<PaymentPayload>(b64);

export const encodeSettleResponse = (sr: SettleResponse): string => b64encode(sr);
export const decodeSettleResponse = (b64: string): SettleResponse => b64decode<SettleResponse>(b64);
