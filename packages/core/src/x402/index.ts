/**
 * x402 v2 protocol module — wire types + the exact-EVM (EIP-3009) scheme + CAIP-2 +
 * HTTP header (de)serialization. Pure x402 (no HSP concepts); HSP rides the top-level
 * `extensions` field. Used by the conformant facilitator, the resource-server
 * middleware, and the SDK x402 client.
 */

export type {
  ResourceInfo,
  PaymentRequirements,
  PaymentRequired,
  Eip3009Authorization,
  ExactEvmPayload,
  PaymentPayload,
  FacilitatorRequest,
  VerifyResponse,
  SettleResponse,
} from './types.js';
export { X402_VERSION } from './types.js';

export { toCaip2, parseCaip2, isEvmCaip2 } from './caip2.js';

export {
  TRANSFER_WITH_AUTHORIZATION_TYPES,
  tokenDomainFrom,
  verifyExactEvm,
  splitSignature,
  type TokenDomain,
} from './exact-evm.js';

export {
  HEADER,
  encodePaymentRequired,
  decodePaymentRequired,
  encodePaymentPayload,
  decodePaymentPayload,
  encodeSettleResponse,
  decodeSettleResponse,
} from './headers.js';
