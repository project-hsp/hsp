/**
 * @hsp/core — public entry.
 *
 * Re-exports the §2/§3 wire surface (wire types, capability tooling, EIP-712
 * derivations) via core/index. The verifier, signer profiles, adapters and
 * attestation helpers are deliberately left on subpath imports
 * (`@hsp/core/verifier/index`, `@hsp/core/adapter/mock-evm-transfer`, …) so
 * consumers pull in only what they use; the SDK may widen this barrel later.
 */
export * from './core/index.js';
