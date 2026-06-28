/**
 * Attestation per-entry validation — HSP.md §4.3.4 CR2 (a),(b),(c),(d),(e).
 *
 * (f) claims-decode, the claims↔capabilityId integrity check, and §3.3.3
 * admissibility (strict / monotone) are done by the verifier's walk (§5.2 step 5),
 * which owns the cap registry + schema family. This covers the rest of CR2.
 */

import { recoverAddress, type Hex } from 'viem';
import { partyRefEqual, type Attestation, type PartyRef } from '../core/index.js';
import { attestationStructHash, evmIssuerKeyId } from './issuer.js';
import type { TrustAnchor } from '../verifier/contracts.js';

const ZERO32: Hex = `0x${'00'.repeat(32)}`;

export interface CR2Result {
  ok: boolean;
  code?: string; // HSP-ATT-ISSUER-UNTRUSTED (CR2b) | HSP-ATT-INVALID (others)
}

/**
 * CR2 (a)–(e). `anchors` is the deployment Issuer Trust Anchor list for this cap's
 * family; `contextScope` is the §7.2.2 per-cap binding requirement (undefined ⇒
 * subject-scoped allowed). Returns the CR3 code on failure.
 */
export async function validateCR2(
  entry: Attestation,
  expectedSubject: PartyRef | undefined,
  anchors: TrustAnchor[],
  now: number,
  mandateHash: Hex,
  receiptHash: Hex,
  contextScope: 'mandate' | 'receipt' | undefined,
): Promise<CR2Result> {
  // (a) issuerSignature recovers to the declared issuerKeyId
  let signer: Hex;
  try {
    signer = await recoverAddress({ hash: attestationStructHash(entry), signature: entry.issuerSignature });
  } catch {
    return { ok: false, code: 'HSP-ATT-INVALID' };
  }
  if (evmIssuerKeyId(signer).toLowerCase() !== entry.issuerKeyId.toLowerCase()) {
    return { ok: false, code: 'HSP-ATT-INVALID' };
  }

  // (b) issuerKeyId ∈ trust anchors AND schemaId ∈ anchor.acceptedSchemaIds
  const trusted = anchors.some(
    (an) =>
      an.identifier.toLowerCase() === entry.issuerKeyId.toLowerCase() &&
      an.acceptedSchemaIds.some((s) => s.toLowerCase() === entry.schemaId.toLowerCase()),
  );
  if (!trusted) return { ok: false, code: 'HSP-ATT-ISSUER-UNTRUSTED' };

  // (c) subjectBinding == roleAssignment[roleName]
  if (!expectedSubject || !partyRefEqual(entry.subjectBinding, expectedSubject)) {
    return { ok: false, code: 'HSP-ATT-INVALID' };
  }

  // (d) validity window
  if (now < entry.issuedAt || (entry.expiresAt !== 0 && now > entry.expiresAt)) {
    return { ok: false, code: 'HSP-ATT-INVALID' };
  }

  // (e) contextBinding ∈ {0, mandateHash, receiptHash} + §7.2.2 scope predicate
  const cb = entry.contextBinding.toLowerCase();
  const inSet = cb === ZERO32 || cb === mandateHash.toLowerCase() || cb === receiptHash.toLowerCase();
  if (!inSet) return { ok: false, code: 'HSP-ATT-INVALID' };
  if (contextScope === 'mandate' && cb !== mandateHash.toLowerCase()) return { ok: false, code: 'HSP-ATT-INVALID' };
  if (contextScope === 'receipt' && cb !== receiptHash.toLowerCase()) return { ok: false, code: 'HSP-ATT-INVALID' };

  return { ok: true };
}
