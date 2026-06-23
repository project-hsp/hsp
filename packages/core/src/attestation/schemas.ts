/**
 * Attestation claims schemas (HSP.md §2.3.1 schemaId + CR2(f)).
 *
 * Each schema defines a schemaId + a claims codec. Per the §3.3.3 (b) decision, the
 * claims carry the STRUCTURED param value (e.g. maxScore=10, level=full) so the
 * verifier reads it directly for monotone comparison — no enumerate-and-rehash.
 * `decodeClaims` doubles as the CR2(f) structural validator (throws on violation).
 */

import { keccak256, stringToBytes, encodeAbiParameters, decodeAbiParameters, type Hex } from 'viem';
import type { CapParam } from '../core/capabilities.js';

export interface AttestationSchema {
  schemaId: Hex;
  baseCapKey: string; // "attests:kyc:v1" — the attests:* family this schema backs
  encodeClaims(params: Record<string, string>): Hex;
  decodeClaims(claims: Hex): CapParam[]; // structured candidate params (b); throws on structural violation (CR2f)
}

export const KYC_SCHEMA_ID: Hex = keccak256(stringToBytes('hsp.attest.kyc.v1'));
export const SANCTIONS_SCHEMA_ID: Hex = keccak256(stringToBytes('hsp.attest.sanctions.v1'));
export const RISK_SCORE_SCHEMA_ID: Hex = keccak256(stringToBytes('hsp.attest.risk-score.v1'));

const KYC_LEVELS = ['basic', 'full'];

const kyc: AttestationSchema = {
  schemaId: KYC_SCHEMA_ID,
  baseCapKey: 'attests:kyc:v1',
  encodeClaims: (p) => encodeAbiParameters([{ type: 'string' }], [p.level ?? '']),
  decodeClaims: (claims) => {
    const level = decodeAbiParameters([{ type: 'string' }], claims)[0];
    if (!KYC_LEVELS.includes(level)) throw new Error(`kyc claims: bad level "${level}"`);
    return [{ key: 'level', type: 'string', value: level }];
  },
};

const sanctions: AttestationSchema = {
  schemaId: SANCTIONS_SCHEMA_ID,
  baseCapKey: 'attests:sanctions:v1',
  encodeClaims: () => '0x',
  decodeClaims: (claims) => {
    if (claims !== '0x') throw new Error('sanctions claims: must be empty');
    return [];
  },
};

const riskScore: AttestationSchema = {
  schemaId: RISK_SCORE_SCHEMA_ID,
  baseCapKey: 'attests:risk-score:v1',
  encodeClaims: (p) => encodeAbiParameters([{ type: 'uint256' }], [BigInt(p.maxScore ?? '0')]),
  decodeClaims: (claims) => {
    const v = decodeAbiParameters([{ type: 'uint256' }], claims)[0];
    return [{ key: 'maxScore', type: 'uint256', value: v.toString() }];
  },
};

export const ATTESTATION_SCHEMAS: Record<Hex, AttestationSchema> = {
  [KYC_SCHEMA_ID]: kyc,
  [SANCTIONS_SCHEMA_ID]: sanctions,
  [RISK_SCORE_SCHEMA_ID]: riskScore,
};
