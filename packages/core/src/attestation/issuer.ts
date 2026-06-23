/**
 * Attestation Operator side — issue + sign Attestation entries (HSP.md §2.3, §4.3).
 *
 * Signing scheme (scheme-defined per §2.3.1, here for `evm-key` issuers): the issuer
 * EOA signs a structHash over the attestation fields. The verifier (CR2a) recovers
 * the signer and matches it to issuerKeyId, then to a deployment trust anchor (CR2b).
 * NOTE: HSP.md leaves the attestation signature scheme open; ATTESTATION_TYPEHASH is
 * an implementation choice (a candidate baseline `evm-key` scheme), NOT a spec-pinned
 * hash — so it is intentionally not in guard.ts.
 */

import { keccak256, stringToBytes, encodeAbiParameters, type Hex, type Address } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { canonicalRefId, makeCap, type PartyRef, type Attestation } from '../core/index.js';
import { KYC_SCHEMA_ID, SANCTIONS_SCHEMA_ID, RISK_SCORE_SCHEMA_ID, ATTESTATION_SCHEMAS } from './schemas.js';

const ZERO32: Hex = `0x${'00'.repeat(32)}`;

export const ATTESTATION_TYPEHASH: Hex = keccak256(
  stringToBytes(
    'Attestation(bytes32 capabilityId,bytes32 schemaId,bytes32 claimsHash,bytes32 issuer,bytes32 issuerKeyId,bytes32 subjectBinding,bytes32 contextBinding,uint64 issuedAt,uint64 expiresAt)',
  ),
);

export type UnsignedAttestation = Omit<Attestation, 'issuerSignature'>;

/** structHash the issuer signs (and the verifier recomputes for CR2a). */
export function attestationStructHash(a: UnsignedAttestation): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'bytes32' }, // ATTESTATION_TYPEHASH
        { type: 'bytes32' }, // capabilityId
        { type: 'bytes32' }, // schemaId
        { type: 'bytes32' }, // claimsHash
        { type: 'bytes32' }, // issuer (canonicalRefId)
        { type: 'bytes32' }, // issuerKeyId
        { type: 'bytes32' }, // subjectBinding (canonicalRefId)
        { type: 'bytes32' }, // contextBinding
        { type: 'uint64' }, // issuedAt
        { type: 'uint64' }, // expiresAt
      ],
      [
        ATTESTATION_TYPEHASH,
        a.capabilityId,
        a.schemaId,
        keccak256(a.claims),
        canonicalRefId(a.issuer),
        a.issuerKeyId,
        canonicalRefId(a.subjectBinding),
        a.contextBinding,
        BigInt(a.issuedAt),
        BigInt(a.expiresAt),
      ],
    ),
  );
}

/** `evm-address` PartyRef for an issuer EOA. */
export function evmIssuerPartyRef(address: Address): PartyRef {
  return { scheme: 'evm-address', id: encodeAbiParameters([{ type: 'address' }], [address]) };
}

/** Deterministic issuerKeyId fingerprint for an evm-key issuer (the verifier recomputes from the recovered signer). */
export function evmIssuerKeyId(address: Address): Hex {
  return keccak256(encodeAbiParameters([{ type: 'address' }], [address]));
}

export async function signAttestation(unsigned: UnsignedAttestation, issuerPrivateKey: Hex): Promise<Attestation> {
  const issuerSignature = await privateKeyToAccount(issuerPrivateKey).sign({ hash: attestationStructHash(unsigned) });
  return { ...unsigned, issuerSignature };
}

export interface IssueArgs {
  issuerPrivateKey: Hex;
  subject: PartyRef;
  issuedAt: number;
  expiresAt: number; // 0 ⇔ no expiry
  contextBinding?: Hex; // default bytes32(0) — subject-scoped
}

async function issue(
  schemaId: Hex,
  capKey: string,
  capParams: Record<string, string>,
  claimsParams: Record<string, string>,
  args: IssueArgs,
): Promise<Attestation> {
  const acct = privateKeyToAccount(args.issuerPrivateKey);
  const cap = makeCap(capKey, capParams); // attestation carries the BASE cap (role binding is via subjectBinding)
  const claims = ATTESTATION_SCHEMAS[schemaId]!.encodeClaims(claimsParams);
  const unsigned: UnsignedAttestation = {
    capabilityId: cap.baseId,
    schemaId,
    claims,
    issuer: evmIssuerPartyRef(acct.address),
    issuerKeyId: evmIssuerKeyId(acct.address),
    subjectBinding: args.subject,
    contextBinding: args.contextBinding ?? ZERO32,
    issuedAt: args.issuedAt,
    expiresAt: args.expiresAt,
  };
  return signAttestation(unsigned, args.issuerPrivateKey);
}

export function issueKyc(args: IssueArgs & { level: 'basic' | 'full' }): Promise<Attestation> {
  return issue(KYC_SCHEMA_ID, 'attests:kyc:v1', { level: args.level }, { level: args.level }, args);
}

export function issueSanctions(args: IssueArgs): Promise<Attestation> {
  return issue(SANCTIONS_SCHEMA_ID, 'attests:sanctions:v1', {}, {}, args);
}

export function issueRiskScore(args: IssueArgs & { maxScore: number | bigint }): Promise<Attestation> {
  const ms = args.maxScore.toString();
  return issue(RISK_SCORE_SCHEMA_ID, 'attests:risk-score:v1', { maxScore: ms }, { maxScore: ms }, args);
}
