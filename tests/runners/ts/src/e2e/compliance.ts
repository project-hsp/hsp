/**
 * M2 end-to-end — compliance (attestation) layer over a public settlement.
 *
 * A full-compliance deployment mandates role[payer, attests:kyc:v1[level=full]] +
 * role[payer, attests:sanctions:v1]. The settlement is the same public ERC-20
 * transfer (mock); the Attestation Operator pre-populates the wire-borne
 * Attestation[]. Exercises §5.2 step 5 (walk + CR2 + §3.3.3 monotone via the (b)
 * structured-claims path) + §5.1 step 3b. Run: `npx tsx src/e2e/compliance.ts`.
 *
 * Keys (PUBLIC anvil defaults): payer=acct0, adapter=acct2, issuer=acct3, untrusted=acct4, recipient=acct1.
 */

import { encodeAbiParameters, keccak256, stringToBytes, getAddress, type Hex, type Address } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  mandateHash as computeMandateHash,
  requiredCapabilitiesHash,
  makeCap,
  familyCapId,
  buildCapabilityRegistry,
  Roles,
  type SignedMandate,
  type MandateBody,
  type DomainInput,
  type ParsedCapability,
  type Attestation,
} from '@hsp/core';
import { eip712EoaSigner, signMandateHash, evmAddressPartyRef } from '@hsp/core/profiles/signer/eip712-eoa';
import { adapterKey, schemaKey, type VerificationPolicy, type AcceptDecision, type TrustAnchor } from '@hsp/core/verifier/contracts';
import { verify, SeqIndex } from '@hsp/core/verifier/index';
import {
  evmTransferSchema,
  buildAndSignReceipt,
  EVM_TRANSFER_ADAPTER_ID,
  EVM_TRANSFER_PROOF_SCHEMA_ID,
  type TransferObservation,
} from '@hsp/core/adapter/mock-evm-transfer';
import { issueKyc, issueSanctions, issueRiskScore, evmIssuerKeyId } from '@hsp/core/attestation/issuer';
import { KYC_SCHEMA_ID, SANCTIONS_SCHEMA_ID, RISK_SCORE_SCHEMA_ID } from '@hsp/core/attestation/schemas';

const PAYER_PK: Hex = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // acct0
const ADAPTER_PK: Hex = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'; // acct2
const ISSUER_PK: Hex = '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6'; // acct3 (trusted)
const UNTRUSTED_PK: Hex = '0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a'; // acct4
const ZERO32: Hex = `0x${'00'.repeat(32)}`;

const payer = privateKeyToAccount(PAYER_PK);
const adapter = privateKeyToAccount(ADAPTER_PK);
const issuer = privateKeyToAccount(ISSUER_PK);
const RECIPIENT: Address = getAddress('0x70997970c51812dc3a010c7d01b50e0d17dc79c8'); // acct1
const TOKEN: Address = getAddress('0x833589fcd6edb6e08f4c7c32d4f71b54bda02913');
const VERIFYING_CONTRACT: Address = getAddress('0x0000000000000000000000000000000000000001');
const CHAIN_ID = 8453;
const DEADLINE = 2_000_000_000;
const EVAL_TIME = 1_800_000_000;
const AMOUNT = 9_990_000n;

const domain: DomainInput = { name: 'HSP', version: '1', chainId: CHAIN_ID, verifyingContract: VERIFYING_CONTRACT };
const payerSubject = evmAddressPartyRef(payer.address);

// required (role-wrapped) caps
const kycFull = makeCap('attests:kyc:v1', { level: 'full' }, Roles.payer);
const kycBasic = makeCap('attests:kyc:v1', { level: 'basic' }, Roles.payer);
const sanctions = makeCap('attests:sanctions:v1', {}, Roles.payer);
const risk50 = makeCap('attests:risk-score:v1', { maxScore: '50' }, Roles.payer);

async function buildMandate(reqCaps: ParsedCapability[], nonceTag: string): Promise<{ mandate: SignedMandate; mandateHash: Hex }> {
  const ids = reqCaps.map((c) => c.id);
  const body: MandateBody = {
    nonce: keccak256(stringToBytes(`m2-${nonceTag}`)),
    signer: { profileId: eip712EoaSigner.profileIdHash, payload: encodeAbiParameters([{ type: 'address' }], [payer.address]) },
    recipient: { kind: 0, payload: encodeAbiParameters([{ type: 'address' }], [RECIPIENT]) },
    token: TOKEN,
    amount: AMOUNT.toString(),
    chainId: CHAIN_ID,
    deadline: DEADLINE,
    requiredCapabilitiesHash: requiredCapabilitiesHash(ids),
  };
  const mh = computeMandateHash(domain, body);
  const signerProof = await signMandateHash(PAYER_PK, mh);
  return { mandate: { body, signerProof, requiredCapabilities: ids }, mandateHash: mh };
}

function observation(): TransferObservation {
  return { from: payer.address, to: RECIPIENT, token: TOKEN, value: AMOUNT, chainId: CHAIN_ID, txHash: keccak256(stringToBytes('tx-m2')), blockNumber: 100n };
}

const issuerAnchor = (schemaId: Hex): TrustAnchor => ({ scheme: 'evm-key', identifier: evmIssuerKeyId(issuer.address), acceptedSchemaIds: [schemaId] });

function compliancePolicy(reqCaps: ParsedCapability[], over: Partial<VerificationPolicy> = {}): VerificationPolicy {
  return {
    verifyingContract: VERIFYING_CONTRACT,
    acceptedVerifyingContracts: new Set([VERIFYING_CONTRACT.toLowerCase()]),
    signerProfiles: new Map([[eip712EoaSigner.profileIdHash, { profile: eip712EoaSigner }]]),
    adapterTrust: new Map([
      [adapterKey(EVM_TRANSFER_ADAPTER_ID, ZERO32), { address: adapter.address, reorgPolicy: { allowsAttempted: true, chainObservation: 'required', disputeWindowMs: 30_000 } }],
    ]),
    proofSchemas: new Map([
      [schemaKey(EVM_TRANSFER_ADAPTER_ID, EVM_TRANSFER_PROOF_SCHEMA_ID), { schema: evmTransferSchema, allowedCapabilities: [], admission: 'accept-new', trustRoots: {} }],
    ]),
    capabilityRegistry: buildCapabilityRegistry(reqCaps),
    issuerTrustAnchors: new Map<Hex, TrustAnchor[]>([
      [familyCapId('attests:kyc:v1'), [issuerAnchor(KYC_SCHEMA_ID)]],
      [familyCapId('attests:sanctions:v1'), [issuerAnchor(SANCTIONS_SCHEMA_ID)]],
      [familyCapId('attests:risk-score:v1'), [issuerAnchor(RISK_SCORE_SCHEMA_ID)]],
    ]),
    policyRequiredCapabilities: reqCaps.map((c) => c.id),
    contextBindingScope: new Map(),
    evaluationTime: EVAL_TIME,
    ...over,
  };
}

const T = { issuedAt: EVAL_TIME - 1000, expiresAt: EVAL_TIME + 100_000 };

let pass = 0;
let fail = 0;
function check(label: string, d: AcceptDecision, want: { ok: boolean; outcomeClass?: string; errorCode?: string }): void {
  const okM = d.ok === want.ok;
  const clsM = want.outcomeClass === undefined || d.outcomeClass === want.outcomeClass;
  const codeM = want.errorCode === undefined || d.errorCode === want.errorCode;
  if (okM && clsM && codeM) {
    pass++;
    console.log(`PASS  ${label}  →  ${d.outcomeClass}${d.errorCode ? ' ' + d.errorCode : ''}`);
  } else {
    fail++;
    console.error(`FAIL  ${label}\n  got:  ${JSON.stringify(d)}\n  want: ${JSON.stringify(want)}`);
  }
}

async function runCase(
  label: string,
  reqCaps: ParsedCapability[],
  attestations: Attestation[],
  want: { ok: boolean; outcomeClass?: string; errorCode?: string },
  policyOver: Partial<VerificationPolicy> = {},
): Promise<void> {
  const { mandate, mandateHash } = await buildMandate(reqCaps, label.replace(/\s+/g, '-'));
  const receipt = await buildAndSignReceipt({ domain, mandateHash, observation: observation(), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 10 });
  check(label, await verify(mandate, receipt, attestations, compliancePolicy(reqCaps, policyOver), new SeqIndex()), want);
}

async function main(): Promise<void> {
  const kycFullAtt = await issueKyc({ issuerPrivateKey: ISSUER_PK, subject: payerSubject, level: 'full', ...T });
  const kycFullUntrusted = await issueKyc({ issuerPrivateKey: UNTRUSTED_PK, subject: payerSubject, level: 'full', ...T });
  const kycFullExpired = await issueKyc({ issuerPrivateKey: ISSUER_PK, subject: payerSubject, level: 'full', issuedAt: EVAL_TIME - 1000, expiresAt: EVAL_TIME - 1 });
  const kycFullWrongSubject = await issueKyc({ issuerPrivateKey: ISSUER_PK, subject: evmAddressPartyRef(RECIPIENT), level: 'full', ...T });
  const sanctionsAtt = await issueSanctions({ issuerPrivateKey: ISSUER_PK, subject: payerSubject, ...T });
  const risk10 = await issueRiskScore({ issuerPrivateKey: ISSUER_PK, subject: payerSubject, maxScore: 10, ...T });
  const risk80 = await issueRiskScore({ issuerPrivateKey: ISSUER_PK, subject: payerSubject, maxScore: 80, ...T });

  // 1 — happy: kyc[full] + sanctions, trusted, correct subject
  await runCase('kyc full + sanctions', [kycFull, sanctions], [kycFullAtt, sanctionsAtt], { ok: true, outcomeClass: 'ACCEPT' });

  // 2 — monotone enum: required kyc[basic] satisfied by kyc[full] attestation
  await runCase('monotone kyc full satisfies basic', [kycBasic, sanctions], [kycFullAtt, sanctionsAtt], { ok: true, outcomeClass: 'ACCEPT' });

  // 3 — monotone numeric: required risk maxScore=50 satisfied by maxScore=10
  await runCase('monotone risk 10 satisfies 50', [risk50, sanctions], [risk10, sanctionsAtt], { ok: true, outcomeClass: 'ACCEPT' });

  // 4 — monotone numeric fails: maxScore=80 does NOT satisfy required 50
  await runCase('risk 80 does not satisfy 50', [risk50, sanctions], [risk80, sanctionsAtt], { ok: false, outcomeClass: 'RETRYABLE', errorCode: 'HSP-ATT-MISSING' });

  // 5 — untrusted issuer for kyc
  await runCase('untrusted kyc issuer', [kycFull, sanctions], [kycFullUntrusted, sanctionsAtt], { ok: false, outcomeClass: 'RETRYABLE', errorCode: 'HSP-ATT-ISSUER-UNTRUSTED' });

  // 6 — expired kyc attestation
  await runCase('expired kyc', [kycFull, sanctions], [kycFullExpired, sanctionsAtt], { ok: false, outcomeClass: 'RETRYABLE', errorCode: 'HSP-ATT-INVALID' });

  // 7 — wrong subject (bound to recipient, not payer)
  await runCase('wrong subject', [kycFull, sanctions], [kycFullWrongSubject, sanctionsAtt], { ok: false, outcomeClass: 'RETRYABLE', errorCode: 'HSP-ATT-INVALID' });

  // 8 — missing kyc (only sanctions provided)
  await runCase('missing kyc attestation', [kycFull, sanctions], [sanctionsAtt], { ok: false, outcomeClass: 'RETRYABLE', errorCode: 'HSP-ATT-MISSING' });

  // 9 — §5.1 step 3b: mandate fails to declare a mandated capability
  await runCase(
    'mandated cap not declared',
    [sanctions],
    [sanctionsAtt],
    { ok: false, outcomeClass: 'POLICY', errorCode: 'HSP-MAND-REQ-INSUFFICIENT' },
    { policyRequiredCapabilities: [kycFull.id, sanctions.id], capabilityRegistry: buildCapabilityRegistry([kycFull, sanctions]) },
  );

  console.log(`\nM2 compliance e2e: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

void main();
