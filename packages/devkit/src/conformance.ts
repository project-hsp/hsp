/**
 * Adapter conformance runner — point it at YOUR AdapterProofSchema + a function
 * that produces one valid (mandate, receipt) pair, and it runs the protocol's
 * generic obligations against the real HSP verifier:
 *
 *   1. happy case                         → ACCEPT
 *   2. forged adapterSignature            → HSP-RCPT-SIG
 *   3. adapter instance not in trust set  → HSP-RCPT-SIG (POLICY)
 *   4. broken mandate linkage             → HSP-RCPT-LINK
 *   5. replayed receipt (same seq)        → HSP-RCPT-SEQ-STALE
 *   6. settled after the mandate deadline → HSP-MAND-EXPIRED
 *   7. post-SETTLED non-DISPUTED emission → HSP-RCPT-OUTCOME-INCONSISTENT
 *   8. DISPUTED without a prior SETTLED   → HSP-RCPT-DISPUTE-NOPRIOR
 *   9. observationId report (wallet-settling adapters MUST emit one)
 *  10. (optional) observation reuse across two mandates → HSP-RCPT-OBS-REUSED
 *
 * Mutated receipts are RE-SIGNED with the adapter key, so what fails is the
 * protocol rule under test — never a stale signature.
 */

import { encodeAbiParameters, keccak256, stringToBytes, getAddress, type Address, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  mandateHash as computeMandateHash,
  receiptHash as computeReceiptHash,
  requiredCapabilitiesHash,
  buildCapabilityRegistry,
  Outcome,
  type DomainInput,
  type MandateBody,
  type SignedMandate,
  type Receipt,
  type ReceiptInput,
  type ParsedCapability,
  type OutcomeValue,
} from '@hsp/core';
import { eip712EoaSigner, signMandateHash, evmAddressPartyRef } from '@hsp/core/profiles/signer/eip712-eoa';
import { verify, SeqIndex, ObservationIndex } from '@hsp/core/verifier/index';
import {
  adapterKey,
  schemaKey,
  type AdapterProofSchema,
  type AdapterTrustRoots,
  type ReorgPolicy,
  type VerificationPolicy,
  type VerifyContext,
} from '@hsp/core/verifier/contracts';

const ZERO32: Hex = `0x${'00'.repeat(32)}`;

/** Fixed, public test fixtures (anvil default keys — not secrets). */
export interface ConformanceCtx {
  domain: DomainInput;
  chainId: number;
  payerPk: Hex;
  payer: Address;
  adapterPk: Hex;
  adapterAddress: Address;
  recipient: Address;
  token: Address;
  amount: bigint;
  deadline: number;
  evaluationTime: number;
}

export interface HappyCase {
  mandate: SignedMandate;
  receipt: Receipt;
}

export interface AdapterConformanceSuite {
  name: string;
  adapterId: Hex;
  proofSchemaId: Hex;
  schema: AdapterProofSchema;
  adapterInstanceKey?: Hex;
  /** static upper bound on proofSatisfiedCapabilities (your registration). */
  allowedCapabilities?: Hex[];
  /** caps to register in the policy (required caps your happy mandate declares). */
  registryCaps?: ParsedCapability[];
  trustRoots?: AdapterTrustRoots;
  reorgPolicy?: ReorgPolicy;
  /** Produce ONE valid SETTLED (mandate, receipt) pair using the ctx fixtures. */
  happyCase(ctx: ConformanceCtx): Promise<HappyCase>;
  /** Optional: the SAME settlement observation consumed by TWO different mandates. */
  observationReuseCase?(ctx: ConformanceCtx): Promise<{ first: HappyCase; second: HappyCase }>;
  /** Optional adapter-specific negatives. */
  tampers?: {
    label: string;
    expect: { ok: boolean; errorCode?: string; outcomeClass?: string };
    make(ctx: ConformanceCtx, happy: HappyCase): Promise<HappyCase>;
  }[];
}

export function defaultCtx(): ConformanceCtx {
  const payerPk: Hex = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // anvil acct0
  const adapterPk: Hex = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'; // anvil acct2
  const chainId = 31337;
  const verifyingContract = getAddress('0x0000000000000000000000000000000000000001');
  return {
    domain: { name: 'HSP', version: '1', chainId, verifyingContract },
    chainId,
    payerPk,
    payer: privateKeyToAccount(payerPk).address,
    adapterPk,
    adapterAddress: privateKeyToAccount(adapterPk).address,
    recipient: getAddress('0x70997970c51812dc3a010c7d01b50e0d17dc79c8'), // anvil acct1
    token: getAddress('0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'),
    amount: 9_990_000n,
    deadline: 2_000_000_000,
    evaluationTime: 1_800_000_000,
  };
}

/** Build + sign a mandate from the ctx fixtures (override any body field). */
export async function makeSignedMandate(
  ctx: ConformanceCtx,
  over: Partial<MandateBody> = {},
  caps: Hex[] = [],
): Promise<{ mandate: SignedMandate; mandateHash: Hex }> {
  const body: MandateBody = {
    nonce: keccak256(stringToBytes(`devkit-${Math.abs(JSON.stringify(over).length * 7919 + caps.length)}`)),
    signer: { profileId: eip712EoaSigner.profileIdHash, payload: encodeAbiParameters([{ type: 'address' }], [ctx.payer]) },
    recipient: { kind: 0, payload: encodeAbiParameters([{ type: 'address' }], [ctx.recipient]) },
    token: ctx.token,
    amount: ctx.amount.toString(),
    chainId: ctx.chainId,
    deadline: ctx.deadline,
    requiredCapabilitiesHash: requiredCapabilitiesHash(caps),
    ...over,
  };
  const mh = computeMandateHash(ctx.domain, body);
  const signerProof = await signMandateHash(ctx.payerPk, mh);
  return { mandate: { body, signerProof, requiredCapabilities: caps }, mandateHash: mh };
}

/** Mutate receipt fields, then RE-SIGN with the adapter key (valid-signature mutant). */
export async function resignReceipt(ctx: ConformanceCtx, receipt: Receipt, mutate: Partial<ReceiptInput>): Promise<Receipt> {
  const core: ReceiptInput = {
    mandateHash: receipt.mandateHash,
    adapterId: receipt.adapterId,
    adapterInstanceKey: receipt.adapterInstanceKey,
    seq: receipt.seq,
    outcome: receipt.outcome,
    settledAt: receipt.settledAt,
    proofSchemaId: receipt.proofSchemaId,
    adapterProof: receipt.adapterProof,
    ...mutate,
  };
  const rHash = computeReceiptHash(ctx.domain, core);
  const adapterSignature = await privateKeyToAccount(ctx.adapterPk).sign({ hash: rHash });
  return { ...core, adapterSignature };
}

function policyFor(suite: AdapterConformanceSuite, ctx: ConformanceCtx, opts: { dropTrust?: boolean } = {}): VerificationPolicy {
  const instanceKey = suite.adapterInstanceKey ?? ZERO32;
  const reorg: ReorgPolicy = suite.reorgPolicy ?? { allowsAttempted: true, chainObservation: 'required', disputeWindowMs: 30_000 };
  return {
    verifyingContract: ctx.domain.verifyingContract as Address,
    acceptedVerifyingContracts: new Set([String(ctx.domain.verifyingContract).toLowerCase()]),
    signerProfiles: new Map([[eip712EoaSigner.profileIdHash, { profile: eip712EoaSigner }]]),
    adapterTrust: opts.dropTrust
      ? new Map()
      : new Map([[adapterKey(suite.adapterId, instanceKey), { address: ctx.adapterAddress, reorgPolicy: reorg }]]),
    proofSchemas: new Map([
      [
        schemaKey(suite.adapterId, suite.proofSchemaId),
        { schema: suite.schema, allowedCapabilities: suite.allowedCapabilities ?? [], admission: 'accept-new' as const, trustRoots: suite.trustRoots ?? {} },
      ],
    ]),
    capabilityRegistry: buildCapabilityRegistry(suite.registryCaps ?? []),
    issuerTrustAnchors: new Map(),
    contextBindingScope: new Map(),
    evaluationTime: ctx.evaluationTime,
  };
}

export interface ConformanceResult {
  passed: number;
  failed: number;
}

export async function runAdapterConformance(suite: AdapterConformanceSuite, ctx: ConformanceCtx = defaultCtx()): Promise<ConformanceResult> {
  let passed = 0;
  let failed = 0;
  const check = (label: string, got: { ok: boolean; errorCode?: string; outcomeClass?: string }, want: { ok: boolean; errorCode?: string; outcomeClass?: string }): void => {
    const okM = got.ok === want.ok;
    const codeM = want.errorCode === undefined || got.errorCode === want.errorCode;
    const clsM = want.outcomeClass === undefined || got.outcomeClass === want.outcomeClass;
    if (okM && codeM && clsM) {
      passed++;
      console.log(`  ok   ${label}  →  ${got.outcomeClass ?? ''}${got.errorCode ? ' ' + got.errorCode : ''}`);
    } else {
      failed++;
      console.error(`  FAIL ${label}\n    got:  ${JSON.stringify(got)}\n    want: ${JSON.stringify(want)}`);
    }
  };

  console.log(`adapter conformance: ${suite.name}`);
  const happy = await suite.happyCase(ctx);
  if (Number(happy.receipt.outcome) !== Outcome.SETTLED) {
    console.error('  FAIL precondition: happyCase must return a SETTLED receipt');
    return { passed, failed: failed + 1 };
  }

  // 1 — happy
  check('happy case accepts', await verify(happy.mandate, happy.receipt, [], policyFor(suite, ctx), new SeqIndex()), { ok: true, outcomeClass: 'ACCEPT' });

  // 2 — forged adapter signature (flip the last signature byte)
  {
    const sig = happy.receipt.adapterSignature;
    const last = sig.slice(-2);
    const flipped = (parseInt(last, 16) ^ 0x01).toString(16).padStart(2, '0');
    const forged: Receipt = { ...happy.receipt, adapterSignature: (sig.slice(0, -2) + flipped) as Hex };
    check('forged adapterSignature rejected', await verify(happy.mandate, forged, [], policyFor(suite, ctx), new SeqIndex()), { ok: false, errorCode: 'HSP-RCPT-SIG' });
  }

  // 3 — adapter instance not in the trust set
  check('untrusted adapter instance rejected (POLICY)', await verify(happy.mandate, happy.receipt, [], policyFor(suite, ctx, { dropTrust: true }), new SeqIndex()), {
    ok: false,
    errorCode: 'HSP-RCPT-SIG',
    outcomeClass: 'POLICY',
  });

  // 4 — broken linkage (receipt re-signed over a different mandateHash)
  {
    const unlinked = await resignReceipt(ctx, happy.receipt, { mandateHash: keccak256(stringToBytes('devkit-other-mandate')) });
    check('broken mandate linkage rejected', await verify(happy.mandate, unlinked, [], policyFor(suite, ctx), new SeqIndex()), { ok: false, errorCode: 'HSP-RCPT-LINK' });
  }

  // 5 — replay (same receipt, shared index)
  {
    const idx = new SeqIndex();
    await verify(happy.mandate, happy.receipt, [], policyFor(suite, ctx), idx);
    check('replayed receipt rejected (stale seq)', await verify(happy.mandate, happy.receipt, [], policyFor(suite, ctx), idx), { ok: false, errorCode: 'HSP-RCPT-SEQ-STALE' });
  }

  // 6 — settled after the mandate deadline
  {
    const late = await resignReceipt(ctx, happy.receipt, { settledAt: ctx.deadline + 5 });
    check('settled-after-deadline rejected', await verify(happy.mandate, late, [], policyFor(suite, ctx), new SeqIndex()), { ok: false, errorCode: 'HSP-MAND-EXPIRED' });
  }

  // 7 — post-SETTLED non-DISPUTED successor
  {
    const idx = new SeqIndex();
    await verify(happy.mandate, happy.receipt, [], policyFor(suite, ctx), idx);
    const successor = await resignReceipt(ctx, happy.receipt, { seq: Number(happy.receipt.seq) + 1, settledAt: Number(happy.receipt.settledAt) + 1 });
    check('post-SETTLED non-DISPUTED rejected', await verify(happy.mandate, successor, [], policyFor(suite, ctx), idx), { ok: false, errorCode: 'HSP-RCPT-OUTCOME-INCONSISTENT' });
  }

  // 8 — DISPUTED without a prior SETTLED
  {
    const disputed = await resignReceipt(ctx, happy.receipt, { outcome: Outcome.DISPUTED as OutcomeValue });
    check('DISPUTED without prior SETTLED rejected', await verify(happy.mandate, disputed, [], policyFor(suite, ctx), new SeqIndex()), { ok: false, errorCode: 'HSP-RCPT-DISPUTE-NOPRIOR' });
  }

  // 9 — observationId report (informative but counted: wallet-settling adapters MUST emit one)
  {
    const vctx: VerifyContext = {
      proofBytes: happy.receipt.adapterProof,
      body: happy.mandate.body,
      mandateHash: happy.receipt.mandateHash,
      signerSubject: evmAddressPartyRef(ctx.payer),
      receipt: (({ adapterProof: _p, ...header }) => header)(happy.receipt),
      now: ctx.evaluationTime,
      trustRoots: suite.trustRoots ?? {},
    };
    const out = await suite.schema.verify(vctx);
    if (out.ok && out.observationId) {
      passed++;
      console.log(`  ok   schema emits observationId (${out.observationId.slice(0, 14)}…) — observation-consumption protected`);
    } else if (out.ok) {
      passed++;
      console.log('  ok   schema emits NO observationId — fine ONLY if your settlement artifact is cryptographically bound to mandateHash (x402-style); otherwise one transfer could settle two mandates');
    } else {
      failed++;
      console.error('  FAIL schema.verify rejected the happy proof when called directly', out.errorCode);
    }
  }

  // 10 — optional: observation reuse across two mandates
  if (suite.observationReuseCase) {
    const { first, second } = await suite.observationReuseCase(ctx);
    const seqIdx = new SeqIndex();
    const obsIdx = new ObservationIndex();
    await verify(first.mandate, first.receipt, [], policyFor(suite, ctx), seqIdx, obsIdx);
    check('same observation for a second mandate rejected', await verify(second.mandate, second.receipt, [], policyFor(suite, ctx), seqIdx, obsIdx), {
      ok: false,
      errorCode: 'HSP-RCPT-OBS-REUSED',
    });
  }

  // 11 — adapter-specific tampers
  for (const t of suite.tampers ?? []) {
    const tampered = await t.make(ctx, happy);
    check(t.label, await verify(tampered.mandate, tampered.receipt, [], policyFor(suite, ctx), new SeqIndex()), t.expect);
  }

  console.log(`\n${suite.name} conformance: ${passed} passed, ${failed} failed`);
  return { passed, failed };
}
