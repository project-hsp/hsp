/**
 * M1 end-to-end — public (trivial) payment over the mock EVM-transfer adapter.
 *
 * Builds + signs a public-payment SignedExecution, has the Adapter Operator emit a
 * signed Receipt for an observed ERC-20 Transfer, runs the full Verifier (§5.1+§5.2),
 * and asserts ACCEPT plus a spread of negative cases (each pinned to its §8.0 class +
 * §8 code). Runnable: `npx tsx src/e2e/public.ts`. No foundry — the Transfer
 * observation is supplied directly; the real anvil wiring lands behind the dep gate.
 *
 * Test keys are the PUBLIC, well-known anvil default keys — not secrets.
 */

import { encodeAbiParameters, keccak256, stringToBytes, getAddress, type Hex, type Address } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  executionHash as computeMandateHash,
  requiredCapabilitiesHash,
  makeCap,
  Outcome,
  type SignedExecution,
  type PaymentExecution,
  type DomainInput,
} from '@hsp/core';
import { eip712EoaSigner, signMandateHash } from '@hsp/core/profiles/signer/eip712-eoa';
import { adapterKey, schemaKey, type VerificationPolicy, type AcceptDecision } from '@hsp/core/verifier/contracts';
import { BASELINE_CAP_FAMILIES } from '@hsp/core/core/capabilities';
import { verify, SeqIndex, ObservationIndex } from '@hsp/core/verifier/index';
import {
  evmTransferSchema,
  buildAndSignReceipt,
  EVM_TRANSFER_ADAPTER_ID,
  EVM_TRANSFER_PROOF_SCHEMA_ID,
  type TransferObservation,
} from '@hsp/core/adapter/mock-evm-transfer';

// anvil default keys (PUBLIC test vectors, not secrets)
// payer = anvil acct0, adapter = anvil acct2, RECIPIENT = anvil acct1 — three distinct roles.
const PAYER_PK: Hex = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const ADAPTER_PK: Hex = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a';
const ZERO32: Hex = `0x${'00'.repeat(32)}`;

const payer = privateKeyToAccount(PAYER_PK);
const adapter = privateKeyToAccount(ADAPTER_PK);
const RECIPIENT: Address = getAddress('0x70997970c51812dc3a010c7d01b50e0d17dc79c8');
const TOKEN: Address = getAddress('0x833589fcd6edb6e08f4c7c32d4f71b54bda02913');
const VERIFYING_CONTRACT: Address = getAddress('0x0000000000000000000000000000000000000001');
const CHAIN_ID = 8453;
const DEADLINE = 2_000_000_000;
const EVAL_TIME = 1_800_000_000;
const AMOUNT = 9_990_000n;

const domain: DomainInput = { name: 'HSP', version: '1', chainId: CHAIN_ID, verifyingContract: VERIFYING_CONTRACT };

function buildBody(over: Partial<PaymentExecution> = {}): PaymentExecution {
  return {
    nonce: keccak256(stringToBytes('m1-public-1')),
    signer: {
      profileId: eip712EoaSigner.profileIdHash,
      payload: encodeAbiParameters([{ type: 'address' }], [payer.address]),
    },
    recipient: { kind: 0, payload: encodeAbiParameters([{ type: 'address' }], [RECIPIENT]) },
    token: TOKEN,
    amount: AMOUNT.toString(),
    chainId: CHAIN_ID,
    deadline: DEADLINE,
    requiredCapabilitiesHash: requiredCapabilitiesHash([]),
    ...over,
  };
}

async function signedMandate(body: PaymentExecution, reqCaps: Hex[] = [], signWith: Hex = PAYER_PK): Promise<SignedExecution> {
  const mh = computeMandateHash(domain, body);
  const signerProof = await signMandateHash(signWith, mh);
  return {
    body,
    signerProof,
    requiredCapabilities: reqCaps,
  };
}

function basePolicy(over: Partial<VerificationPolicy> = {}): VerificationPolicy {
  return {
    verifyingContract: VERIFYING_CONTRACT,
    acceptedVerifyingContracts: new Set([VERIFYING_CONTRACT.toLowerCase()]),
    signerProfiles: new Map([[eip712EoaSigner.profileIdHash, { profile: eip712EoaSigner }]]),
    adapterTrust: new Map([
      [
        adapterKey(EVM_TRANSFER_ADAPTER_ID, ZERO32),
        { address: adapter.address, reorgPolicy: { allowsAttempted: true, chainObservation: 'required', disputeWindowMs: 30_000 } },
      ],
    ]),
    proofSchemas: new Map([
      [
        schemaKey(EVM_TRANSFER_ADAPTER_ID, EVM_TRANSFER_PROOF_SCHEMA_ID),
        { schema: evmTransferSchema, allowedCapabilities: [], admission: 'accept-new', trustRoots: {} },
      ],
    ]),
    capabilityRegistry: new Map(),
    issuerTrustAnchors: new Map(),
    contextBindingScope: new Map(),
    evaluationTime: EVAL_TIME,
    ...over,
  };
}

function observation(over: Partial<TransferObservation> = {}): TransferObservation {
  return {
    from: payer.address,
    to: RECIPIENT,
    token: TOKEN,
    value: AMOUNT,
    chainId: CHAIN_ID,
    txHash: keccak256(stringToBytes('tx-1')),
    blockNumber: 100n,
    ...over,
  };
}

let pass = 0;
let fail = 0;
async function check(
  label: string,
  decision: AcceptDecision,
  want: { ok: boolean; outcomeClass?: string; errorCode?: string },
): Promise<void> {
  const okMatch = decision.ok === want.ok;
  const clsMatch = want.outcomeClass === undefined || decision.outcomeClass === want.outcomeClass;
  const codeMatch = want.errorCode === undefined || decision.errorCode === want.errorCode;
  if (okMatch && clsMatch && codeMatch) {
    pass++;
    console.log(`PASS  ${label}  →  ${decision.outcomeClass}${decision.errorCode ? ' ' + decision.errorCode : ''}`);
  } else {
    fail++;
    console.error(`FAIL  ${label}\n  got:  ${JSON.stringify(decision)}\n  want: ${JSON.stringify(want)}`);
  }
}

async function main(): Promise<void> {
  // 1 — happy path → ACCEPT
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 10 });
    await check('public payment settles', await verify(m, r, [], basePolicy(), new SeqIndex()), { ok: true, outcomeClass: 'ACCEPT' });
  }

  // 2 — deadline anchors to settledAt (§5.2 step 7), not evaluationTime
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    // (a) an on-time settlement stays verifiable AFTER the deadline
    const rOk = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME });
    await check('late verification of on-time settlement', await verify(m, rOk, [], basePolicy({ evaluationTime: DEADLINE + 1 }), new SeqIndex()), {
      ok: true, outcomeClass: 'ACCEPT',
    });
    // (b) settlement after the deadline is expired — whenever it is verified
    const rLate = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, settledAt: DEADLINE + 5 });
    await check('settled after deadline', await verify(m, rLate, [], basePolicy({ evaluationTime: DEADLINE + 100 }), new SeqIndex()), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-MAND-EXPIRED',
    });
  }

  // 3 — bad signer proof (signed by adapter key, not payer)
  {
    const body = buildBody();
    const m = await signedMandate(body, [], ADAPTER_PK);
    const mh = computeMandateHash(domain, body);
    const r = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 10 });
    await check('wrong signer key', await verify(m, r, [], basePolicy(), new SeqIndex()), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-MAND-SIGNER',
    });
  }

  // 3b — malleated signature: same logical sig re-encoded as (r, n−s, v′) → §4.1.6 low-s strictness.
  // Without the strictness check this recovers the same address and would ACCEPT.
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const rHex = m.signerProof.slice(2, 66);
    const s = BigInt(`0x${m.signerProof.slice(66, 130)}`);
    const v = parseInt(m.signerProof.slice(130, 132), 16);
    const sPrime = (SECP256K1_N - s).toString(16).padStart(64, '0');
    const vPrime = (v === 27 ? 28 : 27).toString(16).padStart(2, '0');
    const malleated: SignedExecution = { ...m, signerProof: `0x${rHex}${sPrime}${vPrime}` as Hex };
    const mh = computeMandateHash(domain, body);
    const rcpt = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 10 });
    await check('high-s malleated signature rejected', await verify(malleated, rcpt, [], basePolicy(), new SeqIndex()), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-MAND-SIGNER',
    });
  }

  // 4 — unknown signer profile (POLICY)
  {
    const body = buildBody({
      signer: { profileId: keccak256(stringToBytes('unknown-signer.v1')), payload: encodeAbiParameters([{ type: 'address' }], [payer.address]) },
    });
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 10 });
    await check('unknown signer profile', await verify(m, r, [], basePolicy(), new SeqIndex()), {
      ok: false, outcomeClass: 'POLICY', errorCode: 'HSP-MAND-SIGNER-PROFILE-UNKNOWN',
    });
  }

  // 5 — requiredCapabilitiesHash mismatch (envelope caps inconsistent with signed hash)
  {
    const body = buildBody(); // requiredCapabilitiesHash = hash([])
    const m = await signedMandate(body, [makeCap('hides:amount:v1').id]); // envelope claims a cap
    const mh = computeMandateHash(domain, body);
    const r = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 10 });
    await check('reqcaps hash mismatch', await verify(m, r, [], basePolicy(), new SeqIndex()), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-MAND-REQHASH-MISMATCH',
    });
  }

  // 6 — adapter instance not trusted (POLICY)
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 10 });
    await check('untrusted adapter', await verify(m, r, [], basePolicy({ adapterTrust: new Map() }), new SeqIndex()), {
      ok: false, outcomeClass: 'POLICY', errorCode: 'HSP-RCPT-SIG',
    });
  }

  // 7 — adapter signature by wrong key (PERMANENT)
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: PAYER_PK, settledAt: EVAL_TIME - 10 });
    await check('adapter sig wrong key', await verify(m, r, [], basePolicy(), new SeqIndex()), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-RCPT-SIG',
    });
  }

  // 8 — amount mismatch
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation({ value: AMOUNT + 1n }), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 10 });
    await check('amount mismatch', await verify(m, r, [], basePolicy(), new SeqIndex()), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-MAND-AMOUNT-OUTOFBOUNDS',
    });
  }

  // 9 — signer↔sender binding (observed from != signer)
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation({ from: RECIPIENT }), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 10 });
    await check('sender binding mismatch', await verify(m, r, [], basePolicy(), new SeqIndex()), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-RCPT-PROOF',
    });
  }

  // 10 — recipient mismatch
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation({ to: adapter.address }), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 10 });
    await check('recipient mismatch', await verify(m, r, [], basePolicy(), new SeqIndex()), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-RCPT-PROOF',
    });
  }

  // 10b — COMMITMENT mandate over a plain-transfer schema: no binding claim → rejected
  // (schema fails closed on COMMITMENT; the §5.2 step 4 verifier row rejects independently)
  {
    const body = buildBody({
      recipient: {
        kind: 1, // RecipientKind.COMMITMENT
        payload: encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32' }], [keccak256(stringToBytes('some-commitment')), keccak256(stringToBytes('some-ctx'))]),
      },
    });
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 10 });
    await check('commitment mandate over plain transfer rejected', await verify(m, r, [], basePolicy(), new SeqIndex()), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-RCPT-PROOF',
    });
  }

  // 11 — ATTEMPTED (non-terminal) → RETRYABLE
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, outcome: Outcome.ATTEMPTED, settledAt: EVAL_TIME - 10 });
    await check('attempted is retryable', await verify(m, r, [], basePolicy(), new SeqIndex()), { ok: true, outcomeClass: 'RETRYABLE' });
  }

  // 12 — ATTEMPTED but reorgPolicy disallows it (POLICY)
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, outcome: Outcome.ATTEMPTED, settledAt: EVAL_TIME - 10 });
    const policy = basePolicy({
      adapterTrust: new Map([
        [adapterKey(EVM_TRANSFER_ADAPTER_ID, ZERO32), { address: adapter.address, reorgPolicy: { allowsAttempted: false, chainObservation: 'required' } }],
      ]),
    });
    await check('attempted not allowed', await verify(m, r, [], policy, new SeqIndex()), {
      ok: false, outcomeClass: 'POLICY', errorCode: 'HSP-RCPT-OUTCOME-INCONSISTENT',
    });
  }

  // 13 — S4 equivocation: same (adapter, instance, mandate, seq) with different content
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const seqIndex = new SeqIndex();
    const r1 = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, seq: 0, settledAt: EVAL_TIME - 20 });
    await check('first settle (seq0)', await verify(m, r1, [], basePolicy(), seqIndex), { ok: true, outcomeClass: 'ACCEPT' });
    const r2 = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation({ txHash: keccak256(stringToBytes('tx-2')) }), adapterPrivateKey: ADAPTER_PK, seq: 0, settledAt: EVAL_TIME - 10 });
    await check('equivocation (seq0 conflict)', await verify(m, r2, [], basePolicy(), seqIndex), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-RCPT-EQUIVOCATION',
    });
  }

  // 14 — sequencing: a lower seq arriving after a higher one is stale (S2)
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const seqIndex = new SeqIndex();
    const r1 = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, seq: 1, settledAt: EVAL_TIME - 20 });
    await check('settle at seq1', await verify(m, r1, [], basePolicy(), seqIndex), { ok: true, outcomeClass: 'ACCEPT' });
    const r2 = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation(), adapterPrivateKey: ADAPTER_PK, seq: 0, outcome: Outcome.ATTEMPTED, settledAt: EVAL_TIME - 10 });
    await check('lower seq is stale', await verify(m, r2, [], basePolicy(), seqIndex), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-RCPT-SEQ-STALE',
    });
  }

  // 15 — successor matrix: SETTLED may be followed only by DISPUTED (§5.2 step 7)
  {
    const body = buildBody({ nonce: keccak256(stringToBytes('m1-succ')) });
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const seqIndex = new SeqIndex();
    const r1 = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation({ txHash: keccak256(stringToBytes('tx-succ-1')) }), adapterPrivateKey: ADAPTER_PK, seq: 0, settledAt: EVAL_TIME - 30 });
    await check('settles (seq0)', await verify(m, r1, [], basePolicy(), seqIndex), { ok: true, outcomeClass: 'ACCEPT' });
    const r2 = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation({ txHash: keccak256(stringToBytes('tx-succ-2')) }), adapterPrivateKey: ADAPTER_PK, seq: 1, settledAt: EVAL_TIME - 20 });
    await check('post-SETTLED SETTLED rejected', await verify(m, r2, [], basePolicy(), seqIndex), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-RCPT-OUTCOME-INCONSISTENT',
    });
  }

  // 16 — FAILED ends the attempt, not the stream: FAILED → SETTLED is admissible
  {
    const body = buildBody({ nonce: keccak256(stringToBytes('m1-retry')) });
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const seqIndex = new SeqIndex();
    const rF = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation({ txHash: keccak256(stringToBytes('tx-retry-fail')) }), adapterPrivateKey: ADAPTER_PK, seq: 0, outcome: Outcome.FAILED, settledAt: EVAL_TIME - 40 });
    await check('attempt fails (seq0)', await verify(m, rF, [], basePolicy(), seqIndex), { ok: true, outcomeClass: 'PERMANENT' });
    const rS = await buildAndSignReceipt({ domain, executionHash: mh, observation: observation({ txHash: keccak256(stringToBytes('tx-retry-ok')) }), adapterPrivateKey: ADAPTER_PK, seq: 1, settledAt: EVAL_TIME - 30 });
    await check('fresh attempt settles (seq1)', await verify(m, rS, [], basePolicy(), seqIndex), { ok: true, outcomeClass: 'ACCEPT' });
  }

  // 17 — observation reuse: one transfer cannot settle two different mandates
  {
    const obsIndex = new ObservationIndex();
    const seqIndex = new SeqIndex();
    const sharedTx = keccak256(stringToBytes('tx-shared'));
    const bodyA = buildBody({ nonce: keccak256(stringToBytes('m1-obsA')) });
    const bodyB = buildBody({ nonce: keccak256(stringToBytes('m1-obsB')) });
    const mA = await signedMandate(bodyA);
    const mB = await signedMandate(bodyB);
    const rA = await buildAndSignReceipt({ domain, executionHash: computeMandateHash(domain, bodyA), observation: observation({ txHash: sharedTx }), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 10 });
    await check('first mandate consumes the observation', await verify(mA, rA, [], basePolicy(), seqIndex, obsIndex), { ok: true, outcomeClass: 'ACCEPT' });
    const rB = await buildAndSignReceipt({ domain, executionHash: computeMandateHash(domain, bodyB), observation: observation({ txHash: sharedTx }), adapterPrivateKey: ADAPTER_PK, settledAt: EVAL_TIME - 5 });
    await check('second mandate, same observation → OBS-REUSED', await verify(mB, rB, [], basePolicy(), seqIndex, obsIndex), {
      ok: false, outcomeClass: 'PERMANENT', errorCode: 'HSP-RCPT-OBS-REUSED',
    });
  }

  console.log(`\nM1 public e2e: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

void main();
