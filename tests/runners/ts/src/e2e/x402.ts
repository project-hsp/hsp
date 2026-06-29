/**
 * x402 (machine payment, S3) end-to-end — the conformant-x402 `exact`-EVM v2 path.
 *
 * Self-settling: the payer signs BOTH the HSP mandate AND an EIP-3009
 * TransferWithAuthorization (token domain); a facilitator relays the transfer and
 * signs an `adapter:x402` v2 Receipt. Runs the full Verifier and asserts ACCEPT plus
 * the §4 binding-table negatives — proving the cryptographic payer-binding: even an
 * UNTRUSTED facilitator cannot forge the payer's authorization or alter from/to/
 * value/token (it can only assert the txHash).
 *
 * Runnable: `npx tsx src/e2e/x402.ts`. No facilitator/anvil — the EIP-3009 signature
 * is real (signed here); the settlement txHash is supplied directly.
 *
 * Test keys are PUBLIC, well-known anvil default keys — not secrets.
 */

import { encodeAbiParameters, keccak256, stringToBytes, getAddress, type Hex, type Address } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  mandateHash as computeMandateHash,
  requiredCapabilitiesHash,
  type SignedMandate,
  type Mandate,
  type Receipt,
  type DomainInput,
} from '@hsp/core';
import { eip712EoaSigner, signMandateHash } from '@hsp/core/profiles/signer/eip712-eoa';
import { adapterKey, schemaKey, type VerificationPolicy, type AcceptDecision } from '@hsp/core/verifier/contracts';
import { verify, SeqIndex } from '@hsp/core/verifier/index';
import {
  x402ExactSchema,
  buildAndSignX402ExactReceipt,
  X402_ADAPTER_ID,
  X402_EXACT_PROOF_SCHEMA_ID,
  type X402ExactProof,
} from '@hsp/core/adapter/x402-exact';

// anvil default keys (PUBLIC test vectors, not secrets)
const PAYER_PK: Hex = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // acct0
const FACILITATOR_PK: Hex = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'; // acct2
const IMPOSTOR_PK: Hex = '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6'; // acct3

const payer = privateKeyToAccount(PAYER_PK);
const facilitator = privateKeyToAccount(FACILITATOR_PK);
const MERCHANT: Address = getAddress('0x70997970c51812dc3a010c7d01b50e0d17dc79c8');
const TOKEN: Address = getAddress('0x833589fcd6edb6e08f4c7c32d4f71b54bda02913');
const OTHER_TOKEN: Address = getAddress('0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48');
const VERIFYING_CONTRACT: Address = getAddress('0x0000000000000000000000000000000000000001');
const CHAIN_ID = 8453;
const DEADLINE = 2_000_000_000;
const EVAL_TIME = 1_800_000_000;
const AMOUNT = 9_990_000n;
const TOKEN_NAME = 'MockUSDC';
const TOKEN_VERSION = '2';
const INSTANCE_KEY = keccak256(stringToBytes('merchant.example')); // == keccak256(merchantDomain)

const domain: DomainInput = { name: 'HSP', version: '1', chainId: CHAIN_ID, verifyingContract: VERIFYING_CONTRACT };

const EIP3009_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const;

function buildBody(over: Partial<Mandate> = {}): Mandate {
  return {
    nonce: keccak256(stringToBytes('x402-1')),
    signer: { profileId: eip712EoaSigner.profileIdHash, payload: encodeAbiParameters([{ type: 'address' }], [payer.address]) },
    recipient: { kind: 0, payload: encodeAbiParameters([{ type: 'address' }], [MERCHANT]) },
    token: TOKEN,
    amount: AMOUNT.toString(),
    chainId: CHAIN_ID,
    deadline: DEADLINE,
    requiredCapabilitiesHash: requiredCapabilitiesHash([]),
    ...over,
  };
}

async function signedMandate(body: Mandate): Promise<SignedMandate> {
  return { body, signerProof: await signMandateHash(PAYER_PK, computeMandateHash(domain, body)), requiredCapabilities: [] };
}

/** Build the X402ExactProof — the payer signs the EIP-3009 authorization under the TOKEN domain. */
async function signAuth(over: { from?: Address; to?: Address; value?: bigint; signWith?: Hex; token?: Address } = {}): Promise<X402ExactProof> {
  const from = over.from ?? payer.address;
  const to = over.to ?? MERCHANT;
  const value = over.value ?? AMOUNT;
  const token = over.token ?? TOKEN;
  const validAfter = 0;
  const validBefore = DEADLINE;
  const nonce = keccak256(stringToBytes('auth-nonce-1'));
  const signature = await privateKeyToAccount(over.signWith ?? PAYER_PK).signTypedData({
    domain: { name: TOKEN_NAME, version: TOKEN_VERSION, chainId: CHAIN_ID, verifyingContract: token },
    types: EIP3009_TYPES,
    primaryType: 'TransferWithAuthorization',
    message: { from, to, value, validAfter: BigInt(validAfter), validBefore: BigInt(validBefore), nonce },
  });
  return { from, to, value, validAfter, validBefore, nonce, signature, token, tokenName: TOKEN_NAME, tokenVersion: TOKEN_VERSION, chainId: CHAIN_ID, txHash: keccak256(stringToBytes('settle-tx-1')) };
}

function rcpt(mh: Hex, proof: X402ExactProof, adapterPrivateKey: Hex = FACILITATOR_PK): Promise<Receipt> {
  return buildAndSignX402ExactReceipt({ domain, mandateHash: mh, proof, adapterPrivateKey, adapterInstanceKey: INSTANCE_KEY, settledAt: EVAL_TIME - 10 });
}

function basePolicy(over: Partial<VerificationPolicy> = {}): VerificationPolicy {
  return {
    verifyingContract: VERIFYING_CONTRACT,
    acceptedVerifyingContracts: new Set([VERIFYING_CONTRACT.toLowerCase()]),
    signerProfiles: new Map([[eip712EoaSigner.profileIdHash, { profile: eip712EoaSigner }]]),
    adapterTrust: new Map([
      [adapterKey(X402_ADAPTER_ID, INSTANCE_KEY), { address: facilitator.address, reorgPolicy: { allowsAttempted: true, chainObservation: 'required', disputeWindowMs: 30_000 } }],
    ]),
    proofSchemas: new Map([
      [schemaKey(X402_ADAPTER_ID, X402_EXACT_PROOF_SCHEMA_ID), { schema: x402ExactSchema, allowedCapabilities: [], admission: 'accept-new', trustRoots: {} }],
    ]),
    capabilityRegistry: new Map(),
    issuerTrustAnchors: new Map(),
    contextBindingScope: new Map(),
    evaluationTime: EVAL_TIME,
    ...over,
  };
}

let pass = 0;
let fail = 0;
async function check(label: string, decision: AcceptDecision, want: { ok: boolean; outcomeClass?: string; errorCode?: string }): Promise<void> {
  const ok = decision.ok === want.ok && (want.outcomeClass === undefined || decision.outcomeClass === want.outcomeClass) && (want.errorCode === undefined || decision.errorCode === want.errorCode);
  if (ok) {
    pass++;
    console.log(`PASS  ${label}  →  ${decision.outcomeClass}${decision.errorCode ? ' ' + decision.errorCode : ''}`);
  } else {
    fail++;
    console.error(`FAIL  ${label}\n  got:  ${JSON.stringify(decision)}\n  want: ${JSON.stringify(want)}`);
  }
}

async function main(): Promise<void> {
  // 1 — happy path: payer-signed mandate + EIP-3009 auth, facilitator-signed receipt → ACCEPT
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await rcpt(mh, await signAuth());
    await check('x402 exact settles', await verify(m, r, [], basePolicy(), new SeqIndex()), { ok: true, outcomeClass: 'ACCEPT' });
  }
  // 2 — amount tamper: authorization.value ≠ mandate.amount → binding fail
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await rcpt(mh, await signAuth({ value: AMOUNT + 1n }));
    await check('amount mismatch', await verify(m, r, [], basePolicy(), new SeqIndex()), { ok: false, errorCode: 'HSP-RCPT-PROOF' });
  }
  // 3 — recipient tamper: authorization.to ≠ mandate.recipient → binding fail
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await rcpt(mh, await signAuth({ to: facilitator.address }));
    await check('recipient mismatch', await verify(m, r, [], basePolicy(), new SeqIndex()), { ok: false, errorCode: 'HSP-RCPT-PROOF' });
  }
  // 4 — forged authorization: from=payer but signed by an impostor → recovered ≠ from
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await rcpt(mh, await signAuth({ signWith: IMPOSTOR_PK }));
    await check('forged authorization signature', await verify(m, r, [], basePolicy(), new SeqIndex()), { ok: false, errorCode: 'HSP-RCPT-PROOF' });
  }
  // 5 — token tamper: authorization.token ≠ mandate.token → binding fail
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await rcpt(mh, await signAuth({ token: OTHER_TOKEN }));
    await check('token mismatch', await verify(m, r, [], basePolicy(), new SeqIndex()), { ok: false, errorCode: 'HSP-RCPT-PROOF' });
  }
  // 6 — untrusted facilitator: receipt signed by a non-trusted key → adapter-signature fail
  {
    const body = buildBody();
    const m = await signedMandate(body);
    const mh = computeMandateHash(domain, body);
    const r = await rcpt(mh, await signAuth(), IMPOSTOR_PK);
    await check('untrusted facilitator signature', await verify(m, r, [], basePolicy(), new SeqIndex()), { ok: false, errorCode: 'HSP-RCPT-SIG' });
  }

  console.log(`\nx402 e2e: ${pass} passed, ${fail} failed`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
