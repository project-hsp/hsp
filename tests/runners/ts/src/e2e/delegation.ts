/**
 * Delegation e2e — REAL anvil settlement from a smart-account Principal.
 *
 * Alice (a MockERC1271Account smart account, owner = Alice's EOA) delegates to an Agent
 * (a separate EOA). The Agent signs the PaymentExecution; Alice signs the DelegationGrant
 * (verified ON-CHAIN via the account's isValidSignature); Alice's account executes the
 * ERC-20 transfer so the settlement `Transfer.from` is the ACCOUNT (the Principal). The
 * Verifier resolves payer = the smart account, binds the sender to accountOf(principal),
 * and ACCEPTs. Negative cases exercise the agent-match and grant-signature checks.
 *
 * Self-contained: `npx tsx src/e2e/delegation.ts` (needs anvil on PATH).
 * Keys are PUBLIC anvil defaults: funder=acct0, alice=acct1, adapter=acct2, agent=acct3.
 */

import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createPublicClient,
  createWalletClient,
  http,
  getAddress,
  encodeAbiParameters,
  encodeFunctionData,
  keccak256,
  stringToBytes,
  type Abi,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { anvil } from 'viem/chains';
import {
  executionHash as computeMandateHash,
  grantHash as computeGrantHash,
  requiredCapabilitiesHash,
  type SignedExecution,
  type SignedDelegationGrant,
  type PaymentExecution,
  type DelegationGrantInput,
  type DomainInput,
} from '@hsp/core';
import { eip712EoaSigner, signMandateHash } from '@hsp/core/profiles/signer/eip712-eoa';
import { createErc1271Signer, type Erc1271ReadClient } from '@hsp/core/profiles/signer/erc1271';
import { adapterKey, schemaKey, type VerificationPolicy } from '@hsp/core/verifier/contracts';
import { verify, verifyPhaseA, SeqIndex, ObservationIndex } from '@hsp/core/verifier/index';
import {
  evmTransferSchema,
  buildAndSignReceipt,
  EVM_TRANSFER_ADAPTER_ID,
  EVM_TRANSFER_PROOF_SCHEMA_ID,
} from '@hsp/core/adapter/mock-evm-transfer';
import { observeTransfer } from '@hsp/core/adapter/evm-transfer-live';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../../../../../contracts/out');
const ERC20 = JSON.parse(readFileSync(path.join(ROOT, 'MockERC20.sol/MockERC20.json'), 'utf8')) as { abi: Abi; bytecode: { object: Hex } };
const ACCOUNT = JSON.parse(readFileSync(path.join(ROOT, 'MockERC1271Account.sol/MockERC1271Account.json'), 'utf8')) as { abi: Abi; bytecode: { object: Hex } };

const FUNDER_PK: Hex = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // acct0
const ALICE_PK: Hex = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'; // acct1 — account owner (Principal)
const ADAPTER_PK: Hex = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'; // acct2
const AGENT_PK: Hex = '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6'; // acct3 — delegated signer
const OTHER_PK: Hex = '0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a'; // acct4 — impostor agent
const BOB: Address = getAddress('0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc'); // acct5 — recipient
const VERIFYING_CONTRACT: Address = getAddress('0x0000000000000000000000000000000000000001');
const ZERO32: Hex = `0x${'00'.repeat(32)}`;
const AMOUNT = 1_000_000n;
const DEADLINE = 2_000_000_000;
const EVAL_TIME = 1_800_000_000;
const SETTLED_AT = 1_799_999_900;

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

let passed = 0;
let failed = 0;
function check(name: string, cond: boolean): void {
  if (cond) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.error(`  FAIL ${name}`);
  }
}

async function main(): Promise<void> {
  const anvilProc = spawn('anvil', ['--silent'], { stdio: 'ignore' });
  try {
    const funder = privateKeyToAccount(FUNDER_PK);
    const alice = privateKeyToAccount(ALICE_PK);
    const agent = privateKeyToAccount(AGENT_PK);
    const adapterAcct = privateKeyToAccount(ADAPTER_PK);
    const transport = http('http://127.0.0.1:8545');
    const publicClient = createPublicClient({ chain: anvil, transport });
    const funderWallet = createWalletClient({ account: funder, chain: anvil, transport });
    const aliceWallet = createWalletClient({ account: alice, chain: anvil, transport });

    let up = false;
    for (let i = 0; i < 80; i++) {
      try { await publicClient.getBlockNumber(); up = true; break; } catch { await sleep(150); }
    }
    if (!up) throw new Error('anvil did not become ready');
    const chainId = await publicClient.getChainId();

    // deploy MockERC20 (funder holds supply) + Alice's MockERC1271Account (owner = alice EOA)
    const tokenHash = await funderWallet.deployContract({ abi: ERC20.abi, bytecode: ERC20.bytecode.object, args: [AMOUNT * 10n, funder.address] });
    const token = getAddress((await publicClient.waitForTransactionReceipt({ hash: tokenHash })).contractAddress as Address);
    const acctHash = await funderWallet.deployContract({ abi: ACCOUNT.abi, bytecode: ACCOUNT.bytecode.object, args: [alice.address] });
    const account = getAddress((await publicClient.waitForTransactionReceipt({ hash: acctHash })).contractAddress as Address);

    // fund the smart account so it can pay Bob
    const fundTx = await funderWallet.writeContract({ address: token, abi: ERC20.abi, functionName: 'transfer', args: [account, AMOUNT * 2n] });
    await publicClient.waitForTransactionReceipt({ hash: fundTx });

    const domain: DomainInput = { name: 'HSP', version: '1', chainId, verifyingContract: VERIFYING_CONTRACT };
    const erc1271 = createErc1271Signer((cid) => (cid === chainId ? (publicClient as unknown as Erc1271ReadClient) : undefined));

    // Alice's grant: principal = the smart account (erc1271), agent = the EOA
    const grantBody: DelegationGrantInput = {
      principal: { profileId: erc1271.profileIdHash, payload: encodeAbiParameters([{ type: 'address' }, { type: 'uint256' }], [account, BigInt(chainId)]) },
      agent: { profileId: eip712EoaSigner.profileIdHash, payload: encodeAbiParameters([{ type: 'address' }], [agent.address]) },
      onchainPermissionRef: ZERO32,
      payerRequiredCaps: [],
      payerAllowedCaps: [],
      notBefore: 0,
      expiry: DEADLINE,
      nonce: keccak256(stringToBytes('delegation-grant-1')),
    };
    const gHash = computeGrantHash(domain, grantBody);
    const principalProof = await signMandateHash(ALICE_PK, gHash); // Alice (owner) signs; account.isValidSignature validates
    const signedGrant: SignedDelegationGrant = { body: grantBody, principalProof };

    // The Agent signs a PaymentExecution referencing the grant
    const body: PaymentExecution = {
      nonce: keccak256(stringToBytes('delegation-exec-1')),
      signer: { profileId: eip712EoaSigner.profileIdHash, payload: encodeAbiParameters([{ type: 'address' }], [agent.address]) },
      grantRef: gHash,
      requirementRef: ZERO32,
      recipient: { kind: 0, payload: encodeAbiParameters([{ type: 'address' }], [BOB]) },
      token,
      amount: AMOUNT.toString(),
      chainId,
      deadline: DEADLINE,
      settlementBinding: ZERO32,
      requiredCapabilitiesHash: requiredCapabilitiesHash([]),
    };
    const mh = computeMandateHash(domain, body);
    const signerProof = await signMandateHash(AGENT_PK, mh);
    const mandate: SignedExecution = { body, signerProof, requiredCapabilities: [] };

    // Alice's account executes the transfer → Transfer.from = the account (the Principal)
    const transferData = encodeFunctionData({ abi: ERC20.abi, functionName: 'transfer', args: [BOB, AMOUNT] });
    const settleTx = await aliceWallet.writeContract({ address: account, abi: ACCOUNT.abi, functionName: 'execute', args: [token, transferData] });
    await publicClient.waitForTransactionReceipt({ hash: settleTx });
    const observation = await observeTransfer(publicClient, { txHash: settleTx, token, chainId });
    check('settlement Transfer.from == the smart account', getAddress(observation.from) === account);

    const receipt = await buildAndSignReceipt({ domain, executionHash: mh, observation, adapterPrivateKey: ADAPTER_PK, settledAt: SETTLED_AT });

    const policy: VerificationPolicy = {
      verifyingContract: VERIFYING_CONTRACT,
      acceptedVerifyingContracts: new Set([VERIFYING_CONTRACT.toLowerCase()]),
      signerProfiles: new Map([
        [eip712EoaSigner.profileIdHash, { profile: eip712EoaSigner }],
        [erc1271.profileIdHash, { profile: erc1271 }],
      ]),
      adapterTrust: new Map([
        [adapterKey(EVM_TRANSFER_ADAPTER_ID, ZERO32), { address: adapterAcct.address, reorgPolicy: { allowsAttempted: true, chainObservation: 'required', disputeWindowMs: 30_000 } }],
      ]),
      proofSchemas: new Map([
        [schemaKey(EVM_TRANSFER_ADAPTER_ID, EVM_TRANSFER_PROOF_SCHEMA_ID), { schema: evmTransferSchema, allowedCapabilities: [], admission: 'accept-new', trustRoots: {} }],
      ]),
      capabilityRegistry: new Map(),
      issuerTrustAnchors: new Map(),
      contextBindingScope: new Map(),
      evaluationTime: EVAL_TIME,
    };

    // 1 — full delegated payment → ACCEPT
    const decision = await verify(mandate, receipt, [], policy, new SeqIndex(), new ObservationIndex(), signedGrant);
    check('delegated payment → ACCEPT', decision.ok && decision.outcomeClass === 'ACCEPT');

    // 2 — payer resolves to the smart-account Principal (not the agent)
    const a = await verifyPhaseA(mandate, policy, signedGrant);
    check('payer = the smart-account Principal', a.ok && a.result.roleAssignment.payer?.scheme === 'smart-account');

    // 3 — without the grant, the verifier cannot resolve the delegation → reject
    const noGrant = await verify(mandate, receipt, [], policy, new SeqIndex(), new ObservationIndex());
    check('missing grant → HSP-GRANT-SIGNER', !noGrant.ok && noGrant.errorCode === 'HSP-GRANT-SIGNER');

    // 4 — an impostor agent signs the same execution terms → agent mismatch
    const other = privateKeyToAccount(OTHER_PK);
    const impostorBody: PaymentExecution = { ...body, signer: { profileId: eip712EoaSigner.profileIdHash, payload: encodeAbiParameters([{ type: 'address' }], [other.address]) } };
    const impostorMh = computeMandateHash(domain, impostorBody);
    const impostorMandate: SignedExecution = { body: impostorBody, signerProof: await signMandateHash(OTHER_PK, impostorMh), requiredCapabilities: [] };
    const impostorReceipt = await buildAndSignReceipt({ domain, executionHash: impostorMh, observation, adapterPrivateKey: ADAPTER_PK, settledAt: SETTLED_AT });
    const impostor = await verify(impostorMandate, impostorReceipt, [], policy, new SeqIndex(), new ObservationIndex(), signedGrant);
    check('impostor agent → HSP-GRANT-AGENT-MISMATCH', !impostor.ok && impostor.errorCode === 'HSP-GRANT-AGENT-MISMATCH');

    // 5 — a forged grant signature (signed by the agent, not the owner) fails on-chain isValidSignature
    const forgedGrant: SignedDelegationGrant = { body: grantBody, principalProof: await signMandateHash(AGENT_PK, gHash) };
    const forged = await verify(mandate, receipt, [], policy, new SeqIndex(), new ObservationIndex(), forgedGrant);
    check('forged grant signature → HSP-GRANT-SIGNER', !forged.ok && forged.errorCode === 'HSP-GRANT-SIGNER');

    console.log(`\nDELEGATION E2E: ${passed} passed, ${failed} failed`);
  } finally {
    anvilProc.kill('SIGTERM');
  }
  process.exit(failed === 0 ? 0 : 1);
}

void main();
