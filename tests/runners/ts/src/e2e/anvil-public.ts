/**
 * M1 walking skeleton — REAL anvil settlement.
 *
 * Spawns anvil, deploys MockERC20, the payer makes a real ERC-20 transfer, the
 * adapter scrapes the real Transfer log → observation → signed Receipt, and the
 * Verifier runs the full §5.1+§5.2 pipeline → ACCEPT. Self-contained: `npx tsx
 * src/e2e/anvil-public.ts` (needs foundry's anvil on PATH + network to localhost).
 *
 * Keys are PUBLIC anvil defaults: payer=acct0 (funded), adapter=acct2, recipient=acct1.
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
  keccak256,
  stringToBytes,
  type Abi,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { anvil } from 'viem/chains';
import {
  mandateHash as computeMandateHash,
  requiredCapabilitiesHash,
  type SignedMandate,
  type Mandate,
  type DomainInput,
} from '@hsp/core';
import { eip712EoaSigner, signMandateHash } from '@hsp/core/profiles/signer/eip712-eoa';
import { adapterKey, schemaKey, type VerificationPolicy } from '@hsp/core/verifier/contracts';
import { BASELINE_CAP_FAMILIES } from '@hsp/core/core/capabilities';
import { verify, SeqIndex } from '@hsp/core/verifier/index';
import {
  evmTransferSchema,
  buildAndSignReceipt,
  EVM_TRANSFER_ADAPTER_ID,
  EVM_TRANSFER_PROOF_SCHEMA_ID,
} from '@hsp/core/adapter/mock-evm-transfer';
import { observeTransfer } from '@hsp/core/adapter/evm-transfer-live';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ARTIFACT = path.resolve(__dirname, '../../../../../contracts/out/MockERC20.sol/MockERC20.json');

const PAYER_PK: Hex = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // acct0 (funded)
const ADAPTER_PK: Hex = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a'; // acct2
const RECIPIENT: Address = getAddress('0x70997970c51812dc3a010c7d01b50e0d17dc79c8'); // acct1
const VERIFYING_CONTRACT: Address = getAddress('0x0000000000000000000000000000000000000001');
const ZERO32: Hex = `0x${'00'.repeat(32)}`;
const AMOUNT = 1_000_000n;
const DEADLINE = 2_000_000_000;
const EVAL_TIME = 1_800_000_000;
const SETTLED_AT = 1_799_999_900;

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function main(): Promise<void> {
  const anvilProc = spawn('anvil', ['--silent'], { stdio: 'ignore' });
  let okExit = false;
  try {
    const payer = privateKeyToAccount(PAYER_PK);
    const adapterAcct = privateKeyToAccount(ADAPTER_PK);
    const transport = http('http://127.0.0.1:8545');
    const publicClient = createPublicClient({ chain: anvil, transport });
    const wallet = createWalletClient({ account: payer, chain: anvil, transport });

    // wait for anvil to accept RPC
    let up = false;
    for (let i = 0; i < 80; i++) {
      try {
        await publicClient.getBlockNumber();
        up = true;
        break;
      } catch {
        await sleep(150);
      }
    }
    if (!up) throw new Error('anvil did not become ready');
    const chainId = await publicClient.getChainId();

    // deploy MockERC20(initialSupply, payer)
    const artifact = JSON.parse(readFileSync(ARTIFACT, 'utf8')) as { abi: Abi; bytecode: { object: Hex } };
    const abi = artifact.abi;
    const deployHash = await wallet.deployContract({
      abi,
      bytecode: artifact.bytecode.object,
      args: [AMOUNT * 10n, payer.address],
    });
    const deployRcpt = await publicClient.waitForTransactionReceipt({ hash: deployHash });
    const token = getAddress(deployRcpt.contractAddress as Address);

    // payer makes a real ERC-20 transfer to RECIPIENT
    const txHash = await wallet.writeContract({ address: token, abi, functionName: 'transfer', args: [RECIPIENT, AMOUNT] });
    await publicClient.waitForTransactionReceipt({ hash: txHash });

    // adapter observes the real Transfer log → signed Receipt
    const observation = await observeTransfer(publicClient, { txHash, token, chainId });
    const domain: DomainInput = { name: 'HSP', version: '1', chainId, verifyingContract: VERIFYING_CONTRACT };

    const body: Mandate = {
      nonce: keccak256(stringToBytes('anvil-public-1')),
      signer: { profileId: eip712EoaSigner.profileIdHash, payload: encodeAbiParameters([{ type: 'address' }], [payer.address]) },
      recipient: { kind: 0, payload: encodeAbiParameters([{ type: 'address' }], [RECIPIENT]) },
      token,
      amount: AMOUNT.toString(),
      chainId,
      deadline: DEADLINE,
      requiredCapabilitiesHash: requiredCapabilitiesHash([]),
    };
    const mh = computeMandateHash(domain, body);
    const signerProof = await signMandateHash(PAYER_PK, mh);
    const mandate: SignedMandate = {
      body,
      signerProof,
      requiredCapabilities: [],
    };

    const receipt = await buildAndSignReceipt({ domain, mandateHash: mh, observation, adapterPrivateKey: ADAPTER_PK, settledAt: SETTLED_AT });

    const policy: VerificationPolicy = {
      verifyingContract: VERIFYING_CONTRACT,
      acceptedVerifyingContracts: new Set([VERIFYING_CONTRACT.toLowerCase()]),
      signerProfiles: new Map([[eip712EoaSigner.profileIdHash, { profile: eip712EoaSigner }]]),
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

    const decision = await verify(mandate, receipt, [], policy, new SeqIndex());

    console.log(`anvil chainId=${chainId}  token=${token}`);
    console.log(`observed Transfer: ${observation.from} -> ${observation.to}  value=${observation.value} (block ${observation.blockNumber})`);
    console.log(`decision: ${JSON.stringify(decision)}`);
    if (decision.ok && decision.outcomeClass === 'ACCEPT') {
      console.log('\nANVIL PUBLIC E2E: PASS');
      okExit = true;
    } else {
      console.error('\nANVIL PUBLIC E2E: FAIL');
    }
  } finally {
    anvilProc.kill('SIGTERM');
  }
  process.exit(okExit ? 0 : 1);
}

void main();
