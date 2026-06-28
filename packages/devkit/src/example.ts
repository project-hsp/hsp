/**
 * Worked example + CI gate: run the conformance suite against the reference
 * evm-transfer adapter. All checks must pass — proving both the adapter and the
 * runner. `npm run example -w @hsp/devkit`
 */

import { keccak256, stringToBytes } from 'viem';
import {
  evmTransferSchema,
  buildAndSignReceipt,
  EVM_TRANSFER_ADAPTER_ID,
  EVM_TRANSFER_PROOF_SCHEMA_ID,
  type TransferObservation,
} from '@hsp/core/adapter/mock-evm-transfer';
import { runAdapterConformance, makeSignedExecution, defaultCtx, type ConformanceCtx, type HappyCase } from './conformance.js';

function observation(ctx: ConformanceCtx, txTag: string): TransferObservation {
  return {
    from: ctx.payer,
    to: ctx.recipient,
    token: ctx.token,
    value: ctx.amount,
    chainId: ctx.chainId,
    txHash: keccak256(stringToBytes(txTag)),
    blockNumber: 100n,
  };
}

async function happyFor(ctx: ConformanceCtx, txTag: string, nonceTag: string): Promise<HappyCase> {
  const { mandate, executionHash } = await makeSignedExecution(ctx, { nonce: keccak256(stringToBytes(nonceTag)) });
  const receipt = await buildAndSignReceipt({
    domain: ctx.domain,
    executionHash,
    observation: observation(ctx, txTag),
    adapterPrivateKey: ctx.adapterPk,
    settledAt: ctx.evaluationTime - 10,
  });
  return { mandate, receipt };
}

async function main(): Promise<void> {
  const { failed } = await runAdapterConformance({
    name: 'adapter:evm-transfer (reference)',
    adapterId: EVM_TRANSFER_ADAPTER_ID,
    proofSchemaId: EVM_TRANSFER_PROOF_SCHEMA_ID,
    schema: evmTransferSchema,
    happyCase: (ctx) => happyFor(ctx, 'devkit-tx-1', 'devkit-happy'),
    observationReuseCase: async (ctx) => ({
      first: await happyFor(ctx, 'devkit-shared-tx', 'devkit-reuse-a'),
      second: await happyFor(ctx, 'devkit-shared-tx', 'devkit-reuse-b'),
    }),
  });
  process.exit(failed === 0 ? 0 : 1);
}

void main();
