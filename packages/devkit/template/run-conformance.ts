/**
 * Run the conformance suite against YOUR adapter:
 *   npm run template -w @hsp/devkit          (or: npx tsx template/run-conformance.ts)
 * Adjust happyCase/observationReuseCase to exercise your proof shape.
 */

import { keccak256, stringToBytes } from 'viem';
import { runAdapterConformance, makeSignedMandate, type ConformanceCtx, type HappyCase } from '../src/conformance.js';
import { myAdapterSchema, buildAndSignMyReceipt, MY_ADAPTER_ID, MY_PROOF_SCHEMA_ID, type MyObservation } from './my-adapter.js';

function observation(ctx: ConformanceCtx, txTag: string): MyObservation {
  return {
    from: ctx.payer,
    to: ctx.recipient,
    token: ctx.token,
    value: ctx.amount,
    chainId: ctx.chainId,
    txHash: keccak256(stringToBytes(txTag)),
    memo: 'hello hsp',
  };
}

async function happyFor(ctx: ConformanceCtx, txTag: string, nonceTag: string): Promise<HappyCase> {
  const { mandate, mandateHash } = await makeSignedMandate(ctx, { nonce: keccak256(stringToBytes(nonceTag)) });
  const receipt = await buildAndSignMyReceipt({
    domain: ctx.domain,
    mandateHash,
    observation: observation(ctx, txTag),
    adapterPrivateKey: ctx.adapterPk,
    settledAt: ctx.evaluationTime - 10,
  });
  return { mandate, receipt };
}

async function main(): Promise<void> {
  const { failed } = await runAdapterConformance({
    name: 'adapter:my-adapter (template)',
    adapterId: MY_ADAPTER_ID,
    proofSchemaId: MY_PROOF_SCHEMA_ID,
    schema: myAdapterSchema,
    happyCase: (ctx) => happyFor(ctx, 'my-tx-1', 'my-happy'),
    observationReuseCase: async (ctx) => ({
      first: await happyFor(ctx, 'my-shared-tx', 'my-reuse-a'),
      second: await happyFor(ctx, 'my-shared-tx', 'my-reuse-b'),
    }),
  });
  process.exit(failed === 0 ? 0 : 1);
}

void main();
