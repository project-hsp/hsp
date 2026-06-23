/**
 * Adapter descriptor — deployment-facing metadata for one (adapterId, proofSchemaId)
 * pairing. `settlementModel` pins WHO broadcasts the value movement as a property
 * of the ADAPTER, not of the Coordinator:
 *
 *  - 'wallet-settling': the payer's own wallet settles; the operator only OBSERVES.
 *    (evm-transfer: the schema enforces Transfer.from == body.signer, so nobody
 *    but the mandate signer can be the settling party.)
 *  - 'self-settling': the adapter operator broadcasts the settlement itself
 *    (e.g. an x402 Facilitator, HSP-bindings §2 — future A2). No observe step.
 *
 * The Coordinator branches on this field; adding a self-settling adapter later
 * slots in here without reworking the service.
 */

import type { Address, Hex, PublicClient } from 'viem';
import type { AdapterProofSchema } from '../verifier/contracts.js';
import type { Receipt } from '../core/index.js';
import {
  evmTransferSchema,
  buildAndSignReceipt,
  EVM_TRANSFER_ADAPTER_ID,
  EVM_TRANSFER_PROOF_SCHEMA_ID,
  type BuildReceiptArgs,
  type TransferObservation,
} from './mock-evm-transfer.js';
import { observeTransfer } from './evm-transfer-live.js';

export type SettlementModel = 'wallet-settling' | 'self-settling';

export type ObservationClient = Pick<PublicClient, 'getTransactionReceipt'>;

export interface AdapterDescriptor<TObservation = unknown, TBuildArgs = unknown, TObserveParams = unknown> {
  adapterId: Hex;
  proofSchemaId: Hex;
  settlementModel: SettlementModel;
  schema: AdapterProofSchema;
  buildReceipt: (args: TBuildArgs) => Promise<Receipt>;
  /** wallet-settling adapters observe the chain; self-settling adapters omit this. */
  observe?: (client: ObservationClient, params: TObserveParams) => Promise<TObservation>;
}

export type EvmTransferObserveParams = { txHash: Hex; token: Address; chainId: number };

/** The MVP public adapter: direct ERC-20 transfer, payer-wallet settled. */
export const evmTransferDescriptor: AdapterDescriptor<TransferObservation, BuildReceiptArgs, EvmTransferObserveParams> = {
  adapterId: EVM_TRANSFER_ADAPTER_ID,
  proofSchemaId: EVM_TRANSFER_PROOF_SCHEMA_ID,
  settlementModel: 'wallet-settling',
  schema: evmTransferSchema,
  buildReceipt: buildAndSignReceipt,
  observe: observeTransfer,
};
