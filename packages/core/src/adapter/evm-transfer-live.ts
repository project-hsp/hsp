/**
 * Live observation for the public EVM-transfer adapter: scrape a real ERC-20
 * Transfer log off a chain (anvil) and produce the TransferObservation the
 * AdapterProofSchema/receipt builder consume. The proof encoding + receipt signing
 * stay in mock-evm-transfer.ts — only the observation SOURCE differs (real chain
 * vs supplied). This is the §4.2.1 operator-signature trust baseline still (the
 * operator attests what it observed; trust-minimization is M4).
 */

import { decodeEventLog, parseAbiItem, type Address, type Hex, type PublicClient } from 'viem';
import type { TransferObservation } from './mock-evm-transfer.js';

const TRANSFER_EVENT = parseAbiItem('event Transfer(address indexed from, address indexed to, uint256 value)');

/**
 * Observe the SINGLE ERC-20 Transfer emitted by `token` in tx `txHash`.
 *
 * Exactly one matching log is required: proof schema v1 carries no logIndex, so a
 * multi-Transfer tx would make the observation ambiguous (and the Coordinator's
 * observation-dedup is keyed (chainId, token, txHash)). Rejected until a proof
 * schema v2 carries (logIndex, blockHash).
 */
export async function observeTransfer(
  client: Pick<PublicClient, 'getTransactionReceipt'>,
  params: { txHash: Hex; token: Address; chainId: number },
): Promise<TransferObservation> {
  const receipt = await client.getTransactionReceipt({ hash: params.txHash });
  const matches: { from: Address; to: Address; value: bigint }[] = [];
  for (const log of receipt.logs) {
    if (log.address.toLowerCase() !== params.token.toLowerCase()) continue;
    try {
      const decoded = decodeEventLog({ abi: [TRANSFER_EVENT], data: log.data, topics: log.topics });
      matches.push(decoded.args as { from: Address; to: Address; value: bigint });
    } catch {
      // not a Transfer log — keep scanning
    }
  }
  if (matches.length === 0) {
    throw new Error(`no Transfer log from ${params.token} in tx ${params.txHash}`);
  }
  if (matches.length > 1) {
    throw new Error(
      `ambiguous observation: ${matches.length} Transfer logs from ${params.token} in tx ${params.txHash} — ` +
        `proof schema v1 carries no logIndex; refusing to observe`,
    );
  }
  const { from, to, value } = matches[0]!;
  return {
    from,
    to,
    token: params.token,
    value,
    chainId: params.chainId,
    txHash: params.txHash,
    blockNumber: receipt.blockNumber,
  };
}
