/**
 * Delegation helpers — build + settle delegated payments (HSP.md §2.1.1).
 *
 * A delegated payment has two signers and a smart-account Principal:
 *   - the PRINCIPAL (an erc1271 smart account) signs a DelegationGrant (signGrant, signer.ts)
 *   - the AGENT (an EOA) signs each Mandate with grantRef = grantHash
 *   - the Principal's ACCOUNT executes the ERC-20 transfer, so Transfer.from = the account
 *
 * `buildDelegationGrant` constructs the grant body; `AccountExecutor` abstracts the
 * "account executes the transfer" step. `erc1271OwnerExecutor` is the dev/demo executor
 * (owner broadcasts account.execute, mirroring the e2e + MockERC1271Account); production
 * supplies an ERC-4337 UserOp executor instead.
 */

import {
  createPublicClient,
  encodeAbiParameters,
  encodeFunctionData,
  http,
  parseAbi,
  toHex,
  type Address,
  type Hex,
} from 'viem';
import type { DelegationGrantInput } from '@hsp/core';
import { eip712EoaSigner } from '@hsp/core/profiles/signer/eip712-eoa';
import { createErc1271Signer } from '@hsp/core/profiles/signer/erc1271';
import { walletClientFor, type HSPSigner } from './signer.js';

const ZERO32 = `0x${'00'.repeat(32)}` as Hex;
// erc1271.v1 profileIdHash is a constant (keccak256("erc1271.v1")); read it off a
// no-client instance — buildDelegationGrant never verifies, so getClient is unused.
const ERC1271_PROFILE_ID_HASH = createErc1271Signer(() => undefined).profileIdHash;

export interface BuildDelegationGrantOpts {
  /** The smart-account Principal (erc1271) whose funds move. */
  account: Address;
  /** The delegated EOA signer (eip712-eoa) authorized to sign executions. */
  agent: Address;
  /** Settlement chain — pins the account's chain-scoped PartyRef. */
  chainId: number;
  /** payer-side FLOOR every execution under this grant MUST cover. */
  payerRequiredCaps?: Hex[];
  /** payer-side CEILING the Agent may declare. */
  payerAllowedCaps?: Hex[];
  notBefore?: number;
  /** Unix seconds; default now + 24h. */
  expiry?: number;
  nonce?: Hex;
  /** Commits the on-chain permission the account enforces (ERC-7715 / ERC-4337). */
  onchainPermissionRef?: Hex;
}

/** Build a DelegationGrant body (sign it with signGrant). */
export function buildDelegationGrant(opts: BuildDelegationGrantOpts): DelegationGrantInput {
  return {
    principal: {
      profileId: ERC1271_PROFILE_ID_HASH,
      payload: encodeAbiParameters([{ type: 'address' }, { type: 'uint256' }], [opts.account, BigInt(opts.chainId)]),
    },
    agent: {
      profileId: eip712EoaSigner.profileIdHash,
      payload: encodeAbiParameters([{ type: 'address' }], [opts.agent]),
    },
    onchainPermissionRef: opts.onchainPermissionRef ?? ZERO32,
    payerRequiredCaps: opts.payerRequiredCaps ?? [],
    payerAllowedCaps: opts.payerAllowedCaps ?? [],
    notBefore: opts.notBefore ?? 0,
    expiry: opts.expiry ?? Math.floor(Date.now() / 1000) + 86_400,
    nonce: opts.nonce ?? toHex(crypto.getRandomValues(new Uint8Array(32))),
  };
}

/**
 * Settles a delegated payment by making the Principal account move the funds, so the
 * on-chain `Transfer.from` is the account (which the verifier binds to accountOf(principal)).
 */
export interface AccountExecutor {
  execute(p: { account: Address; token: Address; to: Address; amount: bigint }): Promise<Hex>;
}

const ACCOUNT_EXECUTE_ABI = parseAbi(['function execute(address target, bytes data)']);
const ERC20_TRANSFER_ABI = parseAbi(['function transfer(address to, uint256 amount) returns (bool)']);

/**
 * Dev/demo executor: the account OWNER broadcasts `account.execute(token, transfer(to,amount))`
 * (the MockERC1271Account shape, owner-gated). Production replaces this with an ERC-4337
 * UserOp executor (the agent's session key drives the account, gas via a bundler).
 */
export function erc1271OwnerExecutor(owner: HSPSigner, rpcUrl: string, chainId: number): AccountExecutor {
  return {
    async execute({ account, token, to, amount }) {
      const wallet = walletClientFor(owner, rpcUrl, chainId);
      const acct = wallet.account;
      if (!acct) throw new Error('owner wallet has no account');
      const data = encodeFunctionData({ abi: ERC20_TRANSFER_ABI, functionName: 'transfer', args: [to, amount] });
      const txHash = await wallet.writeContract({
        address: account,
        abi: ACCOUNT_EXECUTE_ABI,
        functionName: 'execute',
        args: [token, data],
        account: acct,
        chain: wallet.chain,
      });
      const publicClient = createPublicClient({ transport: http(rpcUrl) });
      await publicClient.waitForTransactionReceipt({ hash: txHash });
      return txHash;
    },
  };
}
