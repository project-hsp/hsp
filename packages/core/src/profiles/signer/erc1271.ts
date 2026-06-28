/**
 * SignerProfile `erc1271.v1` — HSP.md §4.1.5 reserved profile (smart-account Principal).
 *
 * payload = abi.encode(address smartAccount, uint256 chainId); proof = account-defined
 * bytes verified ON-CHAIN via `IERC1271.isValidSignature(digest, proof)`. The digest is
 * the bound HSP typed-data hash — mandateHash for a Mandate signer, grantHash
 * for a DelegationGrant principal (§5.1 step 4c-i).
 *
 * SP7 state-dependent: validation reads live account state (ownership / module config),
 * so the profile reads fresh at verify time through a deployment-injected per-chain client.
 * PartyRef.scheme = "smart-account"; PartyRef.id covers (chainId, account) (§4.1.5).
 * `accountOf` returns the account's evm-address — the on-chain `Transfer.from` the §5.2
 * step-4 sender binding checks (NEVER the agent / owner / tx.from).
 */

import {
  keccak256,
  stringToBytes,
  encodeAbiParameters,
  decodeAbiParameters,
  getAddress,
  type Hex,
  type Address,
} from 'viem';
import type { PartyRef, Mandate } from '../../core/index.js';
import type { SignerProfile, SignerDecision } from '../../verifier/contracts.js';
import { evmAddressPartyRef } from './eip712-eoa.js';

const PROFILE_ID = 'erc1271.v1';
const PROFILE_ID_HASH = keccak256(stringToBytes(PROFILE_ID));

// bytes4(keccak256("isValidSignature(bytes32,bytes)")) — the ERC-1271 success magic value.
export const ERC1271_MAGIC: Hex = '0x1626ba7e';

const IERC1271_ABI = [
  {
    type: 'function',
    name: 'isValidSignature',
    stateMutability: 'view',
    inputs: [
      { name: 'hash', type: 'bytes32' },
      { name: 'signature', type: 'bytes' },
    ],
    outputs: [{ name: 'magicValue', type: 'bytes4' }],
  },
] as const;

/** Minimal read surface the profile needs from a viem PublicClient. */
export interface Erc1271ReadClient {
  readContract(args: {
    address: Address;
    abi: typeof IERC1271_ABI;
    functionName: 'isValidSignature';
    args: readonly [Hex, Hex];
  }): Promise<Hex>;
}

/** §4.1.5: PartyRef { scheme: "smart-account", id: abi.encode(uint256 chainId, address account) }. */
export function smartAccountPartyRef(chainId: bigint, account: Address): PartyRef {
  return {
    scheme: 'smart-account',
    id: encodeAbiParameters(
      [{ type: 'uint256' }, { type: 'address' }],
      [chainId, getAddress(account)],
    ),
  };
}

function decodeAccount(payload: Hex): { account: Address; chainId: bigint } {
  const [account, chainId] = decodeAbiParameters(
    [{ type: 'address' }, { type: 'uint256' }],
    payload,
  );
  return { account: getAddress(account), chainId };
}

/**
 * Construct an `erc1271.v1` SignerProfile bound to a per-chain read client.
 * `getClient(chainId)` returns a client able to `eth_call` on that chain, or undefined
 * if the deployment has no RPC for it (→ verify rejects, never a misleading ACCEPT).
 */
export function createErc1271Signer(
  getClient: (chainId: number) => Erc1271ReadClient | undefined,
): SignerProfile {
  return {
    profileId: PROFILE_ID,
    profileIdHash: PROFILE_ID_HASH,
    description: {
      profileId: PROFILE_ID,
      signatureSchemes: ['erc1271'],
      bindsRequiredCapabilitiesHash: true,
      supportsBatch: false,
      stateDependent: true, // reads live account state via isValidSignature (§5.1 step 4b)
    },

    decode(payload: Hex): PartyRef {
      const { account, chainId } = decodeAccount(payload);
      return smartAccountPartyRef(chainId, account);
    },

    // §4.1: the smart account itself is the settlement account whose Transfer.from binds.
    accountOf(payload: Hex): PartyRef {
      const { account } = decodeAccount(payload);
      return evmAddressPartyRef(account);
    },

    async verify(payload: Hex, proof: Hex, digest: Hex, _body: Mandate): Promise<SignerDecision> {
      let account: Address;
      let chainId: bigint;
      try {
        ({ account, chainId } = decodeAccount(payload));
      } catch {
        return { granted: false, errorCode: 'HSP-MAND-SIGNER' };
      }
      const client = getClient(Number(chainId));
      if (!client) {
        // No RPC for this chain — cannot read account state; fail closed (never ACCEPT).
        return { granted: false, errorCode: 'HSP-MAND-SIGNER-STATE-UNAVAILABLE' };
      }
      let magic: Hex;
      try {
        magic = await client.readContract({
          address: account,
          abi: IERC1271_ABI,
          functionName: 'isValidSignature',
          args: [digest, proof],
        });
      } catch {
        // revert / non-contract / call failure → not a valid signature.
        return { granted: false, errorCode: 'HSP-MAND-SIGNER' };
      }
      if (magic.toLowerCase() !== ERC1271_MAGIC) {
        return { granted: false, errorCode: 'HSP-MAND-SIGNER' };
      }
      // SP6: resolvedSubject == decode(payload) when granted. SP7: state read fresh here.
      return {
        granted: true,
        resolvedSubject: smartAccountPartyRef(chainId, account),
        signerStateHash: keccak256(
          encodeAbiParameters([{ type: 'uint256' }, { type: 'address' }], [chainId, account]),
        ),
      };
    },

    // SP7: the profile reads current account state at verify time, so there is no
    // sign-time commitment that could go stale — validation is always against `now`.
    isStateStale(_signerStateHash: Hex, _stateAnchor: Record<string, unknown>, _now: number): boolean {
      return false;
    },
  };
}
