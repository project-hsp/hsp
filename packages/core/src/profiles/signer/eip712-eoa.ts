/**
 * SignerProfile `eip712-eoa.v1` — HSP.md §4.1.6 reserved profile (worked example).
 *
 * payload = abi.encode(address); proof = EIP-712 secp256k1 sig over mandateHash
 * (mandateHash is the final typed-data digest, signed directly). PartyRef.scheme
 * = "evm-address". No deployment trust anchors — purely cryptographic.
 *
 * §4.1.6 signature strictness: proof is exactly 65 bytes (r ‖ s ‖ v), v ∈ {27, 28},
 * s ≤ secp256k1n ÷ 2 (EIP-2 low-s — one byte encoding per logical signature), and the
 * recovered address is non-zero. Any violation → granted: false (HSP-MAND-SIGNER).
 */

import {
  keccak256,
  stringToBytes,
  encodeAbiParameters,
  decodeAbiParameters,
  recoverAddress,
  getAddress,
  type Hex,
  type Address,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import type { PartyRef, Mandate } from '../../core/index.js';
import type { SignerProfile, SignerDecision } from '../../verifier/contracts.js';

const PROFILE_ID = 'eip712-eoa.v1';
const PROFILE_ID_HASH = keccak256(stringToBytes(PROFILE_ID));

// EIP-2 low-s bound: secp256k1n ÷ 2 (s above this is the malleated twin encoding).
const SECP256K1_N_DIV_2 = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
const ZERO_ADDRESS: Address = '0x0000000000000000000000000000000000000000';

/** §3.4 / §4.1.6: PartyRef { scheme: "evm-address", id: abi.encode(address) }. */
export function evmAddressPartyRef(address: Address): PartyRef {
  return { scheme: 'evm-address', id: encodeAbiParameters([{ type: 'address' }], [getAddress(address)]) };
}

export const eip712EoaSigner: SignerProfile = {
  profileId: PROFILE_ID,
  profileIdHash: PROFILE_ID_HASH,
  description: {
    profileId: PROFILE_ID,
    signatureSchemes: ['secp256k1-eip712'],
    bindsRequiredCapabilitiesHash: true,
    supportsBatch: false,
    stateDependent: false, // EOA static key — §5.1 step 4b skipped
  },

  decode(payload: Hex): PartyRef {
    const address = decodeAbiParameters([{ type: 'address' }], payload)[0];
    return evmAddressPartyRef(address);
  },

  // §4.1: an EOA is its own settlement account — accountOf == decode.
  accountOf(payload: Hex): PartyRef {
    const address = decodeAbiParameters([{ type: 'address' }], payload)[0];
    return evmAddressPartyRef(address);
  },

  async verify(payload: Hex, proof: Hex, mandateHash: Hex, _body: Mandate): Promise<SignerDecision> {
    // errorDetail below is derived only from request inputs + the verifier's own digest —
    // safe to surface, and lets an integrator self-diagnose domain/struct mismatches.
    let address: Address;
    try {
      address = decodeAbiParameters([{ type: 'address' }], payload)[0];
    } catch {
      return { granted: false, errorCode: 'HSP-MAND-SIGNER', errorDetail: 'signer.payload must be abi.encode(address) (32 bytes)' };
    }
    // §4.1.6 strictness: 65-byte (r ‖ s ‖ v), v ∈ {27, 28}, low-s (EIP-2).
    if (proof.length !== 2 + 65 * 2) {
      return {
        granted: false,
        errorCode: 'HSP-MAND-SIGNER',
        errorDetail: `signerProof must be 65 bytes r||s||v (got ${(proof.length - 2) / 2})`,
      };
    }
    const s = BigInt(`0x${proof.slice(66, 130)}`);
    const v = parseInt(proof.slice(130, 132), 16);
    if ((v !== 27 && v !== 28) || s > SECP256K1_N_DIV_2) {
      return {
        granted: false,
        errorCode: 'HSP-MAND-SIGNER',
        errorDetail: `signerProof v must be 27 or 28 and s low-s per EIP-2 (got v=${v})`,
      };
    }
    let recovered: Address;
    try {
      recovered = await recoverAddress({ hash: mandateHash, signature: proof });
    } catch {
      return { granted: false, errorCode: 'HSP-MAND-SIGNER', errorDetail: `signature recovery failed over digest ${mandateHash}` };
    }
    if (getAddress(recovered) === ZERO_ADDRESS || getAddress(recovered) !== getAddress(address)) {
      return {
        granted: false,
        errorCode: 'HSP-MAND-SIGNER',
        errorDetail:
          `recovered ${getAddress(recovered)} over digest ${mandateHash}, but signer.payload declares ` +
          `${getAddress(address)} — a digest mismatch usually means a different EIP-712 domain or Mandate ` +
          `struct on the signing side (wire v1 = 11-field Mandate; see the deployment's wire changelog)`,
      };
    }
    // SP6: resolvedSubject == decode(payload) when granted.
    return { granted: true, resolvedSubject: evmAddressPartyRef(address) };
  },
};

/** Payer-side helper: produce the §4.1.6 signerProof by signing mandateHash with an EOA key. */
export async function signMandateHash(privateKey: Hex, mandateHash: Hex): Promise<Hex> {
  return privateKeyToAccount(privateKey).sign({ hash: mandateHash });
}
