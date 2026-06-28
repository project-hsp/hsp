// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MockERC1271Account — minimal ERC-1271 smart account for HSP erc1271.v1 testing.
/// @notice Models a smart-account Principal whose `owner` EOA authorizes signatures.
///         `isValidSignature(hash, sig)` returns the ERC-1271 magic value iff `sig` is a
///         65-byte secp256k1 signature by `owner` over `hash`. The HSP `erc1271.v1` signer
///         profile calls this on-chain to verify a Principal's grant/execution signature
///         (SP7 state-dependent — ownership lives in account state, §4.1.5 / §5.1 step 4c).
contract MockERC1271Account {
    bytes4 internal constant MAGIC = 0x1626ba7e; // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant INVALID = 0xffffffff;

    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    /// @notice Rotate the authorizing owner — exercises SP7 staleness (sign-time vs verify-time).
    function setOwner(address _owner) external {
        require(msg.sender == owner, "not owner");
        owner = _owner;
    }

    /// @notice Minimal account execution — the owner drives the account to move value, so the
    ///         settlement's `Transfer.from` is THIS account (the Principal), not the agent/owner.
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        require(msg.sender == owner, "not owner");
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "exec failed");
        return ret;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (signature.length != 65) return INVALID;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        // EIP-2 low-s + valid v, matching the eip712-eoa.v1 profile's acceptance window.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return INVALID;
        }
        if (v != 27 && v != 28) return INVALID;
        address recovered = ecrecover(hash, v, r, s);
        if (recovered != address(0) && recovered == owner) return MAGIC;
        return INVALID;
    }
}
