# HSP wire typehash snapshot (vendored)

Vendored snapshot of the EIP-712 struct typehash declarations from the normative
spec (HSP.md §2.4.1 / §2.4.2). `src/guard.ts` pins the implementation's field
arrays to these strings, which breaks the conformance-vector self-loop WITHOUT
requiring the full (private) normative spec to live in this repo.

Keep this in sync with HSP.md whenever a wire-format change lands — see the
repo-split plan, "协议修改 SOP" (B-class / wire change).

Delegation refactor (v-next): `Mandate` is 11 fields (v0 `MandateBody`
was 8; `grantRef`/`requirementRef`/`settlementBinding` added), `ReceiptPreimage`
renames `mandateHash` → `mandateHash`, and `GRANT_TYPEHASH` (DelegationGrant,
§2.4.1a) is added for delegated payments — the Principal signs `grantHash`.

MANDATE_TYPEHASH = keccak256(
  "Mandate("
    "bytes32 nonce,"
    "Signer signer,"
    "bytes32 grantRef,"
    "bytes32 requirementRef,"
    "Recipient recipient,"
    "address token,"
    "uint256 amount,"
    "uint256 chainId,"
    "uint64 deadline,"
    "bytes32 settlementBinding,"
    "bytes32 requiredCapabilitiesHash"
  ")"
  "Recipient(uint8 kind,bytes payload)"
  "Signer(bytes32 profileId,bytes payload)"
)

GRANT_TYPEHASH = keccak256(
  "DelegationGrant("
    "Signer principal,"
    "Signer agent,"
    "bytes32 onchainPermissionRef,"
    "bytes32[] payerRequiredCaps,"
    "bytes32[] payerAllowedCaps,"
    "uint64 notBefore,"
    "uint64 expiry,"
    "bytes32 nonce"
  ")"
  "Signer(bytes32 profileId,bytes payload)"
)

RECEIPT_PREIMAGE_TYPEHASH = keccak256(
  "ReceiptPreimage("
    "bytes32 mandateHash,"
    "bytes32 adapterId,"
    "bytes32 adapterInstanceKey,"
    "uint64 seq,"
    "uint8 outcome,"
    "uint64 settledAt,"
    "bytes32 proofSchemaId,"
    "bytes32 adapterProofHash"
  ")"
)
