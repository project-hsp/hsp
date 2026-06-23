# HSP wire typehash snapshot (vendored)

Vendored snapshot of the two EIP-712 struct typehash declarations from the
normative spec (HSP.md §2.4.1 / §2.4.2). `src/guard.ts` pins the implementation's
field arrays to these strings, which breaks the conformance-vector self-loop
WITHOUT requiring the full (private) normative spec to live in this repo.

Keep this in sync with HSP.md whenever a wire-format change lands — see the
repo-split plan, "协议修改 SOP" (B-class / wire change).

MANDATE_BODY_TYPEHASH = keccak256(
  "MandateBody("
    "bytes32 nonce,"
    "Signer signer,"
    "Recipient recipient,"
    "address token,"
    "uint256 amount,"
    "uint256 chainId,"
    "uint64 deadline,"
    "bytes32 requiredCapabilitiesHash"
  ")"
  "Recipient(uint8 kind,bytes payload)"
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
