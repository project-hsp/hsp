# HSP Conformance Vectors — Fixture Format

> **Status:** v1 working draft
> **Schema:** [`schema.json`](schema.json)
> **Last updated:** 2026-05-25

This directory holds the language-agnostic JSON fixture pack. Every fixture file conforms to [`schema.json`](schema.json).

## File-level shape

```json
{
  "spec_section": "HSP.md §2.4.1",
  "derivation":   "mandateHash",
  "vectors": [
    { "id": "...", "description": "...", "spec_refs": ["..."], "input": {...}, "expected_output": {...} },
    { "id": "...", ... }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `spec_section` | yes | The single normative section a reader should cross-reference. |
| `derivation` | yes | Identifier of the derivation function (`mandateHash`, `receiptHash`, `requiredCapabilitiesHash`, `capabilityId`). Used by the runner to dispatch to the right reference function. |
| `vectors[]` | yes | One or more fixtures. |

## Vector-level shape

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable id, kebab-case. Use as ticket reference when discussing failures. |
| `description` | yes | One sentence, plain prose. Describes the variation this vector exercises. |
| `spec_refs[]` | yes | Specific MUST clauses or sections this vector pins. Multiple allowed when the vector exercises a cross-cutting invariant. |
| `input` | yes | The derivation function's input arguments, named per the function's signature. |
| `expected_output` | optional during freeze; required after | The byte-equal expected return value. **Filled by the freezer**, not by humans. |

## Per-derivation `input` and `expected_output` shapes

### `mandateHash`

```json
"input": {
  "domain": {
    "name": "HSP",
    "version": "1",
    "chainId": 8453,
    "verifyingContract": "0x..."
  },
  "body": {
    "nonce":         "0x...",
    "signer":        { "profileId": "0x...", "payload": "0x..." },
    "recipient":     { "kind": 0, "payload": "0x..." },        // 0 = ADDRESS, 1 = COMMITMENT
    "token":         "0x...",                                    // bare EVM ERC-20 contract address (v1 is EVM-only)
    "amount":        "9990000",                                  // decimal string
    "chainId":       8453,
    "deadline":      1714000600,
    "requiredCapabilitiesHash": "0x..."
  }
},
"expected_output": { "hash": "0x..." }
```

The reference runner constructs the EIP-712 typed-data hash per the HSP specification §2.4. The struct field set is pinned to the spec by the runner's drift guard (see "Freeze / verify protocol" below).

### `requiredCapabilitiesHash`

Two `input` shapes are accepted; exactly one MUST be present:

```json
// Shape A: literal bytes32 wire array
"input": { "capabilities": ["0x...", "0x...", "0x..."] }

// Shape B: inline capability declarations (the runner computes each id, uses inline order as wire order)
"input": {
  "_inline_capability_ids": [
    { "namespace": "hides", "name": "sender", "version": "v1", "params": [] },
    { "namespace": "hides", "name": "amount", "version": "v1", "params": [] }
  ]
}
```

Shape B is preferred for readability; Shape A is for cases where the test wants to pin specific bytes32 values regardless of how they were derived. Combining both in one input is rejected.

Canonicalizes (dedupe → sort lexicographically as `bytes32`) and hashes per the HSP specification §3.1.3. Empty array → `0x000…000`.

```json
"expected_output": { "hash": "0x..." }
```

### `capabilityId`

```json
"input": {
  "namespace": "attests",
  "name": "kyc",
  "version": "v1",
  "params": [
    { "key": "level", "type": "string", "value": "full" }
  ]
}
```

`params` is an ordered array; the runner sorts by key per the HSP specification §3.1.4. Each entry's `type` is one of `string`, `uint256`, `bytes32`, `bool`, `address`. Empty `params` → `[]`.

`expected_output`:

```json
"expected_output": { "id": "0x..." }   // 32-byte hash
```

For role-prefixed ids (`role[roleName, baseId]`), use the dedicated `roledCapabilityId` derivation (Phase 2 — not yet implemented).

## Freeze / verify protocol

- **Freeze.** When a fixture lacks `expected_output`, the freezer reads `input`, runs the named derivation against the reference implementation, and writes `expected_output` back. The author then inspects the result: if it matches what they expected, they commit; otherwise they investigate (either the input was wrong or the spec is ambiguous).
- **Verify.** Re-runs every derivation against its `input` and asserts byte-equality against the committed `expected_output`, **and** runs the spec drift guard (`src/guard.ts`), which rebuilds the EIP-712 type strings from the runner's struct definitions and pins them to `HSP.md` §2.4.1 / §2.4.2 (mandate + receipt typehashes). Without the guard, freeze/verify is circular — vectors are frozen from the same code that checks them — so the guard is what actually ties the pack to the spec. Any drift fails CI.
- **Re-freezing a committed fixture is a spec change.** Modifying an `expected_output` value with the spec unchanged means the reference implementation diverged from the spec. The PR description MUST explain which side moved.
