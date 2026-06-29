# UNDERSTAND & REQUIREMENTS — reason about HSP (no payment needed)

Use to decode an object, learn the capability language, or check what a payment
needs — independent of verifying one specific receipt. All read-only / constructive;
nothing here signs or moves money.

## Decode any wire object

`hsp_inspect {object}` → plain, labelled fields. Works on a **mandate**, **receipt**,
or **attestation** (auto-detected; pass `kind` to force). For a receipt it decodes the
adapter proof and states whether the binding is **cryptographic** (x402 — the proof
carries the payer's EIP-3009 signature) or **operator-attested** (evm-transfer — an
observation you trust the pinned operator for).

## The capability language

A capability is `verb:object:version[params]`; the verifier compares sets byte-for-byte.

- `hsp_capability {}` (no args) → list the baseline vocabulary (`proves:*` / `attests:*` /
  `hides:*` / `discloses:*`) and each family's params.
- `hsp_capability {verb, object, version, params}` → resolve one to its id + meaning.
  Some families need params, e.g. `attests:kyc` needs `level` → pass `params: {level:"full"}`.
- `hsp_capability_diff {required, satisfied}` → what a payment is MISSING (the gap a proof
  or attestation must close before it verifies).

## What a deployment requires (§7.7)

- `hsp_build_requirements {mode: "public" | "compliance", compliance?, issuerAddress?}` →
  emit a PayeeRequirement object — what a payee/deployment advertises it requires.
- `hsp_check_requirements {mandate, requirements}` → **pre-flight, BEFORE paying**: does this
  mandate cover the deployment's `policyRequiredCapabilities` + a supported chain? Returns
  `ok` + exactly what is missing, so the payer can fix the mandate first.

## Construct an intent (no signing, no money)

`hsp_build_mandate {to, amount, signer, token?, deadline?, capabilities?}` → an UNSIGNED
`Mandate` + its `mandateHash`. To actually sign + pay, hand the hash to `@hsp/sdk` —
these tools never sign and never move money.

## Worked example

**Decode a receipt you were handed:**
```jsonc
hsp_inspect { object: <receipt> }
→ { "kind": "receipt (adapter-operator attestation)", "mandateHash": "0x9f…",
    "adapterId": "0xeeb0…", "proofSchemaId": "0xe8e9…", "outcome": 1, "settledAt": 1700000000, "seq": 0,
    "proof": { "kind": "evm-transfer (operator-attested observation)",
               "from": "0x…", "to": "0x…", "value": "1000000", "token": "0x…", "txHash": "0x…" } }
```
`outcome: 1` = SETTLED; the `proof.kind` tells you **cryptographic** (x402) vs **operator-attested** (evm-transfer).

**Resolve a capability, then see the gap:**
```jsonc
hsp_capability { verb: "attests", object: "kyc", version: "v1", params: { level: "full" } }
→ { "family": "attests:kyc:v1", "id": "0x232e…", "meaning": "attests:kyc:v1[level=full]",
    "params": [{ "key": "level", "type": "string", "value": "full" }] }

hsp_capability_diff { required: ["0x232e…"], satisfied: [] }
→ { "satisfiedAll": false, "missing": [{ "id": "0x232e…", "meaning": "attests:kyc:v1[level=full]" }],
    "note": "the payment must close this gap (a proof or attestation that satisfies each id) before it verifies" }
```

**Pre-flight a mandate against a deployment, BEFORE paying:**
```jsonc
hsp_build_requirements { mode: "public" }
→ { "hspVersion": "1", "domain": { "verifyingContract": "0x…01", "chainIds": [133] },
    "signerProfiles": ["eip712-eoa.v1"], "policyRequiredCapabilities": [],
    "adapters": [{ "adapterId": "adapter:evm-transfer", "adapterInstanceKey": "0x00…", "proofSchemaId": "0xe8e9…" }] }

hsp_check_requirements { mandate, requirements: <the above> }
→ { "ok": true, "chainOk": true, "missingRequiredCapabilities": [],
    "note": "mandate covers the deployment’s required capabilities + a supported chain" }
```
`ok: true` → the payer can sign + pay. If `missingRequiredCapabilities` is non-empty, fix the mandate first
(add the caps, or pay a deployment that doesn't require them).
