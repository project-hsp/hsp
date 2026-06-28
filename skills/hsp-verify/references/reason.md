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
`MandateBody` + its `mandateHash`. To actually sign + pay, hand the hash to `@hsp/sdk` —
these tools never sign and never move money.
