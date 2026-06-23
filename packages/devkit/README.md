# @hsp/devkit — build your own HSP settlement adapter

An HSP **adapter** plugs a settlement method (another chain, Lightning, a
points system, an exchange's internal ledger, …) into the protocol: it settles
the value movement and emits a signed **Receipt** whose `adapterProof` your
**AdapterProofSchema** teaches the verifier to check. Once a deployment
registers your adapter in its trust set, payers can settle HSP mandates through
it — no protocol changes, no permission from the spec.

## Quick start

```sh
# 1. start from the compiling template (it already passes conformance)
cp packages/devkit/template/my-adapter.ts        my-team/adapter.ts
cp packages/devkit/template/run-conformance.ts   my-team/run-conformance.ts

# 2. make it settle YOUR way: proof struct + encode/decode + verify()

# 3. self-test against the real HSP verifier until everything passes
npx tsx my-team/run-conformance.ts
```

The runner exercises the protocol's generic obligations — happy ACCEPT, forged
signature, untrusted instance, broken linkage, replay, settled-after-deadline,
post-SETTLED successor, DISPUTED-without-prior, observation reuse — re-signing
every mutant so what fails is the rule under test, never a stale signature.

## The four duties of `verify()`

| # | Duty | Why |
|---|---|---|
| D1 | **Decode + validate** the proof bytes; malformed → `ok:false` | the proof is attacker-controlled input |
| D2 | **Bind the settling party** to the mandate signer (`ctx.signerSubject`) when your settlement exposes it | else anyone's settlement satisfies anyone's mandate |
| D3 | **Surface true observations** (amount/recipient/token/chain) from your settlement system — never echo the mandate | the verifier compares them to the mandate (§5.2 step 4) |
| D4 | **Emit `observationId`** (hash of your settlement-native identity) for observation-based settlement | one settlement must satisfy at most one mandate; omit only if your artifact is cryptographically bound to `mandateHash` (x402-style) |

Plus: `proofSatisfiedCapabilities` must stay within the `allowedCapabilities`
you register (fail-closed upper bound), and pick your `reorgPolicy` honestly
(`allowsAttempted`, `chainObservation`, `disputeWindowMs`).

## Identity & registration

Your adapter's identity is immutable once registered:

```
adapterId          = keccak256("adapter:<your-name>")
proofSchemaId      = keccak256("<your-name>.proof.v1")     // new schema ⇒ new id
adapterInstanceKey = bytes32(0), or keccak256(<instance discriminator>)
```

To go live on the hackathon sandbox, submit to the organizers:

1. `adapterId` + `proofSchemaId` (and the names they hash from),
2. your **operator signing address** (the key that signs receipts — it attests
   observations, it is not custody),
3. your `reorgPolicy` and `allowedCapabilities`,
4. your schema module (this repo's PR or a package) + a passing conformance run.

They register it in the Coordinator's §7.2.1 trust tables; from then on
`POST /payments/:id/receipts` accepts your receipts and the Explorer will show
your adapter's decision traces.

## Reference implementations to crib from

- `@hsp/core/adapter/mock-evm-transfer` — plain ERC-20 transfer (wallet-settling)
- `@hsp/core/adapter/x402` — signature-chain settlement (self-settling, mandate-bound)

`npm run example -w @hsp/devkit` runs the suite against the reference adapter;
`npm run template -w @hsp/devkit` runs it against the template.
