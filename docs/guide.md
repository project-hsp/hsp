# HSP Developer Guide

> The detailed companion to the [developer portal](../README.md#developer-portal) (`GET /docs` on any
> Coordinator). The portal is the 10-minute orientation; this guide is the reference you keep open
> while building.
>
> **Status:** HSP is a pre-1.0 draft protocol. The concepts in §1 are stable; wire details may still
> change. The implementation is conformance-guarded against re-derived typehashes + 23 frozen vectors
> + 34 protocol e2e checks, so this repo cannot silently drift from its own conformance gates.

## Contents

1. [The protocol](#1-the-protocol)
2. [The ecosystem at a glance](#2-the-ecosystem-at-a-glance)
3. [The Coordinator — API reference](#3-the-coordinator--api-reference)
4. [The SDK — @hsp/sdk](#4-the-sdk--hspsdk)
5. [AI integration — @hsp/mcp and the skill](#5-ai-integration--hspmcp-and-the-skill)
6. [Building an adapter — @hsp/devkit](#6-building-an-adapter--hspdevkit)
7. [Walkthroughs](#7-walkthroughs)
8. [Environments](#8-environments)
9. [Decision reference](#9-decision-reference)
10. [Trust model & security](#10-trust-model--security)
11. [FAQ](#11-faq)

---

## 1. The protocol

### 1.1 What problem HSP solves

Payment rails move money. Almost none of them give the *relying party* — the merchant about to ship,
the platform about to unlock, the agent about to proceed — a cryptographic answer to the question:

> *Did the thing I authorized actually happen, under the conditions I demanded?*

HSP is that answer layer. It deliberately does **not** move money, hold
funds, or replace any settlement system. It defines three signed wire objects and one decision
procedure that make *any* settlement system verifiable:

```
            ┌────────────────────┐
  payer ──► │ Mandate            │  signed payment intent (EIP-712)
            ├────────────────────┤
adapter ──► │ Receipt            │  signed settlement observation + proof
            ├────────────────────┤        ──►  VERIFIER  ──►  ACCEPT / REJECT
issuers ──► │ Attestations       │  signed compliance statements (optional)
            └────────────────────┘
```

The decision rule is one line:

```
ACCEPT  ⇔  mandate.requiredCapabilities ⊆ satisfiedCapabilities(proof ∪ attestations)
```

Everything interesting — compliance, consumer protection, settlement-quality guarantees —
is an entry in those two capability sets. A payer (or a merchant's posted requirements) *requires*
capabilities; the settlement proof and external attestations *satisfy* them; the verifier checks the
subset relation and a battery of consistency rules. Nothing else.

### 1.2 Design principles

- **Verification, not settlement.** HSP composes with rails (bare ERC-20 transfers, x402, anything
  an adapter can witness); it never competes with them.
- **Custody-free.** In the reference deployment your wallet signs the mandate *and* broadcasts the
  transfer. The Coordinator's key signs *observations* — statements about what it saw on-chain — and
  can never move funds.
- **"ACCEPT means ship."** The verifier is a pure function of the wire objects plus deployment-pinned
  trust roots. Same inputs ⇒ same decision, anywhere. A merchant can (and should) re-run it
  independently instead of trusting anyone's API response.
- **Compliance is a capability, not a fork.** KYC and sanctions screening are expressed through the
  same require/satisfy mechanism as everything else, toggleable per payment.

### 1.3 The three wire objects

#### Mandate — the signed intent

A `MandateBody` has exactly eight fields, signed as EIP-712 typed data
(domain `{name: "HSP", version: "1", chainId, verifyingContract}`):

| Field | Meaning |
|---|---|
| `nonce` | unique 32 bytes; pure replay protection. Two mandates with identical bodies *are* the same mandate — use distinct nonces for repeated identical orders. |
| `signer` | profile-tagged signer reference. The baseline profile is `eip712-eoa.v1` (a plain EOA); the profile system is pluggable (smart accounts / ERC-1271 are the designed extension). |
| `recipient` | tagged `ADDRESS` — a plain EVM address. |
| `token` | the ERC-20 contract address (v1 is EVM-first; non-ERC-20 assets are identified per adapter binding). |
| `amount` | base units; the exact transfer value the proof must match. |
| `chainId` | settlement chain; must be non-zero. |
| `deadline` | Unix seconds. A receipt is admissible only if its settlement time `settledAt ≤ deadline`. Verification may happen later — an on-time settlement stays verifiable forever. |
| `requiredCapabilitiesHash` | hash of the sorted canonical capability-id set. `bytes32(0)` ⇔ empty set ⇔ trivial public payment. |

The **`mandateHash`** (EIP-712 digest) is the payment's identity everywhere — the Coordinator's
`paymentId` *is* the mandateHash, so you can recompute it client-side and registration is idempotent.

#### Receipt — the signed settlement observation

| Field | Meaning |
|---|---|
| `mandateHash` | which mandate this settlement is claimed against |
| `adapterId` | `keccak256("adapter:<name>")` — which settlement method |
| `adapterInstanceKey` | which instance of it (32 bytes; `0x0` for singletons, e.g. `keccak256(merchantDomain)` for x402) |
| `seq` | strictly-increasing emission counter per `(adapterId, instanceKey, mandateHash)` — replay/equivocation protection |
| `outcome` | `ATTEMPTED` → `SETTLED` \| `FAILED`, with `DISPUTED` as the only post-`SETTLED` successor (technical reversal, e.g. a chain reorg within the adapter's dispute window) |
| `settledAt` | the outcome-effective time — anchored to chain time where the proof carries it |
| `proofSchemaId` | which proof schema can decode + verify `adapterProof` |
| `adapterProof` | the settlement evidence (transfer observation, signature chain, ZK proof, …) |
| `adapterSignature` | the registered operator key's signature over the receipt hash |

#### Attestation — the signed compliance statement

An external issuer's signed statement binding a capability (e.g. `attests:kyc:v1[level=full]`,
`attests:sanctions:v1`) to a **subject** (a `PartyRef`, typically the payer's address), with claims,
a validity window, and the issuer's signature. The verifier admits attestations only from issuers in
its deployment-pinned trust anchors. Issuers sign statements — never funds.

### 1.4 Capabilities

A capability id is a hash over `namespace:name:version[params]`. Two namespaces in this release:

| Namespace | Satisfied by | Examples |
|---|---|---|
| `proves:*` | a structural cryptographic property of the proof | `proves:quote-honored:v1[quoteHash]`, `proves:settlement-verified:v1[via=zk]` |
| `attests:*` | an external issuer's attestation — never the adapter | `attests:kyc:v1[level=full]`, `attests:sanctions:v1` |

One fact worth internalizing:

- **Deployments can set a policy floor.** Besides what the mandate requires, a deployment may demand
  that every mandate *itself requires* certain capabilities (e.g. KYC + sanctions). A mandate that
  doesn't is rejected with `HSP-MAND-REQ-INSUFFICIENT` *before* any settlement is looked at —
  published in advance via `GET /requirements`.

### 1.5 The verifier

Two phases. **Phase A** (mandate admission, no receipt needed): EIP-712 domain + signature, signer
profile resolution, capability-set hash consistency, policy-floor check. **Phase B** (receipt
verification): adapter/instance trust + signature, mandate linkage, proof-schema dispatch
(`verify()` decodes and cryptographically checks the proof), **settlement consistency** (observed
token/chain/recipient/amount vs the mandate), attestation walk, the subset decision, and stateful
admission (sequencing, outcome-successor rules, `settledAt ≤ deadline`, observation consumption).

Two stateful rules deserve emphasis because they bite integrators:

- **One settlement, one payment.** A settlement-native observation (for bare transfers:
  `(chainId, token, txHash)`) may satisfy **at most one** mandate, ever. Replaying the same on-chain
  transfer against a second mandate yields `HSP-RCPT-OBS-REUSED` (HTTP `409 observation-reuse` at the
  Coordinator).
- **Exactly one matching Transfer log.** The public-path adapter rejects transactions with zero or
  multiple matching transfer logs (`ambiguous`). No fee-on-transfer tokens, no batched/multi-log
  settlement transactions on the public path.

### 1.6 Adapters and the trust boundary

An **adapter** plugs a settlement method into HSP: it settles (or observes settlement) and emits
receipts; its registered **proof schema** teaches the verifier how to check the proof. Two settlement
models:

- **wallet-settling** (evm-transfer): the *payer's wallet* moves funds; the adapter only
  observes. The schema enforces `Transfer.from == mandate.signer`.
- **self-settling** (x402): the facilitator executes the settlement — the proof carries the payer's
  EIP-3009 authorization (its signature recovers to `from == mandate signer`, a cryptographic payer
  binding), and the settlement `txHash` rests on the facilitator's operator signature.

**Trust boundary, stated plainly:** a valid `adapterSignature` proves *the registered operator signed
this observation* — not, by itself, that the value movement happened. That is operator-signature
trust, and it is the protocol's only non-cryptographic link. Deployments that want more require
`proves:settlement-verified:v1[via=spv|light-client|zk]`, which an operator-signature-only schema
cannot emit (fail-closed). For the hackathon sandbox, operator trust in the Coordinator's observation
key is the intended posture — and merchants can still independently re-verify everything else.

---

## 2. The ecosystem at a glance

```
skills/hsp-pay      AI skill — how an agent understands paying (quote → approval → pay → track)
packages/mcp        MCP server — how an agent acts: hsp_quote / hsp_pay / hsp_status / hsp_verify
packages/sdk        how a developer pays & verifies — HSPClient.pay() / HSPVerifier.verify()
packages/core       the protocol — types, hashes, verifier, adapters, attestations
packages/devkit     adapter scaffolding — template + conformance runner
contracts/          test tokens (MockERC20, MockEIP3009Token) — foundry
```

The **Coordinator** — the REST hub the SDK talks to (registration, observation, verification,
persistence, the Explorer + `/docs` portal) — is a **hosted service** run by the organizer, not a
package in this repo: you point your SDK at it, you do not build it here.

Everything runs from TypeScript source via `tsx` — there is deliberately no build step. On a
contributor machine, everything runs inside Docker (`docker/dev.Dockerfile` carries node + anvil +
forge); see [§8.4](#84-local-protocol-development).

---

## 3. The Coordinator — API reference

The Coordinator is the lifecycle hub: it registers mandates, observes chains, signs observation
receipts (as the registered Adapter Operator), runs the verifier, persists the
`(mandate, receipts[], attestations[])` triple, and serves status, the Explorer, and the developer
portal. It is custody-free — see [§10](#10-trust-model--security).

### 3.1 Authentication

Public reads need no key. **Write endpoints and the payment list** require
`Authorization: Bearer <key>` with a key from the deployment's `HSP_API_KEYS` (per-team keys on the
sandbox). An empty key list means open dev mode (the server warns at startup).

### 3.2 Endpoints

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /` | — | 302 → `/docs` |
| `GET /docs` | — | developer portal (single-file HTML) |
| `GET /explorer` | — | Explorer UI; deep-link `/explorer?id=0x<paymentId>` |
| `GET /healthz` | — | liveness: `{ ok: true }` |
| `GET /chains` | — | chain registry: name, chainId, stablecoin, confirmations, verifyingContract, instanceKey, **adapterAddress (pin this)** |
| `GET /requirements?chain=<name>` | — | the §7.7 `MandateRequirements` projection — everything a passing mandate must satisfy (signer profiles, policy-floor capabilities, trusted issuers, adapters + reorg policies, domain constants). Build mandates from this, not from guesswork. |
| `GET /stats` | — | public aggregates: `{ byChainStatus: [{chain, status, count}], totalPayments }` |
| `GET /payments?status=&chain=&limit=&offset=` | Bearer | detail list (capped at 200/page) |
| `POST /payments` | Bearer | register: `{ chain, mandate: SignedMandate, attestations?: Attestation[] }` → `201` (or `200` with `existing: true`) `{ paymentId, status }` |
| `GET /payments/:id` | — | snapshot: status, mandate, admitted receipts, rejected submissions, last decision |
| `GET /payments/:id/explain` | — | the label-resolved decision trace (what the Explorer renders) |
| `POST /payments/:id/observe` | Bearer | `{ txHash }` — observe an on-chain settlement for this payment |
| `POST /payments/:id/receipts` | Bearer | `{ receipt }` — submit an externally built receipt (e.g. from your own adapter) |

### 3.3 Semantics that matter

- **`paymentId` is the mandateHash.** Recompute it client-side; `POST /payments` is idempotent for an
  equivalent body + valid signature (returns the original), and `409`s on a non-equivalent body with
  the same hash.
- **Only admitted receipts change status.** A submission the verifier rejects lands in
  `rejectedSubmissions[]` with its decision and never harms the payment — a bogus `txHash` cannot
  kill a payment that can still settle.
- **`202` from observe = not yet observable.** The tx isn't mined or hasn't reached the chain's
  pinned confirmation count. Retry; the SDK does this for you.
- **One observation settles at most one payment** (`409 observation-reuse` — see §1.5).
- **`settledAt` is anchored to the observed block timestamp**, and the Coordinator locally refuses to
  sign a receipt for a settlement after the mandate deadline (a deployment mitigation; the verifier
  enforces the rule protocol-side regardless).
- **Status machine:** `PROPOSED` → (admitted receipts drive) `ATTEMPTED` → `SETTLED` | `FAILED`, and
  `SETTLED` → `DISPUTED` (sticky). `EXPIRED` is a read-time view of a `PROPOSED` payment past its
  deadline — never stored, and a pre-deadline settlement observed later still wins.

### 3.4 x402 Facilitator (separate service, optional)

The Facilitator is the x402 server role, speaking the conformant Coinbase **x402 v2** wire
(`exact` scheme on EVM / EIP-3009). It is a **stock** facilitator: it verifies the client's payment
and settles on-chain via `transferWithAuthorization` (the client's funds move; the facilitator only
pays gas). It is **not** HSP-aware — the **Coordinator** is the `adapter:x402` operator: after the
facilitator settles, the payer hands the EIP-3009 proof + txHash to the Coordinator, which reads the
chain to confirm the transfer and signs the verifiable `adapter:x402` receipt itself.

| Method & path | Purpose |
|---|---|
| `GET /x402/info` | facilitator address, merchant domain, instance key, chain |
| `GET /supported` | `{ kinds: [{ x402Version: 2, scheme: "exact", network }] }` |
| `POST /verify` | `{ x402Version, paymentPayload, paymentRequirements }` → `VerifyResponse` (signature + amount/recipient/network/time-window checks; no chain I/O) |
| `POST /settle` | same body → `SettleResponse` (submits `transferWithAuthorization`, returns the settlement `txHash`). Stock x402 — **no HSP bridge**; the payer (or the gate) hands the proof to the Coordinator's `POST /payments/:id/x402-settle`. |

These are the standard x402 facilitator endpoints — a stock x402 resource server can call them.
For a direct merchant payment you normally don't call them by hand: `client.payX402()` drives the
whole flow ([§4.5](#45-x402--payx402)); to pay an x402-gated URL, `fetchWithX402()`.

### 3.5 Mock compliance issuer (separate service)

A stand-in for a real KYC/AML provider; same wire shape as production attestations.

| Method & path | Purpose |
|---|---|
| `GET /issuer` | `{ address, families: ['attests:kyc:v1', 'attests:sanctions:v1'] }` — the address deployments pin as a trust anchor |
| `POST /attest/kyc` | `{ subject: 0xAddress, level?: 'basic'\|'full' }` → `{ attestation }` |
| `POST /attest/sanctions` | `{ subject: 0xAddress }` → `{ attestation }` |

The SDK calls these automatically when you pass `profile: { compliance: [...] }`.

### 3.6 Faucet (separate service)

| Method & path | Purpose |
|---|---|
| `GET /` | the claim web page |
| `GET /faucet` | config + balances: faucet address, chain, drip amounts, cooldown hours |
| `POST /faucet` | `{ address }` → drips testnet gas + USDC; rate-limited per address (default cooldown 24 h) |

---

## 4. The SDK — @hsp/sdk

### 4.1 Setup

The packages are npm-workspace members (not yet published); clone the repo and import by workspace
name. Runnable references: [`examples/pay-demo.ts`](../examples/pay-demo.ts) and
[`examples/merchant-verify.ts`](../examples/merchant-verify.ts).

```ts
import { HSPClient, HSPVerifier, fetchRequirements, buildPaymentRequest } from '@hsp/sdk';
import { resolveChain } from '@hsp/core/chains/index';
```

### 4.2 HSPClient

```ts
const client = new HSPClient({
  coordinatorUrl: 'http://localhost:8787',
  signer,                                  // see signer kinds below
  chain: resolveChain('hashkey-testnet', {}),
  chainName: undefined,                    // Coordinator registry name; defaults to chain.name
  apiKey: 'your-team-key',                 // Bearer key for write endpoints
  issuerUrl: 'http://localhost:8788',      // required only for pay({ profile: { compliance } })
});
```

**Signer kinds** (`HSPSigner`):

| kind | shape | use |
|---|---|---|
| `privateKey` | `{ kind: 'privateKey', privateKey: '0x…' }` | scripts, demos, agents (cap the key!) |
| `viemAccount` | `{ kind: 'viemAccount', account }` | anything viem supports (mnemonic, HD, hardware) |
| `eip1193` | `{ kind: 'eip1193', provider, address }` | browser wallets — signing stays in the wallet |

Helper: `client.parseAmount('1.5')` → base units using the chain's stablecoin decimals.

### 4.3 pay() — one call, the whole flow

```ts
const handle = await client.pay({
  to: '0xMerchant…',
  amount: 1_000_000n,        // base units (1 USDC at 6 decimals)
  token: undefined,          // defaults to the chain-pinned stablecoin
  deadline: undefined,       // Unix seconds; default now + 1h
  capabilities: [],          // raw capability ids, if you build them yourself
  profile: undefined,        // or the high-level profile (compliance) — §4.4
  nonce: undefined,          // random by default
});
```

One `pay()` call performs: ① build the `MandateBody` (random nonce, default deadline) → ② compute
`mandateHash`, sign EIP-712 → ③ `POST /payments` → ④ broadcast the ERC-20 `transfer` **from the same
signer** (mandate signer ≡ on-chain sender is enforced by the proof schema) → ⑤ wait for the tx
receipt, then `POST …/observe` (retrying on `202`) → ⑥ return a handle.

```ts
interface PayHandle {
  paymentId: Hex;            // = mandateHash
  txHash: Hex;
  status: string;            // status at return time
  mandate: SignedMandate;
  awaitSettled(opts?: { timeoutMs?; pollMs? }): Promise<PaymentSnapshot>;
}
```

`pay()` also accepts a payee-built `PaymentRequest` (from `buildPaymentRequest()`, [§4.7](#47-payee-invoicing--discovery)) —
the payer↔payee handshake closes without either side hand-assembling fields.

**Exact-amount discipline:** the public path verifies `Transfer.value == mandate.amount` exactly and
exactly one matching log. Fee-on-transfer tokens, partial fills, and batched transfers are
`PERMANENT` rejections by design.

### 4.4 Compliance — pay({ profile })

```ts
const handle = await client.pay({
  to, amount,
  profile: { compliance: ['kyc', 'sanctions'] },
});
```

What happens: the tags resolve to capability ids (`attests:kyc:v1[level=full]`,
`attests:sanctions:v1`) which are **signed into the mandate's required set**; the SDK fetches
matching attestations for *your* address from the configured issuer and submits them with the
registration. If the deployment publishes a compliance floor in `GET /requirements`, build mandates
that require at least that floor — otherwise registration fails fast with
`HSP-MAND-REQ-INSUFFICIENT`.

### 4.5 x402 — payX402() and fetchWithX402()

Conformant Coinbase **x402 v2** (the `exact` scheme / EIP-3009). Two entry points:

**Pay a merchant directly** (`payX402`) — one call drives the whole flow:

```ts
const handle = await client.payX402({
  merchant: '0xMerchant…',
  facilitatorUrl: 'http://localhost:8789',
  amount: 10_000n,                          // requires a FiatTokenV2-style token (name()/version())
});
```

The SDK signs the HSP mandate AND an EIP-3009 `TransferWithAuthorization`, settles **your** funds via
one `POST /settle` to a stock facilitator (zero gas for you), then hands the EIP-3009 proof + txHash to
the Coordinator (`POST /payments/:id/x402-settle`), which confirms the transfer on-chain and signs the
verifiable `adapter:x402` receipt.

**Pay an x402-gated HTTP resource** (`fetchWithX402`) — works against ANY conformant x402 server
(ours or a stock one); on `402` it signs the authorization and retries:

```ts
import { fetchWithX402 } from '@hsp/sdk';
const res = await fetchWithX402(url, undefined, {
  signer: { kind: 'privateKey', privateKey: KEY },
  hsp: { chain },                           // optional: also yields a verifiable HSP receipt
});                                         // res.response is the 200; res.paymentId is the mandateHash
```

`wrapFetchWithX402(opts)` returns a drop-in `fetch` that auto-pays `402`s. On the server side, gate a
route with `x402Gate(c.req.raw, opts)` (framework-agnostic — hono/Bun/Workers).

### 4.6 HSPVerifier — independent verification, for any relying party

The **relying party** is whoever acts on a payment. HSP's wire roles are `{payer, payee, auditor}`,
and the same pinned-trust verification serves all of them: a merchant shipping goods (the canonical
payee), an auditor reviewing a payment, a platform confirming a buyer paid a seller — even the payer
double-checking a receipt.

```ts
const verifier = new HSPVerifier({
  chain,                      // chain constants you pin
  adapterAddress: PINNED,     // the observation address — pin ONCE, out-of-band (GET /chains, docs)
  compliance: undefined,      // optional pinned issuer anchors + floor for compliant flows
});

const decision = await verifier.verify(mandate, receipt, attestations /* = [] */);
if (decision.ok && decision.outcomeClass === 'ACCEPT') ship();
```

This runs the **full core verifier** with a policy built from *your* pinned config
(`PinnedTrustConfig`) — never from the Coordinator's answers. It layers your pinned compliance config
on top when present. Each call judges one `(mandate, receipt)` pair statelessly; if you process
receipt *streams*, pass your own persistent `SeqIndex`/`ObservationIndex` (optional 4th/5th
parameters) so sequencing and observation-reuse checks see history.

### 4.7 Payee invoicing & discovery

`buildPaymentRequest(chain, { to, amount, token?, requirements? })` produces the `PaymentRequest`
object your checkout hands to payers — `HSPClient.pay(paymentRequest)` consumes it, closing the
payer↔payee handshake without either side hand-assembling fields.
`fetchRequirements(coordinatorUrl, chain)` fetches the deployment's mandate requirements for display
or client-side prevalidation.

---

## 5. AI integration — @hsp/mcp and the skill

### 5.1 MCP server

Four tools, designed so the dangerous one is hard to misuse:

| Tool | What it does | Guardrails |
|---|---|---|
| `hsp_quote` | pure preview: echoes recipient/amount/token + deployment requirements | signs nothing, moves nothing |
| `hsp_pay` | sign → register → broadcast → observe → status | **requires `confirm: true`**, which the agent may set only after the user explicitly approved the exact quote; server-side caps apply regardless |
| `hsp_status` | payment snapshot by id | read-only |
| `hsp_verify` | independent verification (uses the pinned adapter address) | read-only |

Inputs for `hsp_quote`/`hsp_pay`: `to` (address), `amount` (base-unit decimal string), optional
`token`, optional `profile` (compliance tags — needs the server configured with an issuer URL).

### 5.2 Environment reference

| Variable | Required | Meaning |
|---|---|---|
| `HSP_AGENT_PRIVATE_KEY` | ✔ | the agent's signing key — **demo / small-amount scoped**; production should use a wallet/smart-account signer |
| `HSP_COORDINATOR_URL` | default `http://127.0.0.1:8787` | |
| `HSP_CHAIN` | default `anvil-dev` | registry chain name |
| `HSP_STABLECOIN_<CHAIN>` | anvil only | `0xTOKEN:SYMBOL:DECIMALS` for per-run tokens |
| `HSP_API_KEY` | sandbox | team bearer key |
| `HSP_ISSUER_URL` | for compliance | mock-issuer base URL |
| `HSP_MAX_AMOUNT_BASE_UNITS` | **set it** | per-payment cap, enforced server-side |
| `HSP_DAILY_CAP_BASE_UNITS` | **set it** | rolling daily cap, enforced server-side |
| `HSP_RECIPIENT_ALLOWLIST` | optional | comma-separated addresses; anything else is refused |
| `HSP_PINNED_ADAPTER_ADDRESS` | for `hsp_verify` | the observation address you pinned |

Register via [`.mcp.json.example`](../.mcp.json.example) or
`claude mcp add hsp-pay -- npx tsx packages/mcp/src/index.ts`.

### 5.3 The skill

`cp -r skills/hsp-pay ~/.claude/skills/` installs a payment skill that routes between PAY /
CHECK-STATUS / VERIFY-RECEIVED flows, enforces the quote → **explicit user approval** → pay → track
sequence, and explains failures by `outcomeClass` (retry the retryable, abandon the permanent).

---

## 6. Building an adapter — @hsp/devkit

An adapter plugs *any* settlement method into HSP — another chain, Lightning, a points system, an
exchange's internal ledger. Once a deployment registers it, payers can settle mandates through it.
No protocol changes, no permission from the spec.

### 6.1 What you implement

One object: an `AdapterProofSchema` with a single method, `verify(ctx) → VerifyOutcome`. It decodes
your `adapterProof` bytes and answers: is this settlement real, and what did it observably do? The
**four duties**:

| # | Duty | Why |
|---|---|---|
| D1 | **Decode + validate** the proof bytes; malformed → `ok: false` | the proof is attacker-controlled input |
| D2 | **Bind the settling party** to the mandate signer when your settlement exposes it | else anyone's settlement satisfies anyone's mandate |
| D3 | **Surface true observations** (amount/recipient/token/chain) from your settlement system — never echo the mandate | the verifier cross-checks them against the mandate |
| D4 | **Emit `observationId`** (hash of your settlement-native identity) unless your artifact is cryptographically bound to the mandateHash (x402-style) | one settlement must satisfy at most one mandate |

Plus: emitted capabilities must stay within your registered `allowedCapabilities` (fail-closed upper
bound), and pick your `reorgPolicy` honestly (`allowsAttempted`, `chainObservation`,
`disputeWindowMs`).

### 6.2 The conformance runner

```sh
cp packages/devkit/template/my-adapter.ts        my-team/adapter.ts
cp packages/devkit/template/run-conformance.ts   my-team/run-conformance.ts
# implement your proof + verify(), then:
npx tsx my-team/run-conformance.ts
```

The runner exercises the protocol's generic obligations against the **real verifier**, re-signing
every mutated receipt so the rule under test is what fails — never a stale signature:

1. happy case → `ACCEPT`
2. forged `adapterSignature` → `HSP-RCPT-SIG`
3. untrusted adapter instance → `HSP-RCPT-SIG` (`POLICY`)
4. broken mandate linkage → `HSP-RCPT-LINK`
5. replayed receipt → `HSP-RCPT-SEQ-STALE`
6. settled after the deadline → `HSP-MAND-EXPIRED`
7. post-`SETTLED` non-`DISPUTED` emission → `HSP-RCPT-OUTCOME-INCONSISTENT`
8. `DISPUTED` without a prior `SETTLED` → `HSP-RCPT-DISPUTE-NOPRIOR`
9. `observationId` emission report
10. the same observation against a second mandate → `HSP-RCPT-OBS-REUSED`
11. (optional) your own tamper cases

### 6.3 Identity & registration

```
adapterId          = keccak256("adapter:<your-name>")
proofSchemaId      = keccak256("<your-name>.proof.v1")    // any schema change ⇒ NEW id
adapterInstanceKey = bytes32(0), or keccak256(<instance discriminator>)
```

Ids are immutable once registered. To go live on the sandbox, submit to the organizers: the id
tuple (+ the names they hash from), your **operator signing address** (it attests observations — it
is not custody), your `reorgPolicy` + `allowedCapabilities`, and your schema module with a passing
conformance run. They add it to the Coordinator's trust tables; from then on
`POST /payments/:id/receipts` accepts your receipts and the Explorer renders your decision traces.

Reference implementations to crib from, in `@hsp/core/adapter/`: `mock-evm-transfer`
(wallet-settling) and `x402` (self-settling signature chain).

---

## 7. Walkthroughs

All four run against the sandbox today. Point at the hosted sandbox Coordinator the organizers give
you and set once:

```sh
export HSP_COORDINATOR_URL=<COORDINATOR_URL>  # the hosted sandbox Coordinator
export HSP_API_KEY=<your-team-key>
export HSP_CHAIN=hashkey-testnet
export HSP_PRIVATE_KEY=0x<funded key>        # fund it via the faucet first
```

### 7.1 Public payment (S1)

```sh
curl -X POST -H 'content-type: application/json' \
  -d '{"address":"0xYourAddress"}' <FAUCET_URL>/faucet   # gas + USDC

npx tsx examples/pay-demo.ts 0xRecipient 1000000
# paymentId 0x…   txHash 0x…   status SETTLED
```

Open `/explorer`, paste the paymentId: an empty required set, trivially satisfied → `ACCEPT`.

### 7.2 Compliant payment (S2)

```ts
const handle = await client.pay({ to, amount, profile: { compliance: ['kyc', 'sanctions'] } });
```

The Explorer trace now shows two required capabilities, each satisfied by an issuer attestation —
and the deployment's policy floor listed separately. Try paying *without* the profile on a
floor-enforcing deployment to see `HSP-MAND-REQ-INSUFFICIENT` fail fast.
Runnable: `npx tsx examples/compliance-pay-demo.ts 0xRecipient 1000000` (needs `HSP_ISSUER_URL`).

### 7.3 x402 machine payment (S3)

Use [§4.5](#45-x402--payx402) against the sandbox facilitator (`:8789`) — runnable:
`npx tsx examples/x402-pay-demo.ts 10000` (real EIP-3009 client-pull). With
pull you can verify on-chain that the funds left *your* address while the gas was paid by the
facilitator.

### 7.4 Verify like a merchant

```sh
export HSP_PINNED_ADAPTER_ADDRESS=0x<from GET /chains — then never fetch it again>
npx tsx examples/merchant-verify.ts 0x<paymentId>     # → SHIP / DO NOT SHIP
```

Flip one byte of the pinned address and watch verification fail — that failure is the security
property.

---

## 8. Environments

### 8.1 The hosted sandbox

| Service | Port | Notes |
|---|---|---|
| Coordinator (+ Explorer + portal) | `:8787` | the API base everything points at (`/explorer`, `/docs`) |
| Mock issuer | `:8788` | `attests:kyc` / `attests:sanctions` for test identities |
| x402 Facilitator | `:8789` | optional; conformant x402 v2 (`/supported`, `/verify`, `/settle`) |
| Faucet (+ claim page) | `:8790` | testnet gas + USDC, per-address cooldown |

### 8.2 Chains

| Name | Chain ID | Stablecoin | Notes |
|---|---|---|---|
| `hashkey-testnet` | 133 | USDC `0x8FE3cB71…06eF53c6` (6 dec, RPC-verified) | **start here** — faucet-friendly; RPC `testnet.hsk.xyz` |
| `anvil-dev` | 31337 | per-run MockERC20 | local development |
| `hashkey` | 177 | USDC.e `0x054ed458…c9D88D0a` (6 dec) | mainnet — real money |
| `ethereum` | 1 | USDC `0xA0b8…eB48` (6 dec) | mainnet — real money |

Always confirm against `GET /chains` on the deployment you're using — it also carries the
`adapterAddress` merchants pin.

### 8.3 Using the hosted sandbox

In this release the organizers host the Coordinator, mock issuer, x402 facilitator, and faucet for
you — you run nothing yourself. Point the SDK and MCP at the sandbox Coordinator URL the organizers
give you:

```sh
export HSP_COORDINATOR_URL=<COORDINATOR_URL>   # the hosted sandbox Coordinator
export HSP_API_KEY=<your-team-key>
```

The deployment is configured server-side with everything statements-only or rate-limited: the
Coordinator's observation-signing key, per-team API keys + optional compliance floor, the mock
issuer's pinned issuer addresses, the optional x402 facilitator, and the faucet drip/cooldown
settings. You only need your team key and the funded payer key from the faucet.

### 8.4 Local protocol development

No npm/node on the host — everything through Docker:

```sh
docker build -f docker/dev.Dockerfile -t hsp-dev .                  # node 24 + anvil + forge
docker run --rm -v "$PWD":/work -v hsp-node-modules:/work/node_modules hsp-dev \
  bash -lc "npm install && npm rebuild better-sqlite3 --ignore-scripts=false --foreground-scripts"
docker run --rm -v "$PWD":/work -v hsp-node-modules:/work/node_modules hsp-dev \
  bash -lc "npm run check && npm run e2e:public && npm run e2e:anvil"   # gates
```

`npm run check` runs every workspace's typecheck plus the conformance guard (re-derived typehashes)
and the 23 frozen conformance vectors. `npm run e2e:public` / `e2e:anvil` / `e2e:compliance`
exercise the protocol flows end-to-end (the anvil ones spawn their own chain), and
`npm run test:devkit` runs the adapter conformance.

---

## 9. Decision reference

### 9.1 outcomeClass — branch on this

| Class | Meaning | What to do |
|---|---|---|
| `ACCEPT` | settled and verified under the policy | **ship** |
| `RETRYABLE` | transient — not observable yet, stale signer state | remediate & resubmit |
| `POLICY` | this deployment doesn't admit a key / schema / capability / issuer | switch verifier or widen policy — the payment may be fine elsewhere |
| `PERMANENT` | the settlement contradicts the mandate | give up; inspect `errorCode` |

### 9.2 Payment status (Coordinator view)

`PROPOSED → ATTEMPTED → SETTLED | FAILED`, `SETTLED → DISPUTED` (sticky). `EXPIRED` is a read-time
view of `PROPOSED` past the deadline. Only verifier-admitted receipts transition status; everything
else accumulates in `rejectedSubmissions`.

### 9.3 Error codes

Codes are *informative* (branch on `outcomeClass`; log codes). Grouped by prefix:

**Mandate admission (`HSP-MAND-*`)**

| Code | Meaning |
|---|---|
| `HSP-MAND-DOMAIN` | EIP-712 domain / verifyingContract not accepted by this deployment |
| `HSP-MAND-CHAINID` | zero or inconsistent chain id |
| `HSP-MAND-SIGNER` | mandate signature invalid for the claimed signer |
| `HSP-MAND-SIGNER-PROFILE-UNKNOWN` | signer profile not admitted (POLICY) |
| `HSP-MAND-SIGNER-PAYLOAD-MALFORMED` | signer reference undecodable |
| `HSP-MAND-SIGNER-STATE-DRIFT` | signer-state anchor stale (e.g. rotated/revoked key) |
| `HSP-MAND-RECIPIENT-DECODE` / `HSP-MAND-TOKEN-DECODE` | recipient/token field undecodable |
| `HSP-MAND-REQHASH-MISMATCH` | envelope capability list ≠ signed `requiredCapabilitiesHash` |
| `HSP-MAND-REQ-INSUFFICIENT` | mandate doesn't require the deployment's policy floor |
| `HSP-MAND-EXPIRED` | settlement after the mandate deadline (`settledAt > deadline`) |
| `HSP-MAND-AMOUNT-OUTOFBOUNDS` | observed amount does not match the mandate's amount |

**Capability resolution (`HSP-CAP-*`)**

| Code | Meaning |
|---|---|
| `HSP-CAP-UNKNOWN` | capability id not in the deployment registry (POLICY) |
| `HSP-CAP-PARAMS-MALFORMED` | capability parameters fail their declared type |
| `HSP-CAP-NAMESPACE-VIOLATION` | a source claimed a capability its namespace forbids (e.g. an adapter emitting `attests:*`) |

**Receipt verification (`HSP-RCPT-*`, `HSP-PROOF-*`)**

| Code | Meaning |
|---|---|
| `HSP-RCPT-SIG` | receipt not signed by the trusted operator key for that adapter instance — check your pin |
| `HSP-RCPT-LINK` | receipt's `mandateHash` doesn't match the mandate under verification |
| `HSP-RCPT-SCHEMA-UNKNOWN` / `HSP-RCPT-SCHEMA-DEPRECATED` | proof schema not registered / retired (POLICY) |
| `HSP-RCPT-PROOF` | proof inconsistent with the mandate (amount/recipient/token/chain mismatch, broken binding) |
| `HSP-RCPT-SEQ-STALE` | replayed or out-of-order emission (seq not strictly increasing) |
| `HSP-RCPT-EQUIVOCATION` | same `(adapter, instance, mandate, seq)` with different content |
| `HSP-RCPT-OUTCOME-INCONSISTENT` | outcome-successor violation (e.g. anything but `DISPUTED` after `SETTLED`) |
| `HSP-RCPT-DISPUTE-NOPRIOR` | `DISPUTED` with no prior `SETTLED` |
| `HSP-RCPT-OBS-REUSED` | this settlement observation already satisfied another mandate |
| `HSP-RCPT-REQ-UNMET` | required capabilities not covered by proof ∪ attestations — the subset check itself |
| `HSP-PROOF-DECODE` / `HSP-PROOF-CRYPTO` | proof undecodable / cryptographic check failed |
| `HSP-PROOF-FIELD-MISSING` / `HSP-PROOF-FIELD-MALFORMED` | mandatory observation absent / malformed |
| `HSP-PROOF-CAP-NOT-DERIVED` | schema emitted a capability outside its registered upper bound |

**Attestations & lifecycle**

| Code | Meaning |
|---|---|
| `HSP-ATT-MISSING` | a required `attests:*` capability has no covering attestation |
| `HSP-ATT-INVALID` | attestation signature/validity-window/claims check failed |
| `HSP-ATT-ISSUER-UNTRUSTED` | issuer not in deployment trust anchors |
| `HSP-LCYC-DISPUTE-WINDOW-CLOSED` | `DISPUTED` outside the adapter's declared reversal window |
| `HSP-SUBJ-ROLE-UNRESOLVED` | a role-wrapped capability's subject couldn't be resolved |
| `HSP-RCPT-PROOF` | x402 EIP-3009 authorization doesn't bind to this mandate (signer/recipient/token/amount/chain) |

---

## 10. Trust model & security

**Who signs what:**

| Key | Signs | Can it move money? |
|---|---|---|
| payer's wallet | mandates; the settlement transfer itself | its own funds, as always |
| Coordinator's adapter key | observation receipts (evm-transfer **and** adapter:x402) | **no** — statements only |
| issuer keys | compliance attestations | **no** — statements only |
| facilitator key (x402) | verifies payments + relays the EIP-3009 settlement (does **not** sign HSP receipts) | only its own gas (the client's funds move via `transferWithAuthorization`) |

**The three rules:**

1. **Pin, don't fetch-and-trust.** Merchants record the adapter observation address once
   (out-of-band: `GET /chains` at setup time, the deployment's docs) and hardcode it. Never re-fetch
   trust anchors at decision time from the party you're refusing to trust.
2. **Demo keys are demo keys.** Example keys and the MCP agent key are for small testnet amounts.
   Production signing belongs in a wallet (`eip1193`) or a smart account; the spec's signer-profile
   system is the designed path for ERC-1271/4337 accounts.
3. **Caps on, always.** Any agent-held key runs behind `HSP_MAX_AMOUNT_BASE_UNITS` +
   `HSP_DAILY_CAP_BASE_UNITS` (+ allowlist). The faucet rate-limits per address. Team API keys are
   per-team — don't share them; they gate writes, not reads.

**Supply-chain posture of this repo** (inherit it): exact-pinned versions, repo-wide
`ignore-scripts=true`, every new dependency vetted (typosquats, advisories, transitive tree) before
install, all npm/node execution inside containers.

---

## 11. FAQ

**How does HSP relate to x402?**
x402 is a settlement transport; HSP is the verification layer above settlement. Here x402 is one
adapter (`adapter:x402`) whose EIP-3009 authorization (exact-EVM) becomes the receipt proof, bound to
your mandate. HSP doesn't compete with rails — it makes them verifiable.

**Where are my funds held?**
Nowhere new. Your wallet holds funds and broadcasts transfers; merchants receive directly. The
Coordinator's key can only sign statements about what it observed.

**Why did my payment reject with `HSP-RCPT-PROOF` when the transfer succeeded?**
Most often: amount not exactly equal to the mandate (fee-on-transfer token? rounding?), wrong
recipient, or a transaction with multiple Transfer logs. The public path is deliberately strict —
exact amount, exactly one matching log.

**Can the same on-chain transfer pay two invoices?**
No — `(chainId, token, txHash)` is consumed by the first mandate it settles; the second gets
`HSP-RCPT-OBS-REUSED` / HTTP 409. Issue distinct mandates (distinct nonces) and settle each
separately.

**What's the difference between `POLICY` and `PERMANENT`?**
`PERMANENT` means the settlement contradicts the mandate — no verifier should accept it. `POLICY`
means *this deployment* doesn't admit something (a schema, an issuer, a capability) — a different
deployment with different trust roots might legitimately accept the same triple.

**Is the spec final?**
No — pre-1.0 draft. Concepts are stable; wire details may change. The conformance gates (guard +
frozen vectors) mean any spec change that affects hashing is caught and re-frozen deliberately,
never silently.

**Can my team add a settlement method the organizers didn't think of?**
Yes — that's [§6](#6-building-an-adapter--hspdevkit). Pass conformance locally, submit the identity
tuple, get registered in the sandbox trust set.

---

*Further reading:* the [developer portal](../README.md#developer-portal) (`GET /docs` on any
Coordinator) for the 10-minute orientation ·
[`packages/devkit/README.md`](../packages/devkit/README.md) (adapter guide).
