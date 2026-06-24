# HSP

A settlement-verification protocol for agent payments: a payer signs a
**Mandate** (EIP-712 intent), any **Adapter** settles it (bare ERC-20 transfer,
x402, …) and emits a signed **Receipt**, and a **Verifier**
accepts iff `requiredCapabilities ⊆ satisfiedCapabilities` — compliance
(`attests:kyc`, `attests:sanctions`) is a first-class, toggleable capability,
not a bolt-on.

- **Developer guide (detailed):** [`docs/guide.md`](docs/guide.md) — concepts, full API reference, walkthroughs, error codes
- **Hackathon onboarding:** [`docs/hsp-hackathon-guide.md`](docs/hsp-hackathon-guide.md) — what HSP is, what you can build, and your first payment in five minutes
- **This repo is the developer toolchain** — point it at a hosted Coordinator and pay:

```
skills/hsp-verify  AI skill: verify/explain/inspect, no money    — how an AI reasons about pay
packages/mcp       MCP server: pure/key-less verify/explain/build — how an AI reasons over HSP
packages/sdk       HSPClient.pay() one-call / HSPVerifier.verify() — how a developer pays
packages/devkit    build & conformance-test your own adapter      — extend the protocol
packages/core      protocol core: types, hashes, verifier,        — the reference implementation
                   adapters (evm-transfer/x402), attestations
```

The **Coordinator** — the REST hub that registers mandates, observes settlement, runs the
verifier, and serves the Explorer + `/docs` portal — is a **hosted service** you point your SDK
at. It is not built from this repo; the organizer runs it for the hackathon.

## Trust model in one paragraph

The Coordinator is **custody-free**: your wallet signs the mandate AND
broadcasts the ERC-20 transfer (`Transfer.from` must equal the mandate signer
— enforced by the proof schema). The Coordinator only *observes* the chain,
signs what it saw (its "adapter key" attests observations, it cannot move
money), verifies, stores the `(mandate, receipts[, attestations])` triple and
serves status. A merchant never has to believe it: pin the adapter address
once and run `HSPVerifier.verify()` yourself — *ACCEPT means ship*.

## Quickstart (everything runs in Docker — no npm on your host)

```sh
# 0. build the dev container (node 24 + anvil)
docker build -f docker/dev.Dockerfile -t hsp-dev .

# 1. install deps into a named volume (re-run only after lockfile changes)
docker run --rm -v "$PWD":/work -v hsp-node-modules:/work/node_modules hsp-dev \
  bash -lc "npm install && npm rebuild better-sqlite3 --ignore-scripts=false --foreground-scripts"

# 2. gates: conformance (guard+23 vectors) + typecheck + 34 protocol e2e
docker run --rm -v "$PWD":/work -v hsp-node-modules:/work/node_modules hsp-dev \
  bash -lc "npm run check && npm run e2e:public && npm run e2e:anvil"

# 3. compliance e2e + your-own-adapter devkit conformance
docker run --rm -v "$PWD":/work -v hsp-node-modules:/work/node_modules hsp-dev \
  bash -lc "npm run e2e:compliance && npm run test:devkit"
```

Pay in ~10 lines: see [`examples/pay-demo.ts`](examples/pay-demo.ts); verify
independently as a merchant: [`examples/merchant-verify.ts`](examples/merchant-verify.ts).
Scenario demos: [`compliance-pay-demo.ts`](examples/compliance-pay-demo.ts) (KYC+sanctions),
[`compliance-x402-demo.ts`](examples/compliance-x402-demo.ts) (KYC+sanctions over x402),
[`x402-pay-demo.ts`](examples/x402-pay-demo.ts) (machine payment, conformant x402 v2) and [`x402-fetch-demo.ts`](examples/x402-fetch-demo.ts) (pay any x402-gated URL).

## Using the hosted sandbox

The organizer hosts the full stack — Coordinator (+ Explorer + the `/docs` portal), a mock
compliance Issuer, an x402 Facilitator, and a testnet Faucet — on HashKey Chain testnet, so you
run nothing yourself. Point the SDK at the Coordinator URL the organizer gives you, claim
funds from the faucet (`POST <FAUCET_URL>/faucet {address}` → gas + USDC, rate-limited per
address &amp; IP), and pay. The five-minute walkthrough lives in
[`docs/hsp-hackathon-guide.md`](docs/hsp-hackathon-guide.md).

## Coordinator API

Public reads need no key; writes + the detail list need `Authorization: Bearer <key>`.

```sh
BASE=<COORDINATOR_URL>; KEY=<your-team-key>   # the hosted sandbox + your /register key

curl $BASE/healthz                                  # liveness
curl $BASE/chains                                   # chain registry + adapterAddress (PIN this)
curl "$BASE/requirements?chain=anvil-dev"           # §7.7 MandateRequirements (normative format)
curl $BASE/stats                                    # public aggregate counts
curl -H "Authorization: Bearer $KEY" "$BASE/payments?status=SETTLED&limit=20"

# register a signed mandate (the SDK does this for you)
curl -X POST -H "Authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d '{"chain":"anvil-dev","mandate":{…SignedMandate…}}' $BASE/payments
curl $BASE/payments/0x<paymentId>                   # status + receipts + rejectedSubmissions
curl -X POST -H "Authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d '{"txHash":"0x…"}' $BASE/payments/0x<paymentId>/observe
curl -X POST -H "Authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d '{"receipt":{…Receipt…}}' $BASE/payments/0x<paymentId>/receipts
```

Semantics worth knowing:

- `paymentId` **is** the mandate hash — recompute it client-side; registration is idempotent.
- Only **admitted** receipts (verifier ACCEPT'ed inputs) change status; a bad
  submission lands in `rejectedSubmissions` and never kills the payment.
- One on-chain transfer settles **at most one** payment
  (`(chainId, token, txHash)` uniqueness) — replaying a tx against a second
  mandate gets `409 observation-reuse`.
- `202` from observe = tx not mined / not enough confirmations yet — retry.

## Reading a decision (`outcomeClass`)

| class | meaning | what to do |
|---|---|---|
| `ACCEPT` | settled + verified | ship |
| `RETRYABLE` | transient (not observable yet, stale state) | remediate + resubmit |
| `POLICY` | this deployment doesn't admit a key/schema/cap | switch verifier or widen policy |
| `PERMANENT` | settlement contradicts the mandate | give up; inspect `errorCode` |

Frequent `errorCode`s: `HSP-MAND-EXPIRED` (settled after the mandate deadline — an on-time settlement stays verifiable later),
`HSP-RCPT-SIG` (receipt not signed by a trusted adapter — check your pin),
`HSP-RCPT-PROOF` (amount/recipient/token mismatch — exact-amount only; no
fee-on-transfer, batch, or multi-log txs on the public path).

## Developer portal

Every Coordinator serves a zero-dependency developer portal at **`GET /docs`**
(the root `/` redirects there): what HSP is, the four scenarios, per-layer
integration snippets, the five-minute first payment, sandbox services and
chains (live from the Coordinator's own API), decision/error reference, trust
model and FAQ. It is the one link to hand to a hackathon participant.

## Explorer

The Coordinator serves a zero-dependency Explorer at **`GET /explorer`** — the
one view no other payment rail has: the verifier's accept decision as a subset
chain `policyRequired ⊆ requiredCapabilities ⊆ satisfied (proof ∪ attestation)`,
with every cap id resolved to its human form. Open it in a browser; paste an API
key to list payments, or deep-link a single one: `/explorer?id=0x<paymentId>`
(public, read-only). Backed by `GET /payments/:id/explain`, the label-resolved
decision trace (also useful as an API).

## AI integration

- **MCP**: copy [`.mcp.json.example`](.mcp.json.example) into your `.mcp.json`
  (or `claude mcp add`). The server is **pure / key-less** — eight tools that
  construct, verify, and explain HSP wire objects + capabilities + policy
  (`hsp_verify`, `hsp_explain`, `hsp_inspect`, `hsp_capability`,
  `hsp_capability_diff`, `hsp_build_requirements`, `hsp_check_requirements`,
  `hsp_build_mandate`). It moves no money and holds no key; only `HSP_CHAIN` is
  required (optional: `HSP_PINNED_ADAPTER_ADDRESS`, `HSP_X402_DOMAINS`,
  `HSP_COMPLIANCE_ISSUER` widen what `hsp_verify` can check). **To actually pay,
  use `@hsp/sdk`** (`HSPClient.pay` / `payX402`).
- **Skill**: `cp -r skills/hsp-verify ~/.claude/skills/` — an AI skill that
  verifies & reasons about HSP payments (verify / explain / inspect / capabilities /
  requirements); moves no money. To pay, use `@hsp/sdk`.

## Chains

| name | chainId | stablecoin | note |
|---|---|---|---|
| `ethereum` | 1 | USDC `0xA0b8…eB48` (Circle, 6 dec) | mainnet — real money |
| `hashkey` | 177 | USDC.e `0x054ed458…c9D88D0a` (6 dec, RPC-verified) | mainnet — real money; RPC `mainnet.hsk.xyz` |
| `hashkey-testnet` | 133 | USDC `0x8FE3cB71…06eF53c6` (6 dec, RPC-verified) | faucet-friendly; RPC `testnet.hsk.xyz` |
| `anvil-dev` | 31337 | per-run MockERC20 | local dev/test |

## Supply-chain posture

Pinned exact versions everywhere; repo-wide `.npmrc ignore-scripts=true`
(better-sqlite3 is the single reviewed `npm rebuild` exception); every new
dependency is vetted (typosquat / advisories / transitive tree, `npm audit` =
0 on the proposed tree) before install; all npm/node execution happens inside
the dev container, never on the host.

## Build your own adapter (devkit)

Teams can plug their own settlement method into HSP: copy the compiling
template in [`packages/devkit/template/`](packages/devkit/template/my-adapter.ts),
implement your proof + `verify()`, then self-test against the real verifier —
`npx tsx your/run-conformance.ts` exercises happy ACCEPT, forged signature,
untrusted instance, replay, settled-after-deadline, successor rules and
observation reuse, re-signing every mutant. When everything passes, submit
`(adapterId, instanceKey, signing address, reorgPolicy)` to the organizers to
get registered in the sandbox Coordinator. Full guide:
[`packages/devkit/README.md`](packages/devkit/README.md).

## License

[Apache-2.0](LICENSE) — including an explicit patent grant and defensive
termination, the standard for protocol reference implementations. Contributions
are accepted under the same terms (see [NOTICE](NOTICE)).

## Conformance & protocol work

The implementation is guarded against drift: `npm run guard` re-derives the
EIP-712 typehashes; `npm run verify` replays 23 frozen vectors;
`npm run e2e:*` exercise public / compliance flows end-to-end (34 checks).
Protocol findings discovered while building this stack (observation reuse,
deadline anchoring, outcome ordering) are tracked for spec feedback — see the
plan in the repo history.
