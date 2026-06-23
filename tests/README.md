# HSP Conformance Tests

> **Status:** v1 working draft, Phase 1 (wire-level hashes only)
> **Last updated:** 2026-04-29

This directory holds the executable, machine-checkable counterpart to the prose specification under [`docs/protocol/`](../docs/protocol/). It exists because no amount of `MUST` clauses in prose can pin down byte-level interoperability — only fixed (input → expected_output) pairs can.

## Layout

```
tests/
├── vectors/                  ← language-agnostic fixture pack (the "spec-as-data")
│   ├── README.md             ← fixture schema, freezing/verification protocol
│   ├── schema.json           ← JSON Schema every fixture file conforms to
│   └── 01-wire-hashes/       ← Phase 1: pure hash derivations
│       ├── capability-id.json
│       ├── required-capabilities-hash.json
│       ├── authorization-ref.json
│       ├── intent-preimage-hash.json
│       └── mandate-hash.json
└── runners/
    └── ts/                   ← TypeScript reference runner (used to freeze + verify)
        ├── README.md
        ├── package.json
        ├── tsconfig.json
        └── src/
            ├── derivations.ts
            ├── freeze.ts
            └── verify.ts
```

## Phases

| Phase | Status | What it covers |
|---|---|---|
| 1 — Wire-level hash derivations | **active** | `mandateHash`, `intentPreimageHash`, `authorizationHash`, `requiredCapabilitiesHash`, capability id |
| 2 — Plug-in profile fixtures | not started | per-profile `verify` paths (`eip712-eoa.v1`, `hsp-ref-tree.v1`, `ap2-intent.v1`, attestation-resolver-template) |
| 3 — Adapter `IAdapterProofSchema` fixtures | not started | per-adapter `verify` + `parse` (rail-x402, rail-erc20-transfer, priv-privacy-pools-0xbow, priv-confidential-erc20-inco) |
| 4 — End-to-end verifier fixtures | not started | full (mandate, receipt, policy) → (accept/reject, errorCode); covers the 7-step algorithm in `receipt.md §3` and every code in `errors.md` |
| 5 — Cross-implementation agreement | not started | ≥ 2 independent reference implementations all pass Phase 1–4 |

## How conformance works

1. **Vectors are language-agnostic JSON.** Anyone implementing HSP can read `tests/vectors/**/*.json` directly — no language runtime required.
2. **Each vector specifies `input` and `expected_output`.** A conformant implementation, given `input`, MUST produce a value byte-equal to `expected_output`.
3. **A reference runner exists** under `tests/runners/ts/` which is the freeze authority. When `expected_output` is missing, running the freezer fills it from the reference implementation's computation; the file is committed; subsequent verification compares.
4. **Disagreements between independent implementations are spec bugs.** When implementation A passes and implementation B fails on the same fixture, exactly one of three things is true: (a) implementation B has a bug, (b) implementation A has a bug, (c) the spec is ambiguous. (c) is the most valuable outcome — it drives a prose clarification.

## Running the TS runner

```bash
cd tests/runners/ts
npm install
npm run verify      # asserts all expected_output match input → derivation
npm run freeze      # fills missing expected_output from input → derivation (use when adding a new fixture)
```

## What this is NOT

- **Not a runtime.** Fixtures cannot move tokens, validate adapters at runtime, or query resolvers. They pin the *shapes* and *hash derivations*; runtime concerns are deployment-policy questions.
- **Not exhaustive.** Fixtures cover representative cases per `MUST`; absence of a fixture for a corner case does not mean the corner case is undefined — it means it is not yet pinned. Add fixtures over time.
- **Not authoritative over the spec.** When a fixture and the spec disagree, the spec wins by default; the fixture is updated. The exception: cryptographic derivations (this directory) are the *machine-readable* spec for those derivations. If prose drifts, prose is what gets corrected.

## Adding a new fixture

1. Edit the relevant `tests/vectors/**/*.json` file. Add a vector with `id`, `description`, `spec_refs`, `input`. Leave `expected_output` absent.
2. Run `npm run freeze` from `tests/runners/ts/`.
3. Inspect the diff: did the freezer write the `expected_output` you expected? If yes, commit. If no, the spec is being interpreted differently than you intended — either fix the input, or open a spec issue.
4. Run `npm run verify` to confirm the frozen file passes.
