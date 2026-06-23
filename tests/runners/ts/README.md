# HSP Conformance Runner (TypeScript)

> **Status:** Phase 1 (wire-level hashes only)
> **Reference for the freeze authority of [`tests/vectors/`](../../vectors/).**

This is the TypeScript reference runner. It implements the canonical hash derivations from the HSP spec and uses them to either:

- **freeze** missing `expected_output` values into fixture files (when adding new fixtures),
- **verify** that every committed `expected_output` matches what the reference implementation computes from `input`, or
- **guard** that the runner's EIP-712 struct definitions still match `HSP.md` — without this the freeze/verify loop is circular (vectors are frozen from the same code that checks them), so the guard is what actually pins the pack to the spec.

## Files

```
src/
├── derivations.ts   The five Phase-1 hash derivations. ALL spec-traceable code lives here.
├── guard.ts         Pins the EIP-712 struct definitions to HSP.md §2.4.1/§2.4.2 (spec drift guard).
├── freeze.ts        Reads vectors/**, fills missing expected_output, writes back.
└── verify.ts        Reads vectors/**, recomputes from input, asserts byte-equality + runs the guard.
```

## Running

```bash
npm install
npm run verify   # vectors + spec drift guard (this is what CI runs)
npm run freeze   # fill missing expected_output for new fixtures
npm run guard    # spec drift guard only
```

Both scripts walk `../../vectors/**/*.json` (relative to this directory), dispatch each file's `derivation` field to the matching reference function, and operate per-vector.

## Adding a new derivation (Phase 2+)

1. Add a function in `src/derivations.ts` whose name matches a new value of the `derivation` enum in `tests/vectors/schema.json`.
2. Extend the `schema.json` enum.
3. Extend the dispatch tables in `src/verify.ts` and `src/freeze.ts`.
4. Add a fixture file under `tests/vectors/NN-...` and run `npm run freeze`.

## Why TypeScript

- viem provides byte-equal EIP-712 typed-data hashing and ABI encoding compatible with Solidity / ethers / Solidity-test outputs.
- Any conformant implementation in any language can read the JSON fixture pack directly; the runner exists only to compute reference outputs and verify drift.
