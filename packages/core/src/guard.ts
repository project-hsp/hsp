/**
 * Spec drift guard — pins the runner's EIP-712 struct definitions to the spec.
 *
 * The conformance vectors prove `viem(field-arrays) == frozen hashes`. On their
 * own that is circular: `freeze` writes the hashes from the same arrays `verify`
 * checks against, so neither catches the arrays drifting from HSP.md. This guard
 * closes the loop by proving `field-arrays == HSP.md`:
 *
 *   - parse the canonical type string the spec declares (§2.4.1 / §2.4.2 receiptHash), and
 *   - rebuild the same string from derivations.ts's exported field arrays.
 *
 * Any field add / remove / reorder / retype (the `notBefore` class of drift)
 * changes MANDATE_TYPEHASH, so the two strings diverge and this fails.
 *
 * Usage:  npm run guard   (also runs as part of `npm run verify`)
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MANDATE_FIELDS,
  GRANT_FIELDS,
  RECEIPT_PREIMAGE_FIELDS,
  NESTED_TYPES,
} from './derivations.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Vendored snapshot of the spec's typehash declarations (HSP.md §2.4.1/§2.4.2).
// The public repo ships this snapshot so guard is self-contained without the
// private normative spec; keep it in sync with HSP.md on any wire change.
export const HSP_MD = path.resolve(__dirname, '../spec/typehashes.md');

interface Field {
  readonly name: string;
  readonly type: string;
}
type NestedTypes = Record<string, readonly Field[]>;

/**
 * EIP-712 `encodeType`: the primary struct first, then every referenced struct
 * type sorted lexicographically by name (matches viem's internal encoding and
 * the spec's hand-written ordering).
 */
export function encodeType(primary: string, fields: readonly Field[], nested: NestedTypes): string {
  const fmt = (fs: readonly Field[]): string => fs.map((f) => `${f.type} ${f.name}`).join(',');
  const refs = new Set<string>();
  const visit = (fs: readonly Field[]): void => {
    for (const f of fs) {
      const base = f.type.replace(/\[\d*\]$/, ''); // strip any array suffix
      if (base in nested && !refs.has(base)) {
        refs.add(base);
        visit(nested[base]!);
      }
    }
  };
  visit(fields);
  const refStr = [...refs].sort().map((n) => `${n}(${fmt(nested[n]!)})`).join('');
  return `${primary}(${fmt(fields)})${refStr}`;
}

/**
 * Concatenate the quoted string literals inside `<constName> = keccak256( … )`
 * in HSP.md. The closing line of the keccak256 call is a bare `)` with no quotes,
 * which terminates the scan; `")"` lines (a quoted close-paren) are kept.
 */
export function parseSpecTypeString(md: string, constName: string): string {
  const lines = md.split('\n');
  const start = lines.findIndex((l) => l.includes(`${constName} = keccak256(`));
  if (start < 0) throw new Error(`${constName} not found in ${path.basename(HSP_MD)}`);
  const parts: string[] = [];
  for (let j = start + 1; j < lines.length; j++) {
    const line = lines[j]!;
    const quoted = [...line.matchAll(/"([^"]*)"/g)].map((m) => m[1]!);
    if (quoted.length > 0) parts.push(...quoted);
    else if (line.trim() === ')') return parts.join('');
    else if (line.trim() === '') continue;
    else throw new Error(`${constName}: unexpected line parsing type string: ${JSON.stringify(line)}`);
  }
  throw new Error(`${constName}: closing ")" not found after declaration`);
}

export interface GuardFailure {
  name: string;
  spec: string;
  runner: string;
}

const CHECKS = [
  { name: 'MANDATE_TYPEHASH', primary: 'Mandate', fields: MANDATE_FIELDS },
  { name: 'GRANT_TYPEHASH', primary: 'DelegationGrant', fields: GRANT_FIELDS },
  { name: 'RECEIPT_PREIMAGE_TYPEHASH', primary: 'ReceiptPreimage', fields: RECEIPT_PREIMAGE_FIELDS },
] as const;

export const GUARDED_COUNT = CHECKS.length;

export async function checkSpecTypehashDrift(): Promise<GuardFailure[]> {
  const md = await fs.readFile(HSP_MD, 'utf8');
  const nested = NESTED_TYPES as unknown as NestedTypes;
  const failures: GuardFailure[] = [];
  for (const c of CHECKS) {
    const spec = parseSpecTypeString(md, c.name);
    const runner = encodeType(c.primary, c.fields as readonly Field[], nested);
    if (spec !== runner) failures.push({ name: c.name, spec, runner });
  }
  return failures;
}

export function reportGuardFailures(failures: GuardFailure[]): void {
  for (const f of failures) {
    console.error(`  ${f.name}`);
    console.error(`    spec:   ${f.spec}`);
    console.error(`    runner: ${f.runner}`);
    console.error('');
  }
}

async function main(): Promise<void> {
  const failures = await checkSpecTypehashDrift();
  if (failures.length === 0) {
    console.log(`Spec typehash guard: OK — ${GUARDED_COUNT} typehash(es) pinned to the vendored spec snapshot.`);
    process.exit(0);
  }
  console.error(`\nSpec typehash guard: FAIL — ${failures.length} typehash(es) drifted from the vendored spec snapshot:\n`);
  reportGuardFailures(failures);
  process.exit(1);
}

// Run main() only when invoked directly (`npm run guard`), not when imported by verify.ts.
const invokedDirectly =
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main().catch((e) => {
    console.error(e);
    process.exit(2);
  });
}
