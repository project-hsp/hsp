/**
 * Verify mode: read every fixture file, recompute expected_output from input,
 * assert byte-equality with the committed expected_output. Any drift fails.
 *
 * Usage:
 *   npm run verify
 */

import {
  discoverFixtureFiles,
  readFixtureFile,
  runDerivation,
  deepEqual,
  VECTORS_DIR,
} from './runner-core.js';
import { checkSpecTypehashDrift, reportGuardFailures, GUARDED_COUNT } from '@hsp/core/guard';
import path from 'node:path';

interface Failure {
  file: string;
  vectorId: string;
  reason: string;
  expected?: unknown;
  actual?: unknown;
}

async function main(): Promise<void> {
  const files = await discoverFixtureFiles();
  const failures: Failure[] = [];
  let totalVectors = 0;

  for (const file of files) {
    const rel = path.relative(VECTORS_DIR, file);
    const data = await readFixtureFile(file);
    for (const v of data.vectors) {
      totalVectors++;
      if (!v.expected_output) {
        failures.push({
          file: rel,
          vectorId: v.id,
          reason: 'expected_output is missing — run `npm run freeze` to fill it.',
        });
        continue;
      }
      let actual: Record<string, unknown>;
      try {
        actual = runDerivation(data.derivation, v.input);
      } catch (e) {
        failures.push({
          file: rel,
          vectorId: v.id,
          reason: `derivation threw: ${(e as Error).message}`,
        });
        continue;
      }
      if (!deepEqual(actual, v.expected_output)) {
        failures.push({
          file: rel,
          vectorId: v.id,
          reason: 'computed output does not match committed expected_output',
          expected: v.expected_output,
          actual,
        });
      }
    }
  }

  // Spec drift guard: pin the runner's struct definitions to HSP.md. Without this,
  // verify is circular (vectors are frozen from the same arrays they check against).
  const guardFailures = await checkSpecTypehashDrift();

  console.log(`Read ${files.length} fixture file(s), ${totalVectors} vector(s).`);
  if (failures.length === 0 && guardFailures.length === 0) {
    console.log(`OK — all ${totalVectors} vectors match; ${GUARDED_COUNT} typehash(es) pinned to HSP.md.`);
    process.exit(0);
  }

  if (failures.length > 0) {
    console.error(`\nFAIL — ${failures.length} vector(s) failed:\n`);
    for (const f of failures) {
      console.error(`  ${f.file}  ::  ${f.vectorId}`);
      console.error(`    ${f.reason}`);
      if (f.expected !== undefined) {
        console.error(`    expected: ${JSON.stringify(f.expected)}`);
        console.error(`    actual:   ${JSON.stringify(f.actual)}`);
      }
      console.error('');
    }
  }

  if (guardFailures.length > 0) {
    console.error(`\nSPEC DRIFT — ${guardFailures.length} typehash(es) diverge from HSP.md:\n`);
    reportGuardFailures(guardFailures);
  }
  process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
