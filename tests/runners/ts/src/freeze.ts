/**
 * Freeze mode: read every fixture file, fill missing `expected_output` from
 * the reference derivation. Existing `expected_output` values are NOT overwritten
 * (so freezing twice is idempotent and never silently changes a committed value).
 *
 * To intentionally re-freeze a vector, delete its `expected_output` first; the PR
 * description MUST then explain which side (spec vs runner) moved.
 *
 * Usage:
 *   npm run freeze
 */

import {
  discoverFixtureFiles,
  readFixtureFile,
  writeFixtureFile,
  runDerivation,
  VECTORS_DIR,
} from './runner-core.js';
import path from 'node:path';

async function main(): Promise<void> {
  const files = await discoverFixtureFiles();
  let frozen = 0;
  let untouched = 0;
  let errored = 0;

  for (const file of files) {
    const rel = path.relative(VECTORS_DIR, file);
    const data = await readFixtureFile(file);
    let dirty = false;
    for (const v of data.vectors) {
      if (v.expected_output) {
        untouched++;
        continue;
      }
      try {
        v.expected_output = runDerivation(data.derivation, v.input);
        console.log(`  FROZE   ${rel}  ::  ${v.id}  →  ${JSON.stringify(v.expected_output)}`);
        frozen++;
        dirty = true;
      } catch (e) {
        console.error(`  ERROR   ${rel}  ::  ${v.id}  →  ${(e as Error).message}`);
        errored++;
      }
    }
    if (dirty) {
      await writeFixtureFile(file, data);
    }
  }

  console.log(`\nFreeze summary: ${frozen} frozen, ${untouched} already had expected_output, ${errored} errored.`);
  process.exit(errored > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
