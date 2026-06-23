/**
 * Shared infrastructure for verify.ts / freeze.ts:
 *   - discover fixture files under tests/vectors/
 *   - dispatch each derivation to the reference implementation in derivations.ts
 *   - read & write JSON fixture files preserving formatting
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  capabilityId,
  requiredCapabilitiesHash,
  mandateHash,
  receiptHash,
  preprocessInput,
  type CapabilityIdInput,
  type DomainInput,
  type MandateBodyInput,
  type ReceiptInput,
} from '@hsp/core/derivations';
import type { Hex } from 'viem';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const VECTORS_DIR = path.resolve(__dirname, '../../../vectors');

export interface VectorFile {
  spec_section: string;
  derivation: string;
  vectors: Vector[];
}

export interface Vector {
  id: string;
  description: string;
  spec_refs: string[];
  input: Record<string, unknown>;
  expected_output?: Record<string, unknown>;
}

export async function discoverFixtureFiles(root: string = VECTORS_DIR): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string): Promise<void> {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        await walk(full);
      } else if (e.isFile() && e.name.endsWith('.json') && e.name !== 'schema.json') {
        out.push(full);
      }
    }
  }
  await walk(root);
  return out.sort();
}

export async function readFixtureFile(file: string): Promise<VectorFile> {
  const txt = await fs.readFile(file, 'utf8');
  return JSON.parse(txt) as VectorFile;
}

export async function writeFixtureFile(file: string, data: VectorFile): Promise<void> {
  // 2-space indent; trailing newline. Stable serialization.
  await fs.writeFile(file, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

/**
 * Dispatch table: derivation name → (preprocessed input → expected_output object).
 *
 * Outputs follow the shapes documented in tests/vectors/README.md.
 */
export type DerivationOutput = Record<string, unknown>;

export function runDerivation(derivation: string, rawInput: Record<string, unknown>): DerivationOutput {
  const input = preprocessInput(derivation, rawInput);
  switch (derivation) {
    case 'capabilityId': {
      const id = capabilityId(input as unknown as CapabilityIdInput);
      return { id };
    }
    case 'requiredCapabilitiesHash': {
      const hash = requiredCapabilitiesHash(input['capabilities'] as Hex[]);
      return { hash };
    }
    case 'mandateHash': {
      const hash = mandateHash(input['domain'] as DomainInput, input['body'] as MandateBodyInput);
      return { hash };
    }
    case 'receiptHash': {
      const hash = receiptHash(input['domain'] as DomainInput, input['receipt'] as ReceiptInput);
      return { hash };
    }
    default:
      throw new Error(`Unknown derivation '${derivation}'`);
  }
}

export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return false;
  if (typeof a !== 'object') return false;
  const aObj = a as Record<string, unknown>;
  const bObj = b as Record<string, unknown>;
  const aKeys = Object.keys(aObj).sort();
  const bKeys = Object.keys(bObj).sort();
  if (aKeys.length !== bKeys.length) return false;
  for (let i = 0; i < aKeys.length; i++) {
    if (aKeys[i] !== bKeys[i]) return false;
    if (!deepEqual(aObj[aKeys[i]!], bObj[bKeys[i]!])) return false;
  }
  return true;
}
