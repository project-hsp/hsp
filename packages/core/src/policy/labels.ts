/**
 * Human labels for the Explorer — resolve a cap id (which is a keccak hash, not
 * reversible) to its human form by looking it up in the deployment's known cap
 * vocabulary, and name adapters + the structural caps each one contributes.
 * Display only; not on any verification path.
 */

import { formatCapability, type ParsedCapability } from '../core/capabilities.js';
import { EVM_TRANSFER_ADAPTER_ID } from '../adapter/mock-evm-transfer.js';
import { X402_ADAPTER_ID } from '../adapter/x402.js';
import { COMPLIANCE_REGISTRY_CAPS } from './compliance.js';

const KNOWN_CAPS: ParsedCapability[] = [...COMPLIANCE_REGISTRY_CAPS];

const LABELS = new Map<string, string>();
for (const c of KNOWN_CAPS) {
  LABELS.set(c.id.toLowerCase(), formatCapability(c));
  // attestations carry the BASE cap id (no role wrap) — index it too
  LABELS.set(c.baseId.toLowerCase(), formatCapability({ ...c, ...(c.role ? { role: undefined } : {}) } as ParsedCapability));
}

/** Cap id → human form, or a short hash when the cap is not in the known vocabulary. */
export function capLabel(id: string): string {
  return LABELS.get(id.toLowerCase()) ?? `${id.slice(0, 10)}…`;
}

export interface AdapterInfo {
  name: string;
  /** Structural caps this adapter's proof contributes (proofSatisfiedCapabilities). */
  contributes: string[];
}

const ADAPTERS = new Map<string, AdapterInfo>([
  [EVM_TRANSFER_ADAPTER_ID.toLowerCase(), { name: 'adapter:evm-transfer', contributes: [] }],
  [X402_ADAPTER_ID.toLowerCase(), { name: 'adapter:x402', contributes: [] }],
]);

export function adapterInfo(adapterId: string): AdapterInfo {
  return ADAPTERS.get(adapterId.toLowerCase()) ?? { name: `${adapterId.slice(0, 10)}…`, contributes: [] };
}
