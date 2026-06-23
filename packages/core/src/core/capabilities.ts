/**
 * HSP capability tooling (HSP.md §3).
 *
 * Builds on the pinned `capabilityId` derivation (../derivations.ts, §3.1.1) and adds:
 *   - the §3.5 v1 baseline capability registry (cap families + param schemas + ordering);
 *   - role wrapping (§3.1.2) and the closed {payer, payee, auditor} role set;
 *   - human-form ⇄ structured ⇄ bytes32-id round-tripping;
 *   - canonical set form (§3.1.3) and the §3.3.3 strict + monotone-narrowing match.
 *
 * The bytes32 id math is delegated to `capabilityId` (guarded against HSP.md). The
 * monotone primitive `dominates()` works on STRUCTURED caps (real param values), so
 * the M2 verifier feeds it the candidate's structured values read from the
 * attestation `claims` (the decision recorded for the §3.3.3 bytes32-wire issue).
 */

import {
  capabilityId,
  type CanonicalParam,
  type CapabilityIdInput,
  type ParamType,
} from '../derivations.js';
import { keccak256, encodeAbiParameters, type Hex } from 'viem';

// =============================================================================
// §3.1.2 Roles — the closed v1 vocabulary (no extension-role mechanism).
// =============================================================================

export const Roles = { payer: 'payer', payee: 'payee', auditor: 'auditor' } as const;
export type RoleName = (typeof Roles)[keyof typeof Roles];
const ROLE_NAMES = new Set<string>(Object.values(Roles));

// =============================================================================
// §3.3.1 Capability registry — Base families with param schemas + ordering.
// =============================================================================

/** §3.3.1 ParamOrder — present ⇒ the param admits monotone narrowing (§3.3.3). */
export type ParamOrder = 'monotone-asc-enum' | 'monotone-desc-numeric';

export interface ParamSchema {
  name: string;
  type: ParamType; // string | uint256 | bytes32 | bool | address (§3.1.4)
  order?: ParamOrder;
  enumValues?: string[]; // ordered value list for monotone-asc-enum (later index dominates)
}

/** A Base cap family (namespace:name:version) plus its declared params. */
export interface CapFamily {
  namespace: string;
  name: string;
  version: string;
  params: ParamSchema[];
}

export const familyKey = (ns: string, name: string, version: string): string => `${ns}:${name}:${version}`;

/** §3.5 v1 baseline registry, keyed by "namespace:name:version". */
export const BASELINE_CAP_FAMILIES: Record<string, CapFamily> = (() => {
  const f = (namespace: string, name: string, params: ParamSchema[] = [], version = 'v1'): CapFamily => ({
    namespace,
    name,
    version,
    params,
  });
  const families: CapFamily[] = [
    // §3.5.1 hides:* — negative proof properties (no params).
    f('hides', 'sender'),
    f('hides', 'recipient'),
    f('hides', 'amount'),
    // §3.5.2 discloses:* — structural disclosures carried in adapterProof.
    f('discloses', 'viewing-key', [{ name: 'viewer', type: 'string' }]),
    f('discloses', 'selective-fields', [{ name: 'schemaHash', type: 'bytes32' }]),
    // §3.5.3 attests:* — external-issuer attestations (always role-wrapped when required).
    f('attests', 'sanctions'),
    f('attests', 'kyc', [
      { name: 'level', type: 'string', order: 'monotone-asc-enum', enumValues: ['basic', 'full'] },
    ]),
    f('attests', 'travel-rule'),
    f('attests', 'risk-score', [{ name: 'maxScore', type: 'uint256', order: 'monotone-desc-numeric' }]),
    f('attests', 'source-of-funds', [{ name: 'proofKind', type: 'string' }]),
    f('attests', 'disclosure', [{ name: 'kind', type: 'string' }]),
    // §3.5.4 proves:* — structural cryptographic properties of the proof.
    f('proves', 'source-of-funds'),
    f('proves', 'association-set', [
      { name: 'setRoot', type: 'bytes32' },
      { name: 'setMonotone', type: 'bool' },
      { name: 'setAuthority', type: 'bytes32' },
    ]),
    f('proves', 'recipient-frontrun-safe', [{ name: 'mode', type: 'string' }]),
    f('proves', 'quote-honored', [{ name: 'quoteHash', type: 'bytes32' }]),
    f('proves', 'settlement-verified', [{ name: 'via', type: 'string' }]),
  ];
  const reg: Record<string, CapFamily> = {};
  for (const fam of families) reg[familyKey(fam.namespace, fam.name, fam.version)] = fam;
  return reg;
})();

export type CapRegistry = Record<string, CapFamily>;

// =============================================================================
// Structured capability + id math
// =============================================================================

export interface CapParam {
  key: string;
  type: ParamType;
  value: string | boolean; // uint256 stored as decimal string; bool as boolean; hex/string as string
}

export interface ParsedCapability {
  role?: RoleName;
  namespace: string;
  name: string;
  version: string;
  params: CapParam[];
  baseId: Hex; // unwrapped capabilityId (§3.1.1)
  id: Hex; // role-wrapped id (§3.1.2) when role is set, else == baseId
}

/** §3.1.2: roleWrappedCapabilityId = keccak256(abi.encode("role", roleName, capabilityId)). */
export function roleWrap(roleName: RoleName, capId: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: 'string' }, { type: 'string' }, { type: 'bytes32' }],
      ['role', roleName, capId],
    ),
  );
}

function coerceParam(ps: ParamSchema, raw: string | bigint | boolean): string | boolean {
  switch (ps.type) {
    case 'bool':
      if (typeof raw === 'boolean') return raw;
      if (raw === 'true') return true;
      if (raw === 'false') return false;
      throw new Error(`param "${ps.name}": bool must be true|false, got ${String(raw)}`);
    case 'uint256':
      return BigInt(String(raw)).toString(); // validates integer + normalizes
    case 'string': {
      const v = String(raw);
      if (ps.order === 'monotone-asc-enum' && ps.enumValues && !ps.enumValues.includes(v)) {
        throw new Error(`param "${ps.name}": "${v}" not in enum [${ps.enumValues.join(', ')}]`);
      }
      return v;
    }
    case 'bytes32':
    case 'address': {
      const v = String(raw);
      if (!v.startsWith('0x')) throw new Error(`param "${ps.name}": ${ps.type} must be 0x-hex, got ${v}`);
      return v;
    }
  }
}

function buildFromFamily(
  family: CapFamily,
  raw: Record<string, string | bigint | boolean>,
): { params: CapParam[]; baseId: Hex } {
  const params: CapParam[] = [];
  for (const ps of family.params) {
    if (!(ps.name in raw)) {
      throw new Error(`${familyKey(family.namespace, family.name, family.version)}: missing param "${ps.name}"`);
    }
    params.push({ key: ps.name, type: ps.type, value: coerceParam(ps, raw[ps.name]!) });
  }
  for (const k of Object.keys(raw)) {
    if (!family.params.some((p) => p.name === k)) {
      throw new Error(`${familyKey(family.namespace, family.name, family.version)}: unknown param "${k}"`);
    }
  }
  const canon: CanonicalParam[] = params.map((p) => ({ key: p.key, type: p.type, value: p.value }));
  const input: CapabilityIdInput = {
    namespace: family.namespace,
    name: family.name,
    version: family.version,
    params: canon,
  };
  return { params, baseId: capabilityId(input) };
}

/** Build a structured capability from a family (or "ns:name:version" key) + param values. */
export function makeCap(
  familyOrKey: string | CapFamily,
  paramValues: Record<string, string | bigint | boolean> = {},
  role?: RoleName,
  registry: CapRegistry = BASELINE_CAP_FAMILIES,
): ParsedCapability {
  const family = typeof familyOrKey === 'string' ? registry[familyOrKey] : familyOrKey;
  if (!family) throw new Error(`HSP-CAP-UNKNOWN: ${String(familyOrKey)}`);
  const { params, baseId } = buildFromFamily(family, paramValues);
  return {
    role,
    namespace: family.namespace,
    name: family.name,
    version: family.version,
    params,
    baseId,
    id: role ? roleWrap(role, baseId) : baseId,
  };
}

// =============================================================================
// Human form ⇄ structured (§3.1.1). Canonical form only — no positional suffix
// shorthand (e.g. NOT `discloses:viewing-key:auditor`; use [viewer=auditor]).
// Grammar: [ "role[" ROLE "," ] NS ":" NAME [ ":" VERSION ] [ "[" K=V("," K=V)* "]" ] [ "]" ]
// =============================================================================

function parseBase(
  s: string,
  registry: CapRegistry,
): Pick<ParsedCapability, 'namespace' | 'name' | 'version' | 'params' | 'baseId'> {
  let head = s;
  let paramsStr = '';
  const lb = s.indexOf('[');
  if (lb >= 0) {
    if (!s.endsWith(']')) throw new Error(`malformed params (missing "]"): ${s}`);
    head = s.slice(0, lb);
    paramsStr = s.slice(lb + 1, -1);
  }
  const seg = head.split(':');
  let namespace: string, name: string, version: string;
  if (seg.length === 2) {
    namespace = seg[0]!;
    name = seg[1]!;
    version = 'v1';
  } else if (seg.length === 3) {
    namespace = seg[0]!;
    name = seg[1]!;
    version = seg[2]!;
    if (!/^v\d+$/.test(version)) throw new Error(`bad version "${version}" (expected vN): ${s}`);
  } else {
    throw new Error(`malformed capability head "${head}"`);
  }
  const family = registry[familyKey(namespace, name, version)];
  if (!family) throw new Error(`HSP-CAP-UNKNOWN: ${familyKey(namespace, name, version)}`);

  const raw: Record<string, string> = {};
  if (paramsStr.trim() !== '') {
    for (const kv of paramsStr.split(',')) {
      const eq = kv.indexOf('=');
      if (eq < 0) throw new Error(`malformed param "${kv}" (expected key=value)`);
      raw[kv.slice(0, eq).trim()] = kv.slice(eq + 1).trim();
    }
  }
  const { params, baseId } = buildFromFamily(family, raw);
  return { namespace, name, version, params, baseId };
}

/** Parse a human-form capability string into structured form + ids. */
export function parseHumanCapability(
  human: string,
  registry: CapRegistry = BASELINE_CAP_FAMILIES,
): ParsedCapability {
  const s = human.trim();
  if (s.startsWith('role[')) {
    if (!s.endsWith(']')) throw new Error(`malformed role wrapper (missing "]"): ${human}`);
    const inner = s.slice('role['.length, -1);
    const comma = inner.indexOf(',');
    if (comma < 0) throw new Error(`role wrapper needs "role[ROLE, baseCap]": ${human}`);
    const roleName = inner.slice(0, comma).trim();
    if (!ROLE_NAMES.has(roleName)) {
      throw new Error(`unknown role "${roleName}" (closed set: payer|payee|auditor)`);
    }
    const base = parseBase(inner.slice(comma + 1).trim(), registry);
    return { ...base, role: roleName as RoleName, id: roleWrap(roleName as RoleName, base.baseId) };
  }
  const base = parseBase(s, registry);
  return { ...base, id: base.baseId };
}

/** Structured → human form (for diagnostics, §3.3.2 C6). */
export function formatCapability(c: ParsedCapability): string {
  const paramStr = c.params.length ? `[${c.params.map((p) => `${p.key}=${String(p.value)}`).join(',')}]` : '';
  const base = `${c.namespace}:${c.name}:${c.version}${paramStr}`;
  return c.role ? `role[${c.role}, ${base}]` : base;
}

// =============================================================================
// §3.1.3 canonical set form + §3.3.3 matching
// =============================================================================

/** §3.1.3: dedupe + sort lexicographically as bytes32 (ascending byte order). */
export function canonicalizeCapSet(ids: Hex[]): Hex[] {
  const norm = ids.map((i) => i.toLowerCase() as Hex);
  return Array.from(new Set(norm)).sort();
}

/**
 * §3.3.3 monotone narrowing on STRUCTURED caps: does `candidate` dominate `required`?
 * Same family; un-ordered params byte-equal; each ordered param's candidate value
 * dominates the required value (asc-enum: candidate index ≥ required; desc-numeric:
 * candidate ≤ required). Role is NOT compared here — role binding is the verifier's
 * subjectBinding check (§5.2 step 5), kept separate.
 */
export function dominates(
  required: ParsedCapability,
  candidate: ParsedCapability,
  registry: CapRegistry = BASELINE_CAP_FAMILIES,
): boolean {
  if (
    required.namespace !== candidate.namespace ||
    required.name !== candidate.name ||
    required.version !== candidate.version
  ) {
    return false;
  }
  const family = registry[familyKey(required.namespace, required.name, required.version)];
  if (!family) return false;

  const rMap = new Map(required.params.map((p) => [p.key, p]));
  const cMap = new Map(candidate.params.map((p) => [p.key, p]));
  if (rMap.size !== cMap.size) return false; // differing param key sets → not a dominance relation

  for (const ps of family.params) {
    const r = rMap.get(ps.name);
    const c = cMap.get(ps.name);
    if (!r || !c) return false;
    if (ps.order === 'monotone-asc-enum') {
      const e = ps.enumValues ?? [];
      const ri = e.indexOf(String(r.value));
      const ci = e.indexOf(String(c.value));
      if (ri < 0 || ci < 0 || ci < ri) return false; // candidate must rank ≥ required
    } else if (ps.order === 'monotone-desc-numeric') {
      if (BigInt(String(c.value)) > BigInt(String(r.value))) return false; // candidate must be ≤ required
    } else if (String(r.value) !== String(c.value)) {
      return false; // un-ordered param must match exactly
    }
  }
  return true;
}

/**
 * §3.3.3 admissibility for a single candidate cap satisfying a required cap:
 * strict (base ids equal) OR — when the required cap declares any ordered param —
 * monotone narrowing. Compares on the BASE cap; role/subject binding is separate.
 */
export function capSatisfies(
  required: ParsedCapability,
  candidate: ParsedCapability,
  registry: CapRegistry = BASELINE_CAP_FAMILIES,
): boolean {
  if (required.baseId === candidate.baseId) return true; // strict (default path)
  const family = registry[familyKey(required.namespace, required.name, required.version)];
  if (!family || !family.params.some((p) => p.order)) return false; // no ordered param ⇒ strict only
  return dominates(required, candidate, registry);
}

/**
 * The unparameterized "family" cap id for a namespace:name:version — capabilityId
 * with empty params (the §6.1.5 wildcard form). Used to key per-family deployment
 * data (e.g. Issuer Trust Anchors) so a deployment trusts an issuer for "kyc"
 * regardless of level, covering monotone variants. Bypasses the param-required check.
 */
export function familyCapId(familyOrKey: string | CapFamily, registry: CapRegistry = BASELINE_CAP_FAMILIES): Hex {
  const family = typeof familyOrKey === 'string' ? registry[familyOrKey] : familyOrKey;
  if (!family) throw new Error(`HSP-CAP-UNKNOWN: ${String(familyOrKey)}`);
  return capabilityId({ namespace: family.namespace, name: family.name, version: family.version, params: [] });
}

/** Build the deployment Capability Registry (cap id → structured registered cap, §3.3.1). */
export function buildCapabilityRegistry(caps: ParsedCapability[]): Map<Hex, ParsedCapability> {
  const m = new Map<Hex, ParsedCapability>();
  for (const c of caps) m.set(c.id, c);
  return m;
}
