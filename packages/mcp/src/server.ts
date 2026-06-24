/**
 * HSP MCP server — a PURE, key-less reasoning surface over the HSP spec
 * (`@hsp/core` deterministic functions + `@hsp/sdk`'s HSPVerifier). It moves NO
 * money and holds NO key: every tool just constructs, verifies, or explains HSP
 * wire objects + capabilities + policy. (To actually pay, use @hsp/sdk.)
 *
 *   hsp_verify           — run the protocol verifier over (mandate, receipt[, attestations])
 *   hsp_explain          — the same decision, narrated: required vs provided caps, outcome
 *                          class → action, the error-code meaning, and the trust boundary
 *   hsp_inspect          — decode a mandate / receipt / attestation into plain fields
 *   hsp_capability       — resolve verb:object:version[params] → id + meaning, or list the vocabulary
 *   hsp_capability_diff  — required vs satisfied capability sets → what's missing
 *   hsp_build_requirements — emit a §7.7 MandateRequirements (what a payee advertises)
 *   hsp_check_requirements — does a mandate satisfy a given MandateRequirements?
 *   hsp_build_mandate    — construct an UNSIGNED MandateBody + its mandateHash (signing is external)
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { encodeAbiParameters, getAddress, keccak256, toHex, type Address, type Hex } from 'viem';
import {
  BASELINE_CAP_FAMILIES,
  canonicalizeCapSet,
  makeCap,
  mandateHash as computeMandateHash,
  requiredCapabilitiesHash,
  type Attestation,
  type MandateBody,
  type Receipt,
  type SignedMandate,
} from '@hsp/core';
import { capLabel } from '@hsp/core/policy/labels';
import { chainDomain, type ChainConfig } from '@hsp/core/chains/index';
import { eip712EoaSigner } from '@hsp/core/profiles/signer/eip712-eoa';
import { EVM_TRANSFER_ADAPTER_ID, decodeTransferProof } from '@hsp/core/adapter/mock-evm-transfer';
import { X402_ADAPTER_ID, x402InstanceKey } from '@hsp/core/adapter/x402';
import { decodeX402ExactProof } from '@hsp/core/adapter/x402-exact';
import { buildPublicRequirements, type MandateRequirements } from '@hsp/core/policy/public';
import { buildComplianceRequirements } from '@hsp/core/policy/compliance';
import { HSPVerifier, resolveComplianceCaps, type CompliancePolicyOpts } from '@hsp/sdk';
import type { ComplianceFamily } from '@hsp/core/policy/compliance';

export interface McpDeps {
  chain: ChainConfig;
  /** Pinned adapter signing address (evm-transfer AND x402 are signed by the Coordinator's one key). */
  pinnedAdapterAddress?: Address;
  /** x402 merchant domains the receipts are signed under (for verifying adapter:x402 receipts). */
  x402Domains?: string[];
  /** Issuer trust, when verifying compliant receipts. */
  compliance?: CompliancePolicyOpts;
}

// ─────────────────────────── helpers ───────────────────────────

const OUTCOME_ACTION: Record<string, string> = {
  ACCEPT: 'ship / treat the payment as good',
  RETRYABLE: 'transient — retry the same submission later (e.g. tx not yet observable / confirming)',
  POLICY: 'the payment cannot satisfy this deployment policy as-is — fix the mandate/attestations, do not blind-retry',
  PERMANENT: 'invalid evidence — give up on this submission (signature / binding / schema failure)',
};

function labelCaps(ids: readonly string[]): { id: string; meaning: string }[] {
  return ids.map((id) => ({ id, meaning: capLabel(id) }));
}

function buildVerifier(deps: McpDeps, adapterAddress: Address): HSPVerifier {
  const opts: ConstructorParameters<typeof HSPVerifier>[0] = { chain: deps.chain, adapterAddress };
  if (deps.x402Domains?.length) {
    opts.x402Facilitators = deps.x402Domains.map((d) => ({ instanceKey: x402InstanceKey(d), address: adapterAddress }));
  }
  if (deps.compliance) opts.compliance = deps.compliance;
  return new HSPVerifier(opts);
}

/** Decode the adapterProof of a receipt into a plain object, by adapterId. */
function decodeProof(receipt: Receipt): Record<string, unknown> {
  const aid = receipt.adapterId.toLowerCase();
  try {
    if (aid === EVM_TRANSFER_ADAPTER_ID.toLowerCase()) {
      const o = decodeTransferProof(receipt.adapterProof);
      return { kind: 'evm-transfer (operator-attested observation)', from: o.from, to: o.to, value: o.value.toString(), token: o.token, txHash: o.txHash };
    }
    if (aid === X402_ADAPTER_ID.toLowerCase()) {
      const p = decodeX402ExactProof(receipt.adapterProof);
      return { kind: 'x402 (EIP-3009 — payer-signed, cryptographic binding)', from: p.from, to: p.to, value: p.value.toString(), token: p.token, txHash: p.txHash, validBefore: p.validBefore };
    }
  } catch (e) {
    return { kind: 'undecodable', error: (e as Error).message };
  }
  return { kind: 'unknown-adapter', adapterId: receipt.adapterId };
}

function trustNote(receipt: Receipt, adapterAddress: Address): string {
  const aid = receipt.adapterId.toLowerCase();
  if (aid === X402_ADAPTER_ID.toLowerCase()) {
    return `payer↔payment binding is CRYPTOGRAPHIC (the proof carries the payer's EIP-3009 signature, re-checked by verify); you trust the pinned operator ${adapterAddress} ONLY for the settlement fact (txHash/settledAt). No proves:settlement-verified ⇒ that fact is operator-attested.`;
  }
  if (aid === EVM_TRANSFER_ADAPTER_ID.toLowerCase()) {
    return `the proof is an OPERATOR OBSERVATION (no payer signature in it); the from/to/value binding rests on the pinned operator ${adapterAddress} honestly observing the chain. Trust-min'd settlement would require proves:settlement-verified (not provided here).`;
  }
  return `trust the pinned operator ${adapterAddress} per the proof schema ${receipt.proofSchemaId}.`;
}

// ─────────────────────────── tool table ───────────────────────────

const A = (props: Record<string, unknown>, required: string[] = []) => ({ type: 'object', properties: props, required });
const S = (description: string) => ({ type: 'string', description });

const TOOLS = [
  {
    name: 'hsp_verify',
    description:
      'Run the protocol verifier over a received (mandate, receipt[, attestations]) — the pure HSP decision: ACCEPT iff requiredCapabilities ⊆ satisfiedCapabilities. Does NOT trust a Coordinator; pins the adapter signing address. Returns the AcceptDecision { ok, outcomeClass, errorCode } + a ship flag.',
    inputSchema: A(
      {
        mandate: { type: 'object', description: 'the SignedMandate JSON' },
        receipt: { type: 'object', description: 'the Receipt JSON' },
        attestations: { type: 'array', description: 'optional Attestation[] JSON' },
        adapterAddress: S('optional override of the pinned adapter signing address (0x…)'),
      },
      ['mandate', 'receipt'],
    ),
  },
  {
    name: 'hsp_explain',
    description:
      'Same decision as hsp_verify, but NARRATED for a human/agent: ship?, the outcomeClass → recommended action, the error-code meaning, the capabilities the mandate REQUIRES vs the attestations PROVIDED, and the trust boundary (what you are trusting, and whether the binding is cryptographic or operator-attested).',
    inputSchema: A(
      {
        mandate: { type: 'object', description: 'the SignedMandate JSON' },
        receipt: { type: 'object', description: 'the Receipt JSON' },
        attestations: { type: 'array', description: 'optional Attestation[] JSON' },
        adapterAddress: S('optional override of the pinned adapter signing address'),
      },
      ['mandate', 'receipt'],
    ),
  },
  {
    name: 'hsp_inspect',
    description:
      'Decode an HSP wire object (mandate / receipt / attestation) into plain, labelled fields — amount, recipient, token, deadline, required capabilities (with meanings), the decoded adapter proof, settledAt, and who signed what. Read-only; no verification.',
    inputSchema: A(
      {
        object: { type: 'object', description: 'a SignedMandate, Receipt, or Attestation JSON' },
        kind: S("optional hint: 'mandate' | 'receipt' | 'attestation' (auto-detected otherwise)"),
      },
      ['object'],
    ),
  },
  {
    name: 'hsp_capability',
    description:
      'Resolve a capability: given verb/object/version (+ optional params), returns its canonical id and meaning (makeCap). With NO verb, lists the baseline capability vocabulary (proves:* / attests:* / hides:* / discloses:*) so you learn the policy language.',
    inputSchema: A({
      verb: S("namespace, e.g. 'attests' | 'proves' | 'hides' | 'discloses' (omit to list the vocabulary)"),
      object: S("object, e.g. 'kyc' | 'sanctions' | 'settlement-verified'"),
      version: S("version, e.g. 'v1' (default v1)"),
      params: { type: 'object', description: 'optional capability params, e.g. { via: "zk" }' },
    }),
  },
  {
    name: 'hsp_capability_diff',
    description:
      'Compare two capability sets (canonicalized byte-for-byte, the verifier rule): returns what is MISSING from satisfied vs required (the gap a payment must close) and any extras. Each id is labelled with its meaning.',
    inputSchema: A(
      {
        required: { type: 'array', description: 'required capability ids (0x…)' },
        satisfied: { type: 'array', description: 'satisfied capability ids (0x…)' },
      },
      ['required', 'satisfied'],
    ),
  },
  {
    name: 'hsp_build_requirements',
    description:
      'Emit a §7.7 MandateRequirements object — what a PAYEE/deployment advertises it requires (policyHash, domain, signer profiles, required/offered capabilities, trusted issuers, admitted adapters). mode "public" = empty policy; mode "compliance" = requires the given KYC/sanctions issuers.',
    inputSchema: A({
      mode: S("'public' (default) | 'compliance'"),
      compliance: { type: 'array', description: 'for mode=compliance: tags to require, e.g. ["kyc","sanctions"]' },
      issuerAddress: S('for mode=compliance: the trusted issuer address (0x…)'),
    }),
  },
  {
    name: 'hsp_check_requirements',
    description:
      'Pre-flight: does a (proposed) mandate satisfy a given §7.7 MandateRequirements? Checks the mandate covers the deployment’s policyRequiredCapabilities and targets a supported domain/chain. Returns ok + what is missing — call this BEFORE paying.',
    inputSchema: A(
      {
        mandate: { type: 'object', description: 'the SignedMandate (or its body) JSON' },
        requirements: { type: 'object', description: 'a MandateRequirements JSON (from hsp_build_requirements or a deployment’s GET /requirements)' },
      },
      ['mandate', 'requirements'],
    ),
  },
  {
    name: 'hsp_build_mandate',
    description:
      'Construct an UNSIGNED MandateBody + its mandateHash for a payment intent (recipient, amount, token, deadline, capabilities). Signing is EXTERNAL (the payer signs the hash with their key, e.g. via @hsp/sdk) — this tool never signs and never moves money.',
    inputSchema: A(
      {
        to: S('recipient EVM address (0x…)'),
        amount: S('amount in token base units (decimal string)'),
        token: S('optional ERC-20 address; defaults to the chain-pinned stablecoin'),
        signer: S('the payer EVM address (0x…) that will sign'),
        deadline: { type: 'number', description: 'optional unix seconds; default now + 1h' },
        capabilities: { type: 'array', description: 'optional required capability ids (0x…)' },
      },
      ['to', 'amount', 'signer'],
    ),
  },
] as const;

function text(payload: unknown, isError = false): { content: { type: 'text'; text: string }[]; isError?: boolean } {
  const out: { content: { type: 'text'; text: string }[]; isError?: boolean } = {
    content: [{ type: 'text', text: JSON.stringify(payload, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2) }],
  };
  if (isError) out.isError = true;
  return out;
}

export function buildServer(deps: McpDeps): Server {
  const server = new Server({ name: 'hsp', version: '0.2.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: TOOLS as unknown as { name: string }[] }));

  const pinned = (override?: unknown): Address => {
    const a = (override as Address | undefined) ?? deps.pinnedAdapterAddress;
    if (!a) throw new Error('no pinned adapter address — set HSP_PINNED_ADAPTER_ADDRESS or pass adapterAddress');
    return getAddress(a);
  };

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    try {
      switch (req.params.name) {
        case 'hsp_verify': {
          const adapterAddress = pinned(args.adapterAddress);
          const decision = await buildVerifier(deps, adapterAddress).verify(
            args.mandate as SignedMandate,
            args.receipt as Receipt,
            (args.attestations as Attestation[] | undefined) ?? [],
          );
          return text({ ...decision, ship: decision.ok && decision.outcomeClass === 'ACCEPT' });
        }

        case 'hsp_explain': {
          const adapterAddress = pinned(args.adapterAddress);
          const mandate = args.mandate as SignedMandate;
          const receipt = args.receipt as Receipt;
          const attestations = (args.attestations as Attestation[] | undefined) ?? [];
          const decision = await buildVerifier(deps, adapterAddress).verify(mandate, receipt, attestations);
          return text({
            ship: decision.ok && decision.outcomeClass === 'ACCEPT',
            decision: { ok: decision.ok, outcomeClass: decision.outcomeClass, errorCode: decision.errorCode, errorDetail: decision.errorDetail },
            recommendedAction: OUTCOME_ACTION[decision.outcomeClass] ?? 'see errorCode',
            requiredCapabilities: labelCaps(mandate.requiredCapabilities ?? []),
            providedAttestations: attestations.map((a) => ({ issuer: a.issuerSignature ? 'signed' : 'unsigned', claims: a.claims })),
            settlement: decodeProof(receipt),
            trustBoundary: trustNote(receipt, adapterAddress),
          });
        }

        case 'hsp_inspect': {
          const o = args.object as Record<string, unknown>;
          const kind = (args.kind as string | undefined) ?? (o.body ? 'mandate' : o.adapterProof ? 'receipt' : o.claims ? 'attestation' : 'unknown');
          if (kind === 'mandate') {
            const m = o as unknown as SignedMandate;
            return text({
              kind: 'mandate (payer-signed intent)',
              signer: m.body.signer,
              recipient: m.body.recipient,
              token: m.body.token,
              amount: String(m.body.amount),
              chainId: m.body.chainId,
              deadline: m.body.deadline,
              requiredCapabilities: labelCaps(m.requiredCapabilities ?? []),
              signed: !!m.signerProof,
            });
          }
          if (kind === 'receipt') {
            const r = o as unknown as Receipt;
            return text({
              kind: 'receipt (adapter-operator attestation)',
              mandateHash: r.mandateHash,
              adapterId: r.adapterId,
              proofSchemaId: r.proofSchemaId,
              outcome: r.outcome,
              settledAt: r.settledAt,
              seq: r.seq,
              proof: decodeProof(r),
              operatorSigned: !!r.adapterSignature,
            });
          }
          if (kind === 'attestation') {
            const a = o as unknown as Attestation;
            return text({ kind: 'attestation (issuer statement)', issuer: a.issuer, claims: a.claims, schemaId: a.schemaId, signed: !!a.issuerSignature });
          }
          return text({ error: 'unknown-object', detail: 'pass kind: mandate | receipt | attestation' }, true);
        }

        case 'hsp_capability': {
          if (!args.verb) {
            const vocab = Object.values(BASELINE_CAP_FAMILIES).map((f) => ({
              family: `${f.namespace}:${f.name}:${f.version}`,
              params: (f.params ?? []).map((p) => p.name),
            }));
            return text({ vocabulary: vocab, note: 'capability = verb:object:version[params]; verbs: proves/attests/hides/discloses' });
          }
          const family = `${String(args.verb)}:${String(args.object)}:${String(args.version ?? 'v1')}`;
          const cap = makeCap(family, (args.params as Record<string, string | bigint | boolean>) ?? {});
          return text({ family, id: cap.id, baseId: cap.baseId, meaning: capLabel(cap.id), params: cap.params });
        }

        case 'hsp_capability_diff': {
          const required = canonicalizeCapSet((args.required as Hex[]) ?? []);
          const satisfied = new Set(canonicalizeCapSet((args.satisfied as Hex[]) ?? []).map((x) => x.toLowerCase()));
          const missing = required.filter((id) => !satisfied.has(id.toLowerCase()));
          return text({
            satisfiedAll: missing.length === 0,
            missing: labelCaps(missing),
            note: missing.length ? 'the payment must close this gap (a proof or attestation that satisfies each id) before it verifies' : 'required ⊆ satisfied — this set passes',
          });
        }

        case 'hsp_build_requirements': {
          const expiresAt = Math.floor(Date.now() / 1000) + 3600;
          let req: MandateRequirements;
          if (args.mode === 'compliance') {
            const tags = (args.compliance as string[] | undefined) ?? ['kyc', 'sanctions'];
            const issuerAddress = getAddress(String(args.issuerAddress)) as Address;
            req = buildComplianceRequirements(deps.chain, {
              expiresAt,
              trustedIssuers: tags.map((t) => ({ family: `attests:${t}:v1` as ComplianceFamily, issuerAddress })),
              policyRequiredCaps: resolveComplianceCaps(tags as never),
            });
          } else {
            req = buildPublicRequirements(deps.chain, { expiresAt });
          }
          return text(req);
        }

        case 'hsp_check_requirements': {
          const req = args.requirements as MandateRequirements;
          const m = args.mandate as SignedMandate;
          const have = new Set((m.requiredCapabilities ?? []).map((x) => x.toLowerCase()));
          const missing = (req.policyRequiredCapabilities ?? []).filter((id) => !have.has(id.toLowerCase()));
          const chainOk = req.domain.chainIds.includes(Number(m.body.chainId));
          return text({
            ok: missing.length === 0 && chainOk,
            chainOk,
            missingRequiredCapabilities: labelCaps(missing),
            note:
              missing.length || !chainOk
                ? 'this mandate would NOT satisfy the deployment — add the missing caps (and matching attestations) / use a supported chain before paying'
                : 'mandate covers the deployment’s required capabilities + a supported chain',
          });
        }

        case 'hsp_build_mandate': {
          const token = (args.token as Address | undefined) ?? deps.chain.stablecoin.address;
          const deadline = (args.deadline as number | undefined) ?? Math.floor(Date.now() / 1000) + 3600;
          const caps = (args.capabilities as Hex[] | undefined) ?? [];
          const body: MandateBody = {
            nonce: toHex(keccak256(toHex(`${args.signer}:${args.to}:${args.amount}:${deadline}`))).slice(0, 66) as Hex,
            signer: { profileId: eip712EoaSigner.profileIdHash, payload: encodeAbiParameters([{ type: 'address' }], [getAddress(String(args.signer))]) },
            recipient: { kind: 0, payload: encodeAbiParameters([{ type: 'address' }], [getAddress(String(args.to))]) },
            token: getAddress(token),
            amount: String(args.amount),
            chainId: deps.chain.chainId,
            deadline,
            requiredCapabilitiesHash: requiredCapabilitiesHash(caps),
          };
          const hash = computeMandateHash(chainDomain(deps.chain), body);
          return text({
            mandateBody: body,
            mandateHash: hash,
            requiredCapabilities: labelCaps(caps),
            next: 'sign mandateHash with the payer key (e.g. @hsp/sdk signMandate) — this tool does NOT sign or move money',
          });
        }

        default:
          return text({ error: 'unknown-tool', tool: req.params.name }, true);
      }
    } catch (e) {
      return text({ error: 'tool-failed', detail: (e as Error).message }, true);
    }
  });

  return server;
}
