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
import {
  createPublicClient,
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  http,
  keccak256,
  parseAbi,
  recoverAddress,
  toHex,
  type Address,
  type Hex,
} from 'viem';
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
import { toCaip2 } from '@hsp/core/x402/index';
import {
  HSPVerifier,
  resolveComplianceCaps,
  mandateTypedData,
  eip3009TypedData,
  type CompliancePolicyOpts,
  type Eip3009Authorization,
} from '@hsp/sdk';
import type { ComplianceFamily } from '@hsp/core/policy/compliance';

export interface McpDeps {
  chain: ChainConfig;
  /** Pinned adapter signing address (evm-transfer AND x402 are signed by the Coordinator's one key). */
  pinnedAdapterAddress?: Address;
  /** x402 merchant domains the receipts are signed under (for verifying adapter:x402 receipts). */
  x402Domains?: string[];
  /** Issuer trust, when verifying compliant receipts. */
  compliance?: CompliancePolicyOpts;
  /** For hsp_prepare_payment / hsp_submit_payment: the Coordinator to register + observe through.
   *  This is a URL + a write API key — NOT a signing key; the MCP still holds NO private key
   *  (the actual signature comes from an external wallet, e.g. a wallet MCP). */
  coordinatorUrl?: string;
  apiKey?: string;
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

const ERC20_TRANSFER = parseAbi(['function transfer(address,uint256)']);
const ERC20_DOMAIN = parseAbi(['function name() view returns (string)', 'function version() view returns (string)']);

/** Build an unsigned MandateBody + its mandateHash (random nonce — distinct payments don't collide). */
function buildMandateBody(deps: McpDeps, p: { payer: Address; to: Address; amount: string; token: Address; deadline: number; caps: Hex[] }): { body: MandateBody; mandateHash: Hex } {
  const body: MandateBody = {
    nonce: toHex(crypto.getRandomValues(new Uint8Array(32))),
    signer: { profileId: eip712EoaSigner.profileIdHash, payload: encodeAbiParameters([{ type: 'address' }], [getAddress(p.payer)]) },
    recipient: { kind: 0, payload: encodeAbiParameters([{ type: 'address' }], [getAddress(p.to)]) },
    token: getAddress(p.token),
    amount: p.amount,
    chainId: deps.chain.chainId,
    deadline: p.deadline,
    requiredCapabilitiesHash: requiredCapabilitiesHash(p.caps),
  };
  return { body, mandateHash: computeMandateHash(chainDomain(deps.chain), body) };
}

/** HTTP to the Coordinator with the (optional) write API key. NOT a signing key. */
async function coordHttp(deps: McpDeps, method: string, path: string, body?: unknown): Promise<{ status: number; json: unknown }> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (deps.apiKey) headers.authorization = `Bearer ${deps.apiKey}`;
  const init: RequestInit = { method, headers };
  if (body !== undefined) init.body = JSON.stringify(body);
  const res = await fetch(`${deps.coordinatorUrl!.replace(/\/$/, '')}${path}`, init);
  let json: unknown = null;
  try {
    json = await res.json();
  } catch {
    /* non-JSON */
  }
  return { status: res.status, json };
}

/** eip712-eoa.v1 requires v ∈ {27,28}; some wallets return v ∈ {0,1}. */
function normalizeV(sig: Hex): Hex {
  if (sig.length !== 132) return sig;
  const v = parseInt(sig.slice(130, 132), 16);
  return v === 0 || v === 1 ? ((sig.slice(0, 130) + (v + 27).toString(16).padStart(2, '0')) as Hex) : sig;
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
  {
    name: 'hsp_prepare_payment',
    description:
      "PREPARE a payment for an EXTERNAL signer (a wallet MCP / the user's wallet) — this tool holds NO key and signs nothing. Returns the unsigned things to sign in STANDARD wallet-RPC shapes: the HSP mandate (eth_signTypedData_v4) + the settlement (evm-transfer = eth_sendTransaction; x402 = eth_signTypedData_v4 EIP-3009). Route each toSign[].method to your wallet MCP, then call hsp_submit_payment.",
    inputSchema: A(
      {
        payer: S('the paying EVM address — the wallet that will sign (0x…)'),
        to: S('recipient EVM address (0x…)'),
        amount: S('amount in token base units (decimal string)'),
        token: S('optional ERC-20 address; defaults to the chain-pinned stablecoin'),
        rail: S("'evm-transfer' (default) | 'x402'"),
        facilitatorUrl: S('for rail=x402: the x402 facilitator base URL'),
        deadline: { type: 'number', description: 'optional unix seconds; default now + 1h' },
      },
      ['payer', 'to', 'amount'],
    ),
  },
  {
    name: 'hsp_submit_payment',
    description:
      'SUBMIT a payment whose mandate + settlement were signed externally (by a wallet MCP). Re-verifies the mandate signature against the expected paymentId (rejects a tampered body), registers it with the Coordinator, relays the settlement (observe the txHash, or relay the EIP-3009 to the facilitator), and returns the SETTLED status. Holds no key — only relays signed artifacts.',
    inputSchema: A(
      {
        paymentId: S('the paymentId returned by hsp_prepare_payment (0x…)'),
        rail: S("'evm-transfer' | 'x402' (as returned by prepare)"),
        mandateBody: { type: 'object', description: 'the mandateBody from hsp_prepare_payment, passed back verbatim' },
        signed: {
          type: 'object',
          description:
            'the signatures: { mandate: <0xsig>, settlement: <txHash for evm-transfer | { authorization, signature, facilitatorUrl, merchantDomain, tokenName, tokenVersion } for x402> }',
        },
      },
      ['paymentId', 'rail', 'mandateBody', 'signed'],
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

        case 'hsp_prepare_payment': {
          const payer = getAddress(String(args.payer));
          const to = getAddress(String(args.to));
          const amount = BigInt(String(args.amount));
          const token = args.token ? getAddress(String(args.token)) : deps.chain.stablecoin.address;
          const rail = (args.rail as string) ?? 'evm-transfer';
          const deadline = (args.deadline as number) ?? Math.floor(Date.now() / 1000) + 3600;
          const { body, mandateHash } = buildMandateBody(deps, { payer, to, amount: amount.toString(), token, deadline, caps: [] });
          const mandateSign = { id: 'mandate', method: 'eth_signTypedData_v4', params: { address: payer, typedData: mandateTypedData(chainDomain(deps.chain), body) }, expect: { mandateHash } };

          if (rail === 'x402') {
            const facilitatorUrl = String(args.facilitatorUrl ?? '').replace(/\/$/, '');
            if (!facilitatorUrl) return text({ error: 'facilitatorUrl-required', detail: 'rail=x402 needs facilitatorUrl' }, true);
            const pc = createPublicClient({ transport: http(deps.chain.rpcUrl) });
            const [name, version] = (await Promise.all([
              pc.readContract({ address: token, abi: ERC20_DOMAIN, functionName: 'name' }),
              pc.readContract({ address: token, abi: ERC20_DOMAIN, functionName: 'version' }),
            ])) as [string, string];
            const info = (await (await fetch(`${facilitatorUrl}/x402/info`)).json()) as { merchantDomain?: string };
            const validBefore = deadline;
            const auth: Eip3009Authorization = { from: payer, to, value: amount, validAfter: 0, validBefore, nonce: toHex(crypto.getRandomValues(new Uint8Array(32))) };
            const settleSign = {
              id: 'settlement',
              method: 'eth_signTypedData_v4',
              params: { address: payer, typedData: eip3009TypedData({ name, version, chainId: deps.chain.chainId, address: token }, auth) },
              relay: {
                rail: 'x402',
                facilitatorUrl,
                merchantDomain: info.merchantDomain ?? '',
                tokenName: name,
                tokenVersion: version,
                authorization: { from: payer, to, value: amount.toString(), validAfter: '0', validBefore: String(validBefore), nonce: auth.nonce },
              },
            };
            return text({ paymentId: mandateHash, rail: 'x402', mandateBody: body, toSign: [mandateSign, settleSign], next: 'route each toSign[].method to your wallet MCP, then call hsp_submit_payment' });
          }

          const data = encodeFunctionData({ abi: ERC20_TRANSFER, functionName: 'transfer', args: [to, amount] });
          const settleSign = { id: 'settlement', method: 'eth_sendTransaction', params: { tx: { from: payer, to: token, data, value: '0x0', chainId: deps.chain.chainId } } };
          return text({ paymentId: mandateHash, rail: 'evm-transfer', mandateBody: body, toSign: [mandateSign, settleSign], next: 'have your wallet MCP sign+broadcast the tx, then call hsp_submit_payment with the mandate signature + the settlement txHash' });
        }

        case 'hsp_submit_payment': {
          if (!deps.coordinatorUrl) return text({ error: 'no-coordinator', detail: 'hsp_submit_payment needs HSP_COORDINATOR_URL (+ HSP_API_KEY)' }, true);
          const rail = String(args.rail);
          const body = args.mandateBody as MandateBody;
          const signed = args.signed as { mandate: Hex; settlement: unknown };
          const mandateHash = computeMandateHash(chainDomain(deps.chain), body);
          if (String(args.paymentId).toLowerCase() !== mandateHash.toLowerCase()) {
            return text({ error: 'mandate-tampered', detail: 'mandateBody does not reproduce paymentId — refusing' }, true);
          }
          const payer = getAddress(decodeAbiParameters([{ type: 'address' }], body.signer.payload)[0] as Address);
          const sig = normalizeV(signed.mandate);
          const recovered = await recoverAddress({ hash: mandateHash, signature: sig });
          if (getAddress(recovered) !== payer) {
            return text({ error: 'bad-mandate-signature', detail: `signature recovers to ${recovered}, expected payer ${payer}` }, true);
          }
          const mandate: SignedMandate = { body, signerProof: sig, requiredCapabilities: [] };
          const reg = await coordHttp(deps, 'POST', '/payments', { chain: deps.chain.name, mandate, attestations: [] });
          if (reg.status !== 200 && reg.status !== 201) return text({ error: 'register-failed', status: reg.status, detail: reg.json }, true);

          if (rail === 'x402') {
            const s = signed.settlement as { authorization: Record<string, unknown>; signature: Hex; facilitatorUrl: string; merchantDomain: string; tokenName: string; tokenVersion: string };
            const payTo = getAddress(decodeAbiParameters([{ type: 'address' }], body.recipient.payload)[0] as Address);
            const requirements = { scheme: 'exact', network: toCaip2(deps.chain.chainId), asset: getAddress(body.token), amount: String(body.amount), payTo, maxTimeoutSeconds: 60, extra: { name: s.tokenName, version: s.tokenVersion } };
            const paymentPayload = { x402Version: 2, accepted: requirements, payload: { signature: s.signature, authorization: s.authorization } };
            const settleRes = await fetch(`${s.facilitatorUrl.replace(/\/$/, '')}/settle`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements: requirements }) });
            const settle = (await settleRes.json()) as { success?: boolean; transaction?: Hex; errorReason?: string };
            if (!settle.success || !settle.transaction) return text({ error: 'x402-settle-failed', detail: settle.errorReason ?? 'unknown' }, true);
            const obs = await coordHttp(deps, 'POST', `/payments/${mandateHash}/x402-observe`, { authorization: s.authorization, signature: s.signature, tokenName: s.tokenName, tokenVersion: s.tokenVersion, txHash: settle.transaction, merchantDomain: s.merchantDomain });
            if (obs.status >= 400) return text({ error: 'x402-observe-failed', status: obs.status, detail: obs.json }, true);
          } else {
            const txHash = signed.settlement as Hex;
            const obs = await coordHttp(deps, 'POST', `/payments/${mandateHash}/observe`, { txHash });
            if (obs.status >= 400 && obs.status !== 202) return text({ error: 'observe-failed', status: obs.status, detail: obs.json }, true);
          }

          const snap = await coordHttp(deps, 'GET', `/payments/${mandateHash}`);
          const j = (snap.json ?? {}) as { status?: string; lastDecision?: { outcomeClass?: string } };
          return text({ paymentId: mandateHash, status: j.status, decision: j.lastDecision, ship: j.lastDecision?.outcomeClass === 'ACCEPT' });
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
