/**
 * HSP MCP server — four tools over @hsp/sdk (low-level Server API + plain JSON
 * Schema; no extra schema deps):
 *
 *   hsp_quote  — preview a payment (no signing, no money movement); echoes the
 *                Coordinator's §7.7 requirements + guard headroom
 *   hsp_pay    — REQUIRES confirm:true; SpendGuard-checked; one-call pay()
 *   hsp_status — payment lifecycle status by paymentId
 *   hsp_verify — merchant-side independent verify of a received (mandate,
 *                receipt[, attestations]) triple with a PINNED adapter address
 *
 * Custody posture: the server holds the agent's demo key only (small amounts,
 * guard-capped); it never holds the Coordinator's adapter key.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { Address, Hex } from 'viem';
import type { Attestation, Receipt, SignedMandate } from '@hsp/core';
import type { ChainConfig } from '@hsp/core/chains/index';
import { HSPClient, HSPVerifier, fetchRequirements, type ComplianceTag } from '@hsp/sdk';
import { SpendGuard } from './guard.js';

export interface McpDeps {
  hsp: HSPClient;
  chain: ChainConfig;
  coordinatorUrl: string;
  guard: SpendGuard;
  /** Pinned adapter observation address for hsp_verify (merchant trust). */
  pinnedAdapterAddress?: Address;
}

const TOOLS = [
  {
    name: 'hsp_quote',
    description:
      'Preview an HSP payment WITHOUT moving money: resolves token/chain defaults, shows the deadline, the verifier requirements (§7.7) and the spend-guard headroom. Always call this and show the user the result BEFORE hsp_pay.',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'recipient EVM address (0x…)' },
        amount: { type: 'string', description: 'amount in token base units (decimal string)' },
        token: { type: 'string', description: 'optional ERC-20 address; defaults to the chain-pinned stablecoin' },
      },
      required: ['to', 'amount'],
    },
  },
  {
    name: 'hsp_pay',
    description:
      'Execute an HSP payment (sign mandate → register → broadcast ERC-20 transfer from the agent wallet → observe → status). REQUIRES confirm:true, which you may only set after the user explicitly approved the exact quote (recipient + amount + chain).',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'recipient EVM address (0x…)' },
        amount: { type: 'string', description: 'amount in token base units (decimal string)' },
        token: { type: 'string', description: 'optional ERC-20 address; defaults to the chain-pinned stablecoin' },
        compliance: {
          type: 'array',
          items: { type: 'string', enum: ['kyc', 'kyc-basic', 'sanctions'] },
          description: 'optional compliance tags; fetches matching attestations from the issuer and signs the caps into the mandate (needs the server configured with an issuer URL)',
        },
        confirm: { type: 'boolean', description: 'must be true; set ONLY after explicit user approval of the quote' },
      },
      required: ['to', 'amount', 'confirm'],
    },
  },
  {
    name: 'hsp_status',
    description: 'Get the lifecycle status of an HSP payment by paymentId (PROPOSED/ATTEMPTED/SETTLED/FAILED/DISPUTED/EXPIRED).',
    inputSchema: {
      type: 'object',
      properties: { paymentId: { type: 'string', description: 'the paymentId (mandate hash, 0x…)' } },
      required: ['paymentId'],
    },
  },
  {
    name: 'hsp_verify',
    description:
      'Independently verify a RECEIVED HSP payment (merchant side): runs the protocol verifier over (mandate, receipt[, attestations]) with a pinned adapter address — does not trust the Coordinator. Returns the AcceptDecision.',
    inputSchema: {
      type: 'object',
      properties: {
        mandate: { type: 'object', description: 'the SignedMandate JSON' },
        receipt: { type: 'object', description: 'the Receipt JSON' },
        attestations: { type: 'array', description: 'optional Attestation[] JSON' },
        adapterAddress: { type: 'string', description: 'optional override of the pinned adapter observation address' },
      },
      required: ['mandate', 'receipt'],
    },
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
  const server = new Server({ name: 'hsp-pay', version: '0.1.0' }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: TOOLS as unknown as { name: string }[] }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    try {
      switch (req.params.name) {
        case 'hsp_quote': {
          const to = String(args.to) as Address;
          const amount = BigInt(String(args.amount));
          let requirements: unknown = null;
          try {
            requirements = await fetchRequirements(deps.coordinatorUrl, deps.chain.name);
          } catch {
            /* coordinator may be offline; quote still useful */
          }
          return text({
            to,
            token: (args.token as Address | undefined) ?? deps.chain.stablecoin.address,
            tokenSymbol: deps.chain.stablecoin.symbol,
            amountBaseUnits: amount.toString(),
            chain: deps.chain.name,
            chainId: deps.chain.chainId,
            estimatedDeadline: Math.floor(Date.now() / 1000) + 3600,
            requiredCapabilities: [], // trivial-public path (§2.2.4)
            requirements,
            guard: { dailyRemaining: deps.guard.remainingToday()?.toString() ?? 'unlimited' },
            next: 'show this to the user; call hsp_pay with confirm:true only after explicit approval',
          });
        }
        case 'hsp_pay': {
          if (args.confirm !== true) {
            return text({ error: 'confirm-required', detail: 'hsp_pay requires confirm:true after the user explicitly approved the quote' }, true);
          }
          const to = String(args.to) as Address;
          const amount = BigInt(String(args.amount));
          const refusal = deps.guard.check(to, amount);
          if (refusal) return text({ error: 'spend-guard', detail: refusal }, true);
          const payParams: Parameters<HSPClient['pay']>[0] = { to, amount };
          if (args.token) (payParams as { token?: Address }).token = args.token as Address;
          if (Array.isArray(args.compliance) && args.compliance.length > 0) {
            (payParams as { profile?: { compliance?: ComplianceTag[] } }).profile = { compliance: args.compliance as ComplianceTag[] };
          }
          const handle = await deps.hsp.pay(payParams);
          deps.guard.commit(amount);
          return text({ paymentId: handle.paymentId, txHash: handle.txHash, status: handle.status });
        }
        case 'hsp_status': {
          const snap = await deps.hsp.getPayment(String(args.paymentId) as Hex);
          const receipts = (snap.receipts as unknown[]) ?? [];
          const rejected = (snap.rejectedSubmissions as unknown[]) ?? [];
          const last = snap.lastDecision as { outcomeClass?: string; errorCode?: string } | null;
          return text({
            paymentId: snap.paymentId,
            status: snap.status,
            outcomeClass: last?.outcomeClass,
            errorCode: last?.errorCode,
            receipts: receipts.length,
            rejectedSubmissions: rejected.length,
          });
        }
        case 'hsp_verify': {
          const adapterAddress = (args.adapterAddress as Address | undefined) ?? deps.pinnedAdapterAddress;
          if (!adapterAddress) {
            return text({ error: 'no-pinned-adapter', detail: 'set HSP_PINNED_ADAPTER_ADDRESS or pass adapterAddress' }, true);
          }
          const verifier = new HSPVerifier({ chain: deps.chain, adapterAddress });
          const decision = await verifier.verify(
            args.mandate as SignedMandate,
            args.receipt as Receipt,
            (args.attestations as Attestation[] | undefined) ?? [],
          );
          return text({ ...decision, ship: decision.ok && decision.outcomeClass === 'ACCEPT' });
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
