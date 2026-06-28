/**
 * HSPClient — payer-side one-call orchestration (plan M2, user need 4.b):
 *
 *   pay() = build Mandate → sign (HSPSigner) → POST /payments
 *         → broadcast the ERC-20 transfer FROM THE SAME ACCOUNT (wallet-settling:
 *           Transfer.from MUST equal body.signer — the schema enforces it)
 *         → wait for the tx to mine → POST /payments/:id/observe (retries 202)
 *         → returns { paymentId, txHash, awaitSettled() }
 *
 * Stepwise primitives (buildMandate / register / broadcastTransfer /
 * observe) are exposed for callers that want manual control (e.g. a browser
 * flow where each wallet prompt is a separate user action).
 */

import {
  createPublicClient,
  http,
  parseAbi,
  parseUnits,
  toHex,
  type Address,
  type Hex,
} from 'viem';
import { encodeAbiParameters } from 'viem';
import { grantHash, requiredCapabilitiesHash, type Attestation, type Mandate, type SignedMandate, type SignedDelegationGrant } from '@hsp/core';
import { eip712EoaSigner } from '@hsp/core/profiles/signer/eip712-eoa';
import { resolveComplianceCaps, type ComplianceTag } from '@hsp/core/policy/compliance';
import { toCaip2 } from '@hsp/core/x402/index';
import { chainDomain, type ChainConfig } from '@hsp/core/chains/index';
import {
  signMandateBody,
  signEip3009Authorization,
  signerAddress,
  walletClientFor,
  type HSPSigner,
  type Eip3009Authorization,
} from './signer.js';
import type { PaymentRequest } from './requirements.js';
import type { AccountExecutor } from './delegation.js';

const ERC20_ABI = parseAbi(['function transfer(address to, uint256 amount) returns (bool)']);

export interface HSPClientOptions {
  coordinatorUrl: string;
  signer: HSPSigner;
  chain: ChainConfig;
  /** Coordinator chain-registry name; defaults to chain.name. */
  chainName?: string;
  /** Bearer key for the Coordinator's write endpoints. */
  apiKey?: string;
  /** Mock-issuer base URL; required to use pay({ profile: { compliance } }). */
  issuerUrl?: string;
}

/** Compliance profile. */
export interface PayProfile {
  compliance?: ComplianceTag[]; // e.g. ['kyc','sanctions']
}

export interface PayParams {
  to: Address;
  /** Base units (use parseAmount() for human amounts). */
  amount: bigint;
  token?: Address;
  /** Unix seconds; default now + 1h. */
  deadline?: number;
  /** Capability ids to require (MVP public path: omit / []). */
  capabilities?: Hex[];
  /** Compliance profile → resolved to caps + fetched attestations (needs issuerUrl). */
  profile?: PayProfile;
  nonce?: Hex;
}

export interface PaymentSnapshot {
  paymentId: Hex;
  status: string;
  [k: string]: unknown;
}

export interface PayHandle {
  paymentId: Hex;
  txHash: Hex;
  status: string;
  mandate: SignedMandate;
  awaitSettled(opts?: { timeoutMs?: number; pollMs?: number }): Promise<PaymentSnapshot>;
}

const TERMINAL = new Set(['SETTLED', 'FAILED', 'DISPUTED', 'EXPIRED']);

export class HSPClient {
  constructor(private readonly opts: HSPClientOptions) {}

  /** Plan P: cached adapter-operator public URL for this chain
   *  (undefined = not yet resolved, null = none advertised → use the hub's /observe). */
  private operatorUrlCache: string | null | undefined;

  get address(): Address {
    return signerAddress(this.opts.signer);
  }

  /** Human amount → base units using the chain's pinned stablecoin decimals. */
  parseAmount(human: string): bigint {
    return parseUnits(human, this.opts.chain.stablecoin.decimals);
  }

  buildMandate(p: PayParams): Mandate {
    const chain = this.opts.chain;
    const caps = p.capabilities ?? [];
    return {
      nonce: p.nonce ?? toHex(crypto.getRandomValues(new Uint8Array(32))),
      signer: {
        profileId: eip712EoaSigner.profileIdHash,
        payload: encodeAbiParameters([{ type: 'address' }], [this.address]),
      },
      recipient: { kind: 0, payload: encodeAbiParameters([{ type: 'address' }], [p.to]) },
      token: p.token ?? chain.stablecoin.address,
      amount: p.amount.toString(),
      chainId: chain.chainId,
      deadline: p.deadline ?? Math.floor(Date.now() / 1000) + 3600,
      requiredCapabilitiesHash: requiredCapabilitiesHash(caps),
    };
  }

  async signMandate(p: PayParams): Promise<{ mandate: SignedMandate; mandateHash: Hex }> {
    const body = this.buildMandate(p);
    const { mandateHash, signerProof } = await signMandateBody(this.opts.signer, chainDomain(this.opts.chain), body);
    return { mandate: { body, signerProof, requiredCapabilities: p.capabilities ?? [] }, mandateHash };
  }

  async register(
    mandate: SignedMandate,
    attestations: Attestation[] = [],
    grant?: SignedDelegationGrant,
  ): Promise<{ paymentId: Hex; status: string }> {
    const r = await this.http('POST', '/payments', { chain: this.chainName, mandate, attestations, ...(grant ? { grant } : {}) });
    if (r.status !== 200 && r.status !== 201) {
      throw new Error(`register failed: HTTP ${r.status} ${JSON.stringify(r.json)}`);
    }
    return r.json as { paymentId: Hex; status: string };
  }

  /** Fetch attestations from the configured mock issuer for the given tags. */
  async fetchComplianceAttestations(tags: ComplianceTag[]): Promise<Attestation[]> {
    if (!this.opts.issuerUrl) throw new Error('pay({ profile: { compliance } }) requires HSPClient issuerUrl');
    const base = this.opts.issuerUrl.replace(/\/$/, '');
    const out: Attestation[] = [];
    for (const tag of tags) {
      const path = tag === 'sanctions' ? '/attest/sanctions' : '/attest/kyc';
      const body = tag === 'sanctions' ? { subject: this.address } : { subject: this.address, level: tag === 'kyc-basic' ? 'basic' : 'full' };
      const res = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      if (!res.ok) throw new Error(`issuer ${tag} failed: HTTP ${res.status}`);
      const j = (await res.json()) as { attestation: Attestation };
      out.push(j.attestation);
    }
    return out;
  }

  /** Broadcast the ERC-20 transfer from the signer's own wallet; returns txHash. */
  async broadcastTransfer(p: { to: Address; amount: bigint; token?: Address }): Promise<Hex> {
    const chain = this.opts.chain;
    const wallet = walletClientFor(this.opts.signer, chain.rpcUrl, chain.chainId);
    const account = wallet.account;
    if (!account) throw new Error('wallet client has no account');
    const txHash = await wallet.writeContract({
      address: p.token ?? chain.stablecoin.address,
      abi: ERC20_ABI,
      functionName: 'transfer',
      args: [p.to, p.amount],
      account,
      chain: wallet.chain,
    });
    const publicClient = createPublicClient({ transport: http(chain.rpcUrl) });
    await publicClient.waitForTransactionReceipt({ hash: txHash });
    return txHash;
  }

  /** POST observe; retries while the answer is 202 (pending/confirming). Plan P: if the hub
   *  advertises an adapter operator, the payer calls IT directly (operator owns seq + submits
   *  the receipt to the hub); else falls back to the hub's own /observe. */
  async observe(
    paymentId: Hex,
    txHash: Hex,
    opts: { retries?: number; delayMs?: number } = {},
  ): Promise<{ status: string }> {
    const retries = opts.retries ?? 30;
    const delayMs = opts.delayMs ?? 2000;
    const operatorUrl = await this.resolveOperatorUrl();
    const coordinatorUrl = this.opts.coordinatorUrl.replace(/\/$/, '');
    for (let i = 0; i <= retries; i++) {
      const r = operatorUrl
        ? await this.postAbs(`${operatorUrl}/observe/evm-transfer`, { coordinatorUrl, paymentId, txHash })
        : await this.http('POST', `/payments/${paymentId}/observe`, { txHash });
      if (r.status === 202) {
        await new Promise((res) => setTimeout(res, delayMs));
        continue;
      }
      if (r.status !== 200) throw new Error(`observe failed: HTTP ${r.status} ${JSON.stringify(r.json)}`);
      return r.json as { status: string };
    }
    throw new Error('observe timed out waiting for the tx to become observable');
  }

  /** One call: sign → register → broadcast → observe → handle. */
  async pay(p: PayParams | PaymentRequest): Promise<PayHandle> {
    let base: PayParams;
    if ('amount' in p && typeof p.amount === 'string') {
      // a payee-built PaymentRequest — honor its chain + advertised required caps
      const pr = p as PaymentRequest;
      if (pr.chainId !== this.opts.chain.chainId) {
        throw new Error(`PaymentRequest targets chainId ${pr.chainId}, but this client is on ${this.opts.chain.chainId}`);
      }
      const required = pr.requirements?.policyRequiredCapabilities ?? [];
      base = {
        to: pr.to,
        amount: BigInt(pr.amount),
        ...(pr.token ? { token: pr.token } : {}),
        ...(required.length ? { capabilities: required as Hex[] } : {}),
      };
    } else {
      base = p as PayParams;
    }
    const params: PayParams = { ...base };
    // compliance profile → extra caps signed into the mandate + fetched attestations
    let attestations: Attestation[] = [];
    if (params.profile?.compliance?.length) {
      const ccaps = resolveComplianceCaps(params.profile.compliance);
      params.capabilities = [...(params.capabilities ?? []), ...ccaps.map((c) => c.id)];
      attestations = await this.fetchComplianceAttestations(params.profile.compliance);
    }
    const { mandate, mandateHash } = await this.signMandate(params);
    const reg = await this.register(mandate, attestations);
    const txHash = await this.broadcastTransfer({
      to: params.to,
      amount: params.amount,
      ...(params.token ? { token: params.token } : {}),
    });
    const obs = await this.observe(reg.paymentId, txHash);
    void mandateHash;
    return {
      paymentId: reg.paymentId,
      txHash,
      status: obs.status,
      mandate,
      awaitSettled: (o) => this.awaitTerminal(reg.paymentId, o),
    };
  }

  /**
   * Delegated payment (HSP.md §2.1.1): THIS client's signer is the AGENT. The Principal
   * (an erc1271 smart account) must have pre-signed the `grant` (see signGrant); the Agent
   * signs the execution with `grantRef = grantHash(grant)`, the Coordinator stores the grant
   * and verifies the delegation, and the Principal's ACCOUNT settles via `executor` so the
   * on-chain `Transfer.from` is the account. Returns the same PayHandle as `pay()`.
   */
  async payDelegated(p: {
    to: Address;
    amount: bigint;
    grant: SignedDelegationGrant;
    /** The Principal smart account whose funds move (== the grant's principal account). */
    account: Address;
    /** Settles account.execute(transfer) so Transfer.from = the account (see delegation.ts). */
    executor: AccountExecutor;
    token?: Address;
    deadline?: number;
    capabilities?: Hex[];
    nonce?: Hex;
    attestations?: Attestation[];
  }): Promise<PayHandle> {
    const domain = chainDomain(this.opts.chain);
    const grantRef = grantHash(domain, p.grant.body);
    const base = this.buildMandate({
      to: p.to,
      amount: p.amount,
      ...(p.token ? { token: p.token } : {}),
      ...(p.deadline !== undefined ? { deadline: p.deadline } : {}),
      ...(p.capabilities ? { capabilities: p.capabilities } : {}),
      ...(p.nonce ? { nonce: p.nonce } : {}),
    });
    const body: Mandate = { ...base, grantRef };
    const { signerProof } = await signMandateBody(this.opts.signer, domain, body);
    const mandate: SignedMandate = { body, signerProof, requiredCapabilities: p.capabilities ?? [] };
    const reg = await this.register(mandate, p.attestations ?? [], p.grant);
    // the Principal account moves the funds — Transfer.from = the account, not the agent
    const txHash = await p.executor.execute({ account: p.account, token: body.token, to: p.to, amount: p.amount });
    const obs = await this.observe(reg.paymentId, txHash);
    return {
      paymentId: reg.paymentId,
      txHash,
      status: obs.status,
      mandate,
      awaitSettled: (o) => this.awaitTerminal(reg.paymentId, o),
    };
  }

  /**
   * Pay a merchant directly via a conformant x402 Facilitator (real Coinbase x402
   * v2, self-settling). The payer signs BOTH an HSP mandate AND an EIP-3009
   * exact-EVM authorization; one `POST /settle` (carrying the mandate in
   * `extensions.hsp`) submits the client-signed `transferWithAuthorization` — YOUR
   * funds move, zero gas for you — and bridges it to a verifiable HSP Receipt at the
   * Coordinator. Requires a FiatTokenV2-style token (exposes `name()`/`version()`).
   * To pay an x402-GATED HTTP resource instead, use `fetchWithX402` (SDK x402 module).
   *
   * With `profile.compliance`, the matching capabilities are signed into the mandate
   * and the attestations are fetched + registered with the Coordinator DIRECTLY
   * (`POST /payments` — they are verification evidence for the Coordinator, never sent
   * to the facilitator). The facilitator only settles + submits the receipt.
   */
  async payX402(p: {
    merchant: Address;
    facilitatorUrl: string;
    /** The facilitator's x402 merchant domain (its instanceKey). Default: read from GET /x402/info. */
    merchantDomain?: string;
    amount: bigint;
    token?: Address;
    deadline?: number;
    /** Compliance profile → caps signed into the mandate + attestations fetched (needs issuerUrl). */
    profile?: PayProfile;
  }): Promise<PayHandle> {
    const chain = this.opts.chain;
    const tokenAddr = p.token ?? chain.stablecoin.address;
    const deadline = p.deadline ?? Math.floor(Date.now() / 1000) + 3600;

    // compliance: caps signed into the mandate; attestations go to the COORDINATOR (not the facilitator)
    let attestations: Attestation[] = [];
    let capabilities: Hex[] | undefined;
    if (p.profile?.compliance?.length) {
      capabilities = resolveComplianceCaps(p.profile.compliance).map((c) => c.id);
      attestations = await this.fetchComplianceAttestations(p.profile.compliance);
    }
    const { mandate, mandateHash } = await this.signMandate({ to: p.merchant, amount: p.amount, token: tokenAddr, deadline, ...(capabilities ? { capabilities } : {}) });
    // the payer owns registration: mandate (+ attestations) go straight to the Coordinator
    await this.register(mandate, attestations);

    // read the token's EIP-712 domain (FiatTokenV2 name()/version())
    const publicClient = createPublicClient({ transport: http(chain.rpcUrl) });
    const erc20Meta = parseAbi(['function name() view returns (string)', 'function version() view returns (string)']);
    const [tokenName, tokenVersion] = await Promise.all([
      publicClient.readContract({ address: tokenAddr, abi: erc20Meta, functionName: 'name' }) as Promise<string>,
      publicClient.readContract({ address: tokenAddr, abi: erc20Meta, functionName: 'version' }) as Promise<string>,
    ]).catch(() => {
      throw new Error(`token ${tokenAddr} does not expose name()/version() — x402 exact-EVM needs a FiatTokenV2-style token`);
    });

    // sign the EIP-3009 authorization (client-pull settlement)
    const auth: Eip3009Authorization = { from: this.address, to: p.merchant, value: p.amount, validAfter: 0, validBefore: deadline, nonce: toHex(crypto.getRandomValues(new Uint8Array(32))) };
    const signature = await signEip3009Authorization(this.opts.signer, { name: tokenName, version: tokenVersion, chainId: chain.chainId, address: tokenAddr }, auth);

    // conformant x402 v2 settle request to a STOCK facilitator (it just settles + pays gas)
    const authorization = { from: auth.from, to: auth.to, value: auth.value.toString(), validAfter: '0', validBefore: String(deadline), nonce: auth.nonce };
    const requirements = { scheme: 'exact', network: toCaip2(chain.chainId), asset: tokenAddr, amount: p.amount.toString(), payTo: p.merchant, maxTimeoutSeconds: 60, extra: { name: tokenName, version: tokenVersion } };
    const paymentPayload = { x402Version: 2, accepted: requirements, payload: { signature, authorization } };
    const fbase = p.facilitatorUrl.replace(/\/$/, '');
    const settle = (await (
      await fetch(`${fbase}/settle`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements: requirements }) })
    ).json()) as { success?: boolean; transaction?: Hex; errorReason?: string };
    if (!settle.success || !settle.transaction) throw new Error(`x402 settle failed: ${settle.errorReason ?? 'unknown'}`);

    // the COORDINATOR is the adapter:x402 operator: hand it the EIP-3009 proof + txHash so it reads
    // the chain, signs the adapter:x402 receipt, and verifies → SETTLED (never assume SETTLED).
    const merchantDomain = p.merchantDomain ?? (await this.facilitatorMerchantDomain(fbase));
    // Plan P: hand the EIP-3009 proof + txHash to the operator directly (it owns its seq +
    // submits the receipt to the hub); else the hub's own /x402-observe. Retry while 202.
    const operatorUrl = await this.resolveOperatorUrl();
    const coordinatorUrl = this.opts.coordinatorUrl.replace(/\/$/, '');
    const evidence = { authorization, signature, tokenName, tokenVersion, txHash: settle.transaction, merchantDomain };
    let x402: { status: number; json: unknown } = { status: 0, json: null };
    for (let i = 0; i <= 30; i++) {
      x402 = operatorUrl
        ? await this.postAbs(`${operatorUrl}/observe/x402`, { coordinatorUrl, paymentId: mandateHash, ...evidence })
        : await this.http('POST', `/payments/${mandateHash}/x402-observe`, evidence);
      if (x402.status === 202) {
        await new Promise((res) => setTimeout(res, 2000));
        continue;
      }
      break;
    }
    if (x402.status !== 200 && x402.status !== 201) {
      throw new Error(`x402 settled on-chain (tx ${settle.transaction}) but the Coordinator rejected it: HTTP ${x402.status} ${JSON.stringify(x402.json)}`);
    }
    const result = x402.json as { status?: string; decision?: { ok?: boolean; errorCode?: string } };

    return {
      paymentId: mandateHash,
      txHash: settle.transaction,
      status: result.status ?? 'SETTLED',
      mandate,
      awaitSettled: (o) => this.awaitTerminal(mandateHash, o),
    };
  }

  /** Read a (stock) x402 facilitator's merchant domain from GET /x402/info. */
  private async facilitatorMerchantDomain(fbase: string): Promise<string> {
    const res = await fetch(`${fbase}/x402/info`);
    if (!res.ok) throw new Error(`could not read facilitator /x402/info (HTTP ${res.status}) — pass merchantDomain explicitly`);
    const info = (await res.json()) as { merchantDomain?: string };
    if (!info.merchantDomain) throw new Error('facilitator /x402/info exposes no merchantDomain — pass merchantDomain explicitly');
    return info.merchantDomain;
  }

  async getPayment(paymentId: Hex): Promise<PaymentSnapshot> {
    const r = await this.http('GET', `/payments/${paymentId}`);
    if (r.status !== 200) throw new Error(`getPayment failed: HTTP ${r.status}`);
    return r.json as PaymentSnapshot;
  }

  private async awaitTerminal(paymentId: Hex, opts: { timeoutMs?: number; pollMs?: number } = {}): Promise<PaymentSnapshot> {
    const timeoutMs = opts.timeoutMs ?? 120_000;
    const pollMs = opts.pollMs ?? 1500;
    const start = Date.now();
    for (;;) {
      const snap = await this.getPayment(paymentId);
      if (TERMINAL.has(snap.status)) return snap;
      if (Date.now() - start > timeoutMs) throw new Error(`awaitSettled timed out (last status: ${snap.status})`);
      await new Promise((res) => setTimeout(res, pollMs));
    }
  }

  private get chainName(): string {
    return this.opts.chainName ?? this.opts.chain.name;
  }

  private async http(method: string, path: string, body?: unknown): Promise<{ status: number; json: unknown }> {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (this.opts.apiKey) headers.authorization = `Bearer ${this.opts.apiKey}`;
    const init: RequestInit = { method, headers };
    if (body !== undefined) init.body = JSON.stringify(body);
    const res = await fetch(`${this.opts.coordinatorUrl.replace(/\/$/, '')}${path}`, init);
    let json: unknown = null;
    try {
      json = await res.json();
    } catch {
      /* non-JSON */
    }
    return { status: res.status, json };
  }

  /** POST to an absolute URL (the adapter operator, off-hub). No Coordinator auth header. */
  private async postAbs(url: string, body: unknown): Promise<{ status: number; json: unknown }> {
    const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    let json: unknown = null;
    try {
      json = await res.json();
    } catch {
      /* non-JSON */
    }
    return { status: res.status, json };
  }

  /**
   * Plan P: the adapter operator's PUBLIC base URL advertised by the hub (GET /chains →
   * adapterOperatorUrl). When present, the payer calls the operator's /observe directly
   * (the operator owns its seq + submits the receipt to the hub). null → no operator is
   * advertised, so observe falls back to the hub's own /observe (in-process / hub-delegated).
   */
  private async resolveOperatorUrl(): Promise<string | null> {
    if (this.operatorUrlCache !== undefined) return this.operatorUrlCache;
    try {
      const r = await this.http('GET', '/chains');
      const chains = (r.json as Array<{ name: string; adapterOperatorUrl?: string | null }>) ?? [];
      const entry = chains.find((c) => c.name === this.chainName);
      this.operatorUrlCache = entry?.adapterOperatorUrl ? entry.adapterOperatorUrl.replace(/\/$/, '') : null;
    } catch {
      this.operatorUrlCache = null;
    }
    return this.operatorUrlCache;
  }
}
