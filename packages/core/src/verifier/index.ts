/**
 * HSP Verifier — the sole normative orchestrator (HSP.md §5).
 *
 * Phase A (§5.1) mandate-side, Phase B (§5.2) receipt-side. Steps run in the exact
 * spec order; each rejection site supplies the §8.0 outcomeClass directly (the class
 * is the nature of the result, not the errorCode string). Stateless core = steps that
 * are a pure function of (mandate, receipt, attestations, policy, evaluationTime);
 * the SeqIndex (step 7 + S4) is the stateful-admission layer (CR5).
 */

import { recoverAddress, decodeAbiParameters, getAddress, type Hex, type Address } from 'viem';
import {
  mandateHash as computeMandateHash,
  grantHash as computeGrantHash,
  requiredCapabilitiesHash as computeReqCapsHash,
  receiptHash as computeReceiptHash,
  canonicalizeCapSet,
  makeCap,
  capSatisfies,
  familyCapId,
  Outcome,
  RecipientKind,
  type OutcomeValue,
  type SignedMandate,
  type SignedDelegationGrant,
  type Receipt,
  type Attestation,
  type Mandate,
  type DomainInput,
  type ParsedCapability,
  type PartyRef,
} from '../core/index.js';
import { ATTESTATION_SCHEMAS } from '../attestation/schemas.js';
import { validateCR2 } from '../attestation/verify.js';
import type {
  VerificationPolicy,
  AcceptDecision,
  OutcomeClass,
  SignerDecision,
  VerifyOutcome,
  VerifyContext,
  ReceiptHeader,
  AdapterTrustEntry,
  SchemaAdmission,
} from './contracts.js';
import { adapterKey, schemaKey } from './contracts.js';
import { roleFunction, partyRefEqual, type RoleAssignment } from './roles.js';
import { outcomeClassForOk } from './outcome.js';
import { SeqIndex, ObservationIndex, type PriorState } from './seq-index.js';

function reject(outcomeClass: OutcomeClass, errorCode: string, errorDetail?: string): AcceptDecision {
  return { ok: false, outcomeClass, errorCode, errorDetail };
}

function domainFor(body: Mandate, policy: VerificationPolicy): DomainInput {
  // §1.5 / §5.1 step 1b: domain version is policy-pinned; "1" is the only value this revision defines.
  return {
    name: 'HSP',
    version: policy.domainVersion ?? '1',
    chainId: Number(body.chainId),
    verifyingContract: policy.verifyingContract,
  };
}

export interface PhaseAResult {
  domain: DomainInput;
  mandateHash: Hex;
  signerDecision: SignerDecision;
  roleAssignment: RoleAssignment;
  payerAccount: PartyRef; // §4.1 accountOf(principal) — the sender binds to this (§5.2 step 4)
  grantWindow?: { notBefore: number; expiry: number }; // delegated only — checked at §5.2 step 7
}

// =============================================================================
// Phase A — Mandate-side (§5.1)
// =============================================================================

export async function verifyPhaseA(
  mandate: SignedMandate,
  policy: VerificationPolicy,
  grant?: SignedDelegationGrant,
): Promise<{ ok: true; result: PhaseAResult } | { ok: false; decision: AcceptDecision }> {
  const body = mandate.body;
  const NONE32 = `0x${'00'.repeat(32)}`;
  const isDelegated = body.grantRef !== undefined && body.grantRef.toLowerCase() !== NONE32;
  const now = policy.evaluationTime;

  // step 1a / 1b — admissibility
  if (Number(body.chainId) === 0) return { ok: false, decision: reject('PERMANENT', 'HSP-MAND-CHAINID') };
  if (!policy.acceptedVerifyingContracts.has(policy.verifyingContract.toLowerCase())) {
    return { ok: false, decision: reject('POLICY', 'HSP-MAND-DOMAIN', 'verifyingContract not accepted') };
  }
  const domain = domainFor(body, policy);

  // step 2 — deadline is NOT checked against evaluationTime: settlement expiry is
  // settledAt ≤ body.deadline at §5.2 step 7 (an on-time historical settlement
  // stays verifiable after the deadline). Pre-settlement screens (e.g. a
  // Coordinator refusing to register an expired mandate) are deployment
  // discretion (§1.4), not a verifier rule.

  // step 3 — requiredCapabilitiesHash
  const canon = canonicalizeCapSet(mandate.requiredCapabilities);
  if (computeReqCapsHash(canon) !== body.requiredCapabilitiesHash) {
    return { ok: false, decision: reject('PERMANENT', 'HSP-MAND-REQHASH-MISMATCH') };
  }

  // step 3b — required-capabilities floor & ceiling (§5.1 step 3b)
  //   floor   = policyRequiredCapabilities (payee/deployment) ∪ grant.payerRequiredCaps (payer)
  //   ceiling = grant.payerAllowedCaps (delegated only)
  const have = new Set(canon.map((c) => c.toLowerCase()));
  const grantBody = isDelegated ? grant?.body : undefined;
  const floor = [...(policy.policyRequiredCapabilities ?? []), ...(grantBody?.payerRequiredCaps ?? [])];
  const floorMissing = floor.filter((m) => !have.has(m.toLowerCase()));
  if (floorMissing.length > 0) {
    return { ok: false, decision: reject('POLICY', 'HSP-MAND-REQ-INSUFFICIENT', floorMissing.join(',')) };
  }
  if (grantBody) {
    const ceiling = new Set((grantBody.payerAllowedCaps ?? []).map((c) => c.toLowerCase()));
    const incompat = floor.filter((m) => !ceiling.has(m.toLowerCase()));
    if (incompat.length > 0) {
      // the required floor is not within what the Principal authorized — grant↔requirement mismatch.
      return { ok: false, decision: reject('POLICY', 'HSP-GRANT-REQ-INCOMPAT', incompat.join(',')) };
    }
    const overCeiling = canon.filter((c) => !ceiling.has(c.toLowerCase()));
    if (overCeiling.length > 0) {
      // the Agent declared a payer-side cap above the ceiling (over-disclosure).
      return { ok: false, decision: reject('PERMANENT', 'HSP-GRANT-CAP-CEILING', overCeiling.join(',')) };
    }
  }

  // step 4 — signer verification
  const signerEntry = policy.signerProfiles.get(body.signer.profileId);
  if (!signerEntry) return { ok: false, decision: reject('POLICY', 'HSP-MAND-SIGNER-PROFILE-UNKNOWN') };
  const mandateHash = computeMandateHash(domain, body);
  const signerDecision = await signerEntry.profile.verify(body.signer.payload, mandate.signerProof, mandateHash, body);
  if (!signerDecision.granted) {
    return { ok: false, decision: reject('PERMANENT', signerDecision.errorCode ?? 'HSP-MAND-SIGNER', signerDecision.errorDetail) };
  }
  // step 4b — signer-state staleness (SP7); EOA static profiles skip
  if (signerEntry.profile.description.stateDependent) {
    if (!signerEntry.profile.isStateStale || signerDecision.signerStateHash === undefined) {
      return {
        ok: false,
        decision: reject('PERMANENT', 'HSP-MAND-SIGNER-STATE-DRIFT', 'state-dependent profile missing staleness machinery'),
      };
    }
    if (signerEntry.profile.isStateStale(signerDecision.signerStateHash, signerEntry.stateAnchor ?? {}, now)) {
      return { ok: false, decision: reject('RETRYABLE', 'HSP-MAND-SIGNER-STATE-DRIFT') };
    }
  }
  if (!signerDecision.resolvedSubject) {
    return { ok: false, decision: reject('PERMANENT', 'HSP-MAND-SIGNER', 'granted without resolvedSubject (SP6)') };
  }

  // step 4c — delegation grant (§5.1 step 4c). Self-pay: the signer is its own account.
  let principalSubject: PartyRef = signerDecision.resolvedSubject;
  let payerAccount: PartyRef;
  let grantWindow: { notBefore: number; expiry: number } | undefined;

  if (isDelegated) {
    if (!grant) {
      return { ok: false, decision: reject('PERMANENT', 'HSP-GRANT-SIGNER', 'grantRef set but no grant supplied') };
    }
    const g = grant.body;
    const principalEntry = policy.signerProfiles.get(g.principal.profileId);
    if (!principalEntry) {
      return { ok: false, decision: reject('POLICY', 'HSP-MAND-SIGNER-PROFILE-UNKNOWN', 'grant principal profile') };
    }
    // 4c-i — the Principal signed grantHash (typically erc1271.v1, verified on-chain)
    const gHash = computeGrantHash(domain, g);
    const grantDecision = await principalEntry.profile.verify(g.principal.payload, grant.principalProof, gHash, body);
    if (!grantDecision.granted || !grantDecision.resolvedSubject) {
      // a grant-principal signature failure is HSP-GRANT-SIGNER regardless of the profile's
      // own execution-side code (e.g. erc1271's HSP-MAND-SIGNER / -STATE-UNAVAILABLE).
      return { ok: false, decision: reject('PERMANENT', 'HSP-GRANT-SIGNER', grantDecision.errorDetail ?? grantDecision.errorCode) };
    }
    // 4c-ii — the Agent the Principal authorized is the one who signed this execution (PartyRef)
    const agentEntry = policy.signerProfiles.get(g.agent.profileId);
    if (!agentEntry) {
      return { ok: false, decision: reject('POLICY', 'HSP-MAND-SIGNER-PROFILE-UNKNOWN', 'grant agent profile') };
    }
    const agentSubject = agentEntry.profile.decode(g.agent.payload);
    if (!partyRefEqual(agentSubject, signerDecision.resolvedSubject)) {
      return { ok: false, decision: reject('PERMANENT', 'HSP-GRANT-AGENT-MISMATCH') };
    }
    principalSubject = grantDecision.resolvedSubject; // payer = Principal (§3.4)
    payerAccount = principalEntry.profile.accountOf(g.principal.payload);
    grantWindow = { notBefore: g.notBefore, expiry: g.expiry };
  } else {
    payerAccount = signerEntry.profile.accountOf(body.signer.payload);
  }

  const roleAssignment = roleFunction(mandate, signerDecision, policy, isDelegated ? principalSubject : undefined);
  return {
    ok: true,
    result: { domain, mandateHash, signerDecision, roleAssignment, payerAccount, grantWindow },
  };
}

// =============================================================================
// Phase B — Receipt-side (§5.2)
// =============================================================================

function stripProof(receipt: Receipt): ReceiptHeader {
  const { adapterProof: _drop, ...header } = receipt;
  return header;
}

function admissible(admission: SchemaAdmission, isFollowUp: boolean, outcome: OutcomeValue): boolean {
  if (!isFollowUp) return admission === 'accept-new'; // §5.2 step 3
  if (admission === 'accept-new' || admission === 'accept-historical') return true;
  return outcome === Outcome.DISPUTED || outcome === Outcome.FAILED; // accept-dispute-only
}

function checkSettlementConsistency(
  body: Mandate,
  requiredCapabilities: Hex[],
  outcome: VerifyOutcome,
): AcceptDecision | null {
  // token (§5.2 step 4 table)
  if (outcome.tokenObserved && getAddress(outcome.tokenObserved.address) !== getAddress(body.token)) {
    return reject('PERMANENT', 'HSP-RCPT-PROOF', 'token mismatch');
  }
  // chain
  if (outcome.chainIdObserved !== undefined && outcome.chainIdObserved !== Number(body.chainId)) {
    return reject('PERMANENT', 'HSP-RCPT-PROOF', 'chain mismatch');
  }
  // recipient
  if (body.recipient.kind === RecipientKind.ADDRESS) {
    const want = getAddress(decodeAbiParameters([{ type: 'address' }], body.recipient.payload)[0]);
    if (outcome.recipientObservation.kind !== 'address' || getAddress(outcome.recipientObservation.address) !== want) {
      return reject('PERMANENT', 'HSP-RCPT-PROOF', 'recipient mismatch');
    }
  } else {
    // COMMITMENT recipient (§5.2 step 4): every acceptance carries a verifier-checked
    // binding claim — "stealth" derived from the commitment, or "shielded" cryptographically
    // bound to it. "address" and bare "shielded" carry no claim field and are rejected.
    let commitment: string;
    try {
      commitment = (decodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32' }], body.recipient.payload)[0] as string).toLowerCase();
    } catch {
      return reject('PERMANENT', 'HSP-MAND-RECIPIENT-DECODE', 'malformed COMMITMENT recipient payload');
    }
    const observed = outcome.recipientObservation;
    if (observed.kind === 'stealth') {
      if (observed.derivedFrom.toLowerCase() !== commitment) {
        return reject('PERMANENT', 'HSP-RCPT-PROOF', 'stealth derivation not bound to mandate commitment');
      }
    } else if (observed.kind === 'shielded') {
      if (observed.boundTo === undefined || observed.boundTo.toLowerCase() !== commitment) {
        return reject('PERMANENT', 'HSP-RCPT-PROOF', 'shielded observation not bound to mandate commitment');
      }
    } else {
      return reject('PERMANENT', 'HSP-RCPT-PROOF', 'commitment recipient requires a bound stealth/shielded observation');
    }
  }
  // amount
  const hidesAmountId = makeCap('hides:amount:v1').id.toLowerCase();
  const wantsHidden = canonicalizeCapSet(requiredCapabilities).some((c) => c.toLowerCase() === hidesAmountId);
  if (!wantsHidden) {
    if (outcome.amountObservation.kind !== 'exact' || outcome.amountObservation.value !== BigInt(body.amount)) {
      return reject('PERMANENT', 'HSP-MAND-AMOUNT-OUTOFBOUNDS', 'amount not exact');
    }
  } else {
    if (outcome.amountObservation.kind === 'exact') {
      return reject('PERMANENT', 'HSP-MAND-AMOUNT-OUTOFBOUNDS', 'hides:amount required but exact amount observed');
    }
    if (outcome.amountObservation.kind === 'upper-bound' && outcome.amountObservation.value > BigInt(body.amount)) {
      return reject('PERMANENT', 'HSP-MAND-AMOUNT-OUTOFBOUNDS', 'upper-bound exceeds signed amount');
    }
  }
  return null;
}

function checkSequencing(receipt: Receipt, trustEntry: AdapterTrustEntry, prior: PriorState): AcceptDecision | null {
  const reorg = trustEntry.reorgPolicy;
  const seq = Number(receipt.seq);
  const outcome = Number(receipt.outcome) as OutcomeValue;

  // strictly increasing seq per (adapterId, adapterInstanceKey, mandateHash)
  if (prior.seen && seq <= prior.maxSeq) return reject('PERMANENT', 'HSP-RCPT-SEQ-STALE');
  // successor matrix (§2.2.2 / §5.2 step 7): DISPUTED is terminal …
  if (prior.disputed && outcome !== Outcome.DISPUTED) {
    return reject('PERMANENT', 'HSP-RCPT-OUTCOME-INCONSISTENT', 'post-DISPUTED non-DISPUTED emission');
  }
  // … and SETTLED may be followed only by DISPUTED (reversal is the sole
  // post-settlement transition; FAILED ends the attempt, not the stream).
  if (prior.settledSeq !== undefined && outcome !== Outcome.DISPUTED) {
    return reject('PERMANENT', 'HSP-RCPT-OUTCOME-INCONSISTENT', 'post-SETTLED non-DISPUTED emission');
  }

  if (outcome === Outcome.DISPUTED) {
    if (prior.settledSeq === undefined) {
      return reject(seq > 0 ? 'RETRYABLE' : 'PERMANENT', 'HSP-RCPT-DISPUTE-NOPRIOR');
    }
    if (!(prior.settledSeq < seq)) return reject('PERMANENT', 'HSP-RCPT-DISPUTE-NOPRIOR', 'DISPUTED seq not greater than prior SETTLED');
    if (reorg.disputeWindowMs === undefined) {
      return reject('POLICY', 'HSP-LCYC-DISPUTE-WINDOW-CLOSED', 'adapter makes no reversal promise');
    }
    const delta = Number(receipt.settledAt) - (prior.settledAt ?? 0);
    if (!(delta >= 0 && delta * 1000 <= reorg.disputeWindowMs)) {
      return reject('PERMANENT', 'HSP-LCYC-DISPUTE-WINDOW-CLOSED', 'reversal outside disputeWindowMs');
    }
  } else if (outcome === Outcome.ATTEMPTED && !reorg.allowsAttempted) {
    return reject('POLICY', 'HSP-RCPT-OUTCOME-INCONSISTENT', 'ATTEMPTED not allowed by reorgPolicy');
  }
  // FAILED ends the attempt, not the stream: ATTEMPTED/SETTLED/FAILED may follow it.
  return null;
}

/**
 * §5.2 step 5 attestation walk for one required attests:* cap.
 * Per entry: decode claims (b) → recompute candidate cap id (integrity) → §3.3.3
 * admissibility (strict / monotone via the structured claims values) → CR2(a–e);
 * first valid wins. On failure returns the CR3 most-severe code + §8.0 class.
 */
async function walkCap(
  reg: ParsedCapability,
  expectedSubject: PartyRef | undefined,
  attestations: Attestation[],
  policy: VerificationPolicy,
  now: number,
  mandateHash: Hex,
  receiptHash: Hex,
): Promise<{ satisfied: boolean; code?: string; outcomeClass?: OutcomeClass }> {
  const famId = familyCapId(`${reg.namespace}:${reg.name}:${reg.version}`);
  const anchors = policy.issuerTrustAnchors.get(famId) ?? [];
  const scope = policy.contextBindingScope.get(famId);

  let severity = 0; // 0 = none (MISSING), 1 = INVALID, 2 = ISSUER-UNTRUSTED
  for (const entry of attestations) {
    const schema = ATTESTATION_SCHEMAS[entry.schemaId];
    if (!schema) continue; // schema we can't interpret — may be for another cap
    let candParams;
    try {
      candParams = schema.decodeClaims(entry.claims); // CR2(f) decode + (b) structured values
    } catch {
      continue;
    }
    let candidate: ParsedCapability;
    try {
      candidate = makeCap(schema.baseCapKey, Object.fromEntries(candParams.map((p) => [p.key, p.value])));
    } catch {
      continue;
    }
    // integrity: claims-derived cap id MUST equal the declared capabilityId
    if (candidate.baseId.toLowerCase() !== entry.capabilityId.toLowerCase()) continue;
    // §3.3.3 admissibility for the required cap (strict or monotone, on structured values)
    if (!capSatisfies(reg, candidate)) continue;
    // admissible — run CR2 (a)–(e)
    const cr2 = await validateCR2(entry, expectedSubject, anchors, now, mandateHash, receiptHash, scope);
    if (cr2.ok) return { satisfied: true };
    severity = Math.max(severity, cr2.code === 'HSP-ATT-ISSUER-UNTRUSTED' ? 2 : 1);
  }
  const code = severity === 2 ? 'HSP-ATT-ISSUER-UNTRUSTED' : severity === 1 ? 'HSP-ATT-INVALID' : 'HSP-ATT-MISSING';
  // §8.0: RETRYABLE when the trust set admits some issuer for the cap (fetch/swap a valid entry); else POLICY.
  const outcomeClass: OutcomeClass = anchors.length > 0 ? 'RETRYABLE' : 'POLICY';
  return { satisfied: false, code, outcomeClass };
}

export async function verifyPhaseB(
  mandate: SignedMandate,
  a: PhaseAResult,
  receipt: Receipt,
  attestations: Attestation[],
  policy: VerificationPolicy,
  seqIndex: SeqIndex,
  obsIndex: ObservationIndex = new ObservationIndex(),
): Promise<AcceptDecision> {
  const body = mandate.body;
  const now = policy.evaluationTime;

  // step 1 — linkage. (Role-wrapper resolution over requiredCapabilities is M2:
  //   it needs the id→registration lookup tied to the §3.3.3 (b) decision. M1 caps are empty.)
  if (receipt.mandateHash !== a.mandateHash) return reject('PERMANENT', 'HSP-RCPT-LINK');

  // step 2 — adapter trust
  const trustEntry = policy.adapterTrust.get(adapterKey(receipt.adapterId, receipt.adapterInstanceKey));
  if (!trustEntry) return reject('POLICY', 'HSP-RCPT-SIG', 'adapter instance not in trust set');
  const rHash = computeReceiptHash(a.domain, receipt);
  let recoveredAdapter: Address;
  try {
    recoveredAdapter = await recoverAddress({ hash: rHash, signature: receipt.adapterSignature });
  } catch {
    return reject('PERMANENT', 'HSP-RCPT-SIG', 'adapterSignature recover failed');
  }
  if (getAddress(recoveredAdapter) !== getAddress(trustEntry.address)) return reject('PERMANENT', 'HSP-RCPT-SIG');

  // S4 equivocation (§2.2.3)
  if (seqIndex.isEquivocation(receipt.adapterId, receipt.adapterInstanceKey, receipt.mandateHash, Number(receipt.seq), rHash)) {
    return reject('PERMANENT', 'HSP-RCPT-EQUIVOCATION');
  }

  // step 3 — schema match + admission
  const schemaReg = policy.proofSchemas.get(schemaKey(receipt.adapterId, receipt.proofSchemaId));
  if (!schemaReg) return reject('POLICY', 'HSP-RCPT-SCHEMA-UNKNOWN');
  const prior = seqIndex.state(receipt.adapterId, receipt.adapterInstanceKey, receipt.mandateHash);
  if (!admissible(schemaReg.admission, prior.seen, Number(receipt.outcome) as OutcomeValue)) {
    // prior-not-yet-witnessed (submit it first) = RETRYABLE; schema retired for new = POLICY (§8.0)
    const cls: OutcomeClass = !prior.seen ? 'POLICY' : 'RETRYABLE';
    return reject(cls, 'HSP-RCPT-SCHEMA-DEPRECATED');
  }

  // step 4 — proof verification + settlement consistency
  const ctx: VerifyContext = {
    proofBytes: receipt.adapterProof,
    body,
    mandateHash: a.mandateHash,
    signerSubject: a.signerDecision.resolvedSubject!,
    payerAccount: a.payerAccount,
    receipt: stripProof(receipt),
    now,
    trustRoots: schemaReg.trustRoots,
  };
  const outcome = await schemaReg.schema.verify(ctx);
  if (!outcome.ok) return reject('PERMANENT', outcome.errorCode ?? 'HSP-RCPT-PROOF');
  const upperBound = new Set(schemaReg.allowedCapabilities.map((c) => c.toLowerCase()));
  for (const c of outcome.proofSatisfiedCapabilities) {
    if (!upperBound.has(c.toLowerCase())) return reject('PERMANENT', 'HSP-PROOF-CAP-NOT-DERIVED', c);
  }
  const consistency = checkSettlementConsistency(body, mandate.requiredCapabilities, outcome);
  if (consistency) return consistency;

  // step 5 — capability dispatch + attestation walk (two-source union begins with proofSatisfiedCapabilities)
  const covered = new Set<string>(outcome.proofSatisfiedCapabilities.map((c) => c.toLowerCase()));
  const reqCanon = canonicalizeCapSet(mandate.requiredCapabilities);
  for (const C of reqCanon) {
    if (covered.has(C.toLowerCase())) continue;
    const reg = policy.capabilityRegistry.get(C);
    if (!reg) return reject('POLICY', 'HSP-CAP-UNKNOWN', C); // §3.3.2 C2 (fail-closed)
    // role-wrapper resolution (§5.2 step 1 / C4)
    let expectedSubject: PartyRef | undefined;
    if (reg.role) {
      expectedSubject = a.roleAssignment[reg.role];
      if (!expectedSubject) {
        // §8.0: only auditor can be unfilled (payer/payee always assigned once Phase A passes) → POLICY
        return reject('POLICY', 'HSP-SUBJ-ROLE-UNRESOLVED', reg.role);
      }
    }
    if (reg.namespace === 'attests') {
      const res = await walkCap(reg, expectedSubject, attestations, policy, now, a.mandateHash, rHash);
      if (res.satisfied) covered.add(C.toLowerCase());
      else return reject(res.outcomeClass ?? 'PERMANENT', res.code ?? 'HSP-ATT-MISSING', C);
    }
    // structural caps (hides/discloses/proves) are satisfied via step-4 proofSatisfiedCapabilities;
    // any still-uncovered required cap falls through to the step-6 check.
  }

  // step 6 — capability subset check (full two-source union)
  const missing = reqCanon.filter((c) => !covered.has(c.toLowerCase()));
  if (missing.length > 0) return reject('PERMANENT', 'HSP-RCPT-REQ-UNMET', missing.join(','));

  // step 7 — outcome / sequencing consistency
  // settlement deadline: a pure wire-field comparison (evaluationTime plays no role)
  const oc = Number(receipt.outcome) as OutcomeValue;
  if ((oc === Outcome.ATTEMPTED || oc === Outcome.SETTLED) && Number(receipt.settledAt) > Number(body.deadline)) {
    return reject('PERMANENT', 'HSP-MAND-EXPIRED', 'settledAt > body.deadline (settled after mandate expiry)');
  }
  // grant validity window (delegated only) — the delegation must be live at settlement (§5.2 step 7)
  if (a.grantWindow && (oc === Outcome.ATTEMPTED || oc === Outcome.SETTLED)) {
    const sa = Number(receipt.settledAt);
    if (sa < a.grantWindow.notBefore || sa > a.grantWindow.expiry) {
      return reject('PERMANENT', 'HSP-GRANT-EXPIRED', 'settledAt outside [grant.notBefore, grant.expiry]');
    }
  }
  const seqCheck = checkSequencing(receipt, trustEntry, prior);
  if (seqCheck) return seqCheck;
  // observation consumption: one settlement-native observation settles at most one
  // mandate — keyed (adapterId, observationId), ACROSS adapter instances.
  if (outcome.observationId) {
    const owner = obsIndex.owner(receipt.adapterId, outcome.observationId);
    if (owner && owner.toLowerCase() !== receipt.mandateHash.toLowerCase()) {
      return reject('PERMANENT', 'HSP-RCPT-OBS-REUSED', `observation already consumed by ${owner}`);
    }
  }

  // accept — record the admitted emission in the stateful indexes
  seqIndex.record(receipt.adapterId, receipt.adapterInstanceKey, receipt.mandateHash, {
    seq: Number(receipt.seq),
    outcome: oc,
    settledAt: Number(receipt.settledAt),
    receiptHash: rHash,
  });
  if (outcome.observationId) {
    obsIndex.record(receipt.adapterId, outcome.observationId, receipt.mandateHash);
  }
  return { ok: true, outcomeClass: outcomeClassForOk(oc) };
}

// =============================================================================
// Top-level verify (Phase A → Phase B)
// =============================================================================

/**
 * Full verification. For multi-receipt sequencing across calls, pass a SHARED
 * SeqIndex (the stateful-admission layer persists between receipts of one mandate).
 */
export async function verify(
  mandate: SignedMandate,
  receipt: Receipt,
  attestations: Attestation[],
  policy: VerificationPolicy,
  seqIndex: SeqIndex = new SeqIndex(),
  obsIndex: ObservationIndex = new ObservationIndex(),
  grant?: SignedDelegationGrant, // delegated payments — the Principal-signed grant (§2.1.1)
): Promise<AcceptDecision> {
  const a = await verifyPhaseA(mandate, policy, grant);
  if (!a.ok) return a.decision;
  return verifyPhaseB(mandate, a.result, receipt, attestations, policy, seqIndex, obsIndex);
}

export { SeqIndex, ObservationIndex } from './seq-index.js';
