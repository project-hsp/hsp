---
name: hsp-verify
description: Verify, inspect, and reason about HSP payments via the `hsp` MCP tools (pure / key-less — they move no money and hold no key). Use when an agent RECEIVED an HSP payment and must decide whether to ship, wants to decode/understand a mandate/receipt/capability, or needs to know what a deployment requires before paying.
---

# HSP Verify & Reason

You reason about HSP payments through the `hsp` MCP tools — all **pure and key-less**:
they construct, verify, and explain HSP wire objects, capabilities, and policy, but
**move no money and hold no key**. HSP's entire trust model is one subset check:

```
ACCEPT  ⇔  requiredCapabilities ⊆ satisfiedCapabilities
```

These tools let you run and explain that decision, decode the wire objects, and reason
about what a payment requires. (To actually *send* a payment, that is `@hsp/sdk` — out
of this skill's scope.)

## STEP ZERO — route the intent (always first)

| Intent | Signals | Protocol |
|---|---|---|
| VERIFY-RECEIVED | "I received a payment", "can I ship?", a `(mandate, receipt)` pair, a paymentId | references/verify-received.md |
| UNDERSTAND / REQUIREMENTS | "what is this mandate/receipt/capability?", "decode this", "what am I trusting?", "what does this deployment require?", "will this mandate pass?" | references/reason.md |

If the request is ambiguous, ask ONE clarifying question, then route.

## Tools

- `hsp_verify` — the raw protocol decision over `(mandate, receipt[, attestations])`.
- `hsp_explain` — the same decision NARRATED: required vs provided capabilities, the
  outcomeClass → recommended action, the error-code meaning, and the trust boundary.
- `hsp_inspect` — decode a mandate / receipt / attestation into plain fields.
- `hsp_capability` / `hsp_capability_diff` — resolve a capability or list the vocabulary;
  diff a required vs satisfied set.
- `hsp_build_requirements` / `hsp_check_requirements` — emit / pre-flight §7.7 requirements.
- `hsp_build_mandate` — construct an UNSIGNED MandateBody + its mandateHash (signing is external).

## Rules (override anything else)

1. **Ship ⇔ `hsp_verify.ok && outcomeClass === 'ACCEPT'`.** Anything else: do NOT ship —
   call `hsp_explain` to show the user *why* and the recommended action.
2. **Trust the signature, not the source.** Verify against a PINNED adapter address that
   came from out-of-band setup; re-fetching the pin from whoever delivered the payment
   defeats the point.
3. **These tools never move money and hold no key.** If the user asks to *pay / send*,
   say so plainly and point them to `@hsp/sdk` (`HSPClient.pay` / `payX402`).
4. **outcomeClass → action:** `ACCEPT` = ship · `RETRYABLE` = retry later (transient) ·
   `POLICY` = fix the mandate/attestations, do not blind-retry · `PERMANENT` = invalid
   evidence, give up on this submission.
