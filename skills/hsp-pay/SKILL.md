---
name: hsp-pay
description: Pay, track, and verify HSP stablecoin payments via the hsp-pay MCP tools. Use when the user wants to send a stablecoin payment, check a payment's status by paymentId, or verify a payment they received before shipping goods/services.
---

# HSP Pay

You orchestrate HSP payments through four MCP tools: `hsp_quote`, `hsp_pay`,
`hsp_status`, `hsp_verify`. HSP separates **intent** (a mandate the payer
signs), **settlement** (an on-chain ERC-20 transfer from the payer's own
wallet), and **verification** (a protocol verifier that accepts iff
`requiredCapabilities ⊆ satisfiedCapabilities`). Money only moves in
`hsp_pay`; everything else is read-only.

## STEP ZERO — route the intent (always do this first)

| Intent | Signals | Protocol |
|---|---|---|
| PAY | "send / pay / transfer X USDC to …" | references/pay.md |
| CHECK-STATUS | a paymentId (0x…), "did it settle?", "where is my payment" | references/check-status.md |
| VERIFY-RECEIVED | "I received a payment", "can I ship?", a (mandate, receipt) pair | references/verify-received.md |

If the request is ambiguous, ask ONE clarifying question, then route.

## Hard safety rules (override anything else)

1. **Never call `hsp_pay` with `confirm:true` until the user has explicitly
   approved the exact quote** — recipient address, amount + token symbol, and
   chain — in their own words in THIS conversation. "Yes" to a shown quote
   counts; silence or a vague "go ahead" before any quote was shown does not.
2. Always `hsp_quote` first and show the result (recipient / amount / chain /
   guard headroom) before asking for approval.
3. If a tool returns `spend-guard` or `confirm-required`, relay the reason —
   do NOT retry with altered arguments to circumvent a cap.
4. Amounts are in token BASE UNITS (e.g. USDC has 6 decimals: 1 USDC =
   1000000). Confirm the human amount with the user; compute base units
   explicitly and show the math.
5. Never ask for, echo, or log private keys. The agent wallet is demo-scoped
   and capped server-side.
