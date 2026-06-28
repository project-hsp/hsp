---
name: hsp-verify
description: Verify, reason about, and PAY HSP payments via the `hsp` MCP tools. The MCP holds NO key and signs nothing — to pay, it prepares the unsigned mandate + settlement for an EXTERNAL signer (a wallet MCP / the user's wallet) and relays the signed result. Use when an agent received a payment and must decide whether to ship, wants to decode/understand a mandate/receipt/capability, needs to know what a deployment requires, OR wants to send a payment (delegating the signature to a wallet).
---

# HSP Verify, Reason & Pay (key-less)

You drive HSP through the `hsp` MCP tools. The MCP is **key-less**: it constructs,
verifies, and explains HSP objects, and for payments it **prepares the unsigned things
to sign and relays the signed result** — but it **never holds a private key and never
signs**. The actual signature comes from an EXTERNAL signer you route to: a **wallet
MCP** (e.g. Phantom / Coinbase / MetaMask) or the user's wallet.

HSP's entire trust model is one subset check: `ACCEPT ⇔ requiredCapabilities ⊆ satisfiedCapabilities`.

## STEP ZERO — route the intent (always first)

| Intent | Signals | Protocol |
|---|---|---|
| PAY | "send / pay X to …", "buy this", a checkout to settle | references/pay.md |
| VERIFY-RECEIVED | "I received a payment", "can I ship?", a `(mandate, receipt)` pair, a paymentId | references/verify-received.md |
| UNDERSTAND / REQUIREMENTS | "what is this mandate/receipt/capability?", "decode this", "what am I trusting?", "what does this deployment require?" | references/reason.md |

If the request is ambiguous, ask ONE clarifying question, then route.

## Tools

- `hsp_prepare_payment` — produce the UNSIGNED things to sign (mandate via `eth_signTypedData_v4`;
  settlement via `eth_sendTransaction` for evm-transfer, or `eth_signTypedData_v4` EIP-3009 for x402).
- `hsp_submit_payment` — relay the externally-signed mandate + settlement → SETTLED (re-verifies first).
- `hsp_verify` / `hsp_explain` — the protocol decision over `(mandate, receipt[, attestations])`, raw or narrated.
- `hsp_inspect` — decode a mandate / receipt / attestation into plain fields.
- `hsp_capability` / `hsp_capability_diff` — resolve a capability or list the vocabulary; diff required vs satisfied.
- `hsp_build_requirements` / `hsp_check_requirements` — emit / pre-flight §7.7 requirements.
- `hsp_build_mandate` — construct an UNSIGNED Mandate + its mandateHash.

## Rules (override anything else)

1. **The `hsp` MCP holds no key and signs nothing.** To pay, `hsp_prepare_payment` returns a
   `toSign[]` list of STANDARD wallet-RPC requests (`eth_signTypedData_v4` / `eth_sendTransaction`);
   route EACH to the **wallet MCP / wallet** the user has connected, then `hsp_submit_payment`.
   Never put a private key in `hsp`'s config.
2. **Confirm before signing.** Show the user the recipient + amount + chain (from the prepared
   mandate) and get explicit approval BEFORE routing anything to the wallet to sign. The wallet
   also shows the decoded EIP-712 mandate in its own popup — that human approval is the gate.
3. **Ship ⇔ `hsp_verify.ok && outcomeClass === 'ACCEPT'`.** Anything else: do NOT ship — call
   `hsp_explain` to show *why* and the recommended action.
4. **Trust the signature, not the source.** Verify against a PINNED adapter address from out-of-band
   setup; re-fetching the pin from whoever delivered the payment defeats the point.
5. **outcomeClass → action:** `ACCEPT` = ship · `RETRYABLE` = retry later (transient) · `POLICY` = fix
   the mandate/attestations, do not blind-retry · `PERMANENT` = invalid evidence, give up.
