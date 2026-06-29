# PAY — key-less, signature delegated to a wallet

The `hsp` MCP **never holds a key**. To pay, it PREPARES the unsigned mandate +
settlement, you route those to a **wallet MCP / the user's wallet** to sign, then the
MCP SUBMITS the signed result. Money moves only when the wallet signs — and the wallet
shows the user a decoded EIP-712 popup, so the human approval is the real gate.

The MCP's key-less `prepare → submit` covers **simple public payments** — `evm-transfer`
(direct) and `x402` (machine payment). Compliance + delegated payments are a separate
section at the bottom.

## Flow

1. **Prepare.** Call `hsp_prepare_payment { payer, to, amount, adapter }` (`adapter` =
   `evm-transfer` default, or `x402` + `facilitatorUrl`). It returns:
   - `paymentId` (the mandateHash),
   - `mandateBody` (pass it back verbatim to submit),
   - `toSign[]` — a list of STANDARD wallet requests, each `{ id, method, params }`:
     - the **mandate**: `method: 'eth_signTypedData_v4'`,
     - the **settlement**: `eth_sendTransaction` (evm-transfer — the wallet signs AND broadcasts)
       or `eth_signTypedData_v4` (x402 — an EIP-3009 authorization; a `relay` hint travels with it).

2. **Confirm with the user.** Show recipient + amount + chain (read from the prepared mandate).
   Get explicit approval. Do NOT route to the wallet before that.

3. **Sign — route each `toSign[]` to the WALLET.** For each item, call the wallet MCP tool that
   matches `item.method` with `item.params`. Collect, keyed by `id`:
   - `mandate` → the 0x signature,
   - `settlement` → the **txHash** (evm-transfer) OR, for x402, the EIP-3009 **signature** (carry the
     `relay` object through).

4. **Submit.** Call `hsp_submit_payment { paymentId, adapter, mandateBody, signed }`. It re-verifies the
   mandate signature against the expected `paymentId` (a tampered body is REJECTED), registers it, relays
   the settlement, and returns `{ status, ship }`.

5. **Report.** `ship: true` (SETTLED + ACCEPT) → done; quote the amount/recipient back. Otherwise
   call `hsp_explain` on the resulting `(mandate, receipt)` to say why.

## Worked example — direct (evm-transfer)

Pay 1 USDC (`1000000` base units) to `0xRECIPIENT`.

**1 — Prepare** → the MCP returns (abbreviated):
```jsonc
hsp_prepare_payment { payer: "0xPAYER", to: "0xRECIPIENT", amount: "1000000" }
→ {
  "paymentId": "0x9a…",                       // = mandateHash
  "adapter": "evm-transfer",
  "mandateBody": { "nonce": "0x…", "signer": {…}, "recipient": {…}, "token": "0xTOKEN",
                   "amount": "1000000", "chainId": 133, "deadline": 1750000000, … },
  "toSign": [
    { "id": "mandate", "method": "eth_signTypedData_v4",
      "params": { "address": "0xPAYER", "typedData": { "primaryType": "Mandate", "domain": {…}, "types": {…}, "message": {…} } },
      "expect": { "mandateHash": "0x9a…" } },
    { "id": "settlement", "method": "eth_sendTransaction",
      "params": { "tx": { "from": "0xPAYER", "to": "0xTOKEN", "data": "0xa9059cbb…", "value": "0x0", "chainId": 133 } } }
  ]
}
```

**2 — Confirm** recipient + amount + chain with the user.

**3 — Sign (route to the wallet):**
- `mandate` → wallet `eth_signTypedData_v4(params.address, params.typedData)` → `0x<sig>`.
  (Sanity: the wallet's digest should equal `expect.mandateHash`.)
- `settlement` → wallet `eth_sendTransaction(params.tx)` → it broadcasts the ERC-20 transfer → a `0x<txHash>`.

**4 — Submit:**
```jsonc
hsp_submit_payment {
  paymentId: "0x9a…", adapter: "evm-transfer",
  mandateBody: <verbatim from prepare>,
  signed: { mandate: "0x<sig>", settlement: "0x<txHash>" }
}
→ { "status": "SETTLED", "ship": true }
```

**5 — Report** — `ship: true` → done.

## x402 variant (gasless for the payer; the facilitator settles)

`hsp_prepare_payment { …, adapter: "x402", facilitatorUrl }`. The `settlement` `toSign` item is an
**EIP-3009** `eth_signTypedData_v4` (NOT a tx — the facilitator submits + pays gas), and it carries a
`relay` object (`facilitatorUrl`, `merchantDomain`, `tokenName`, `tokenVersion`, `authorization`).
Sign the EIP-3009 typed data, then submit with the relay + that signature:
```jsonc
hsp_submit_payment { paymentId, adapter: "x402", mandateBody,
  signed: { mandate: "0x<sig>", settlement: { ...relay, signature: "0x<eip3009Sig>" } } }
```

## Beyond simple payments — compliance & delegation

The key-less `prepare → submit` above is for **public** payments. Two cases it does NOT do end-to-end —
fall back to `@hsp/sdk`:

- **Compliance (a mandate that REQUIRES `attests:kyc` / `attests:sanctions`).** `hsp_submit_payment`
  registers with **no attestations**, so a compliance mandate would fail verification. Use
  `@hsp/sdk` `pay({ profile: { compliance } })` (it fetches the issuer attestations and attaches them).
  The MCP still helps you *understand* the requirement first: `hsp_build_requirements` /
  `hsp_check_requirements`.
- **Delegated payments (a Principal authorizing an Agent).** `hsp_prepare_payment` builds a *self-pay*
  mandate (no `grantRef`), and the principal's account-execute settlement isn't constructed here. For a
  streamlined delegated payment use `@hsp/sdk` `payDelegated`. The MCP gives the building blocks —
  `hsp_build_grant` (the grant), `hsp_build_mandate { grantRef }` (a delegated mandate), and
  `hsp_submit_payment { grant }` accepts a `SignedDelegationGrant` — for advanced manual flows.

## Notes
- If no wallet MCP / wallet is connected, say so — the `hsp` MCP cannot sign on its own (by design).
- Spend limits / approvals live in the WALLET (its policy / session keys / popups), not in `hsp`.
- `x402` adapter is supported by prepare/submit; `evm-transfer` is the default direct payment.
