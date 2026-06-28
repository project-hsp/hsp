# PAY — key-less, signature delegated to a wallet

The `hsp` MCP **never holds a key**. To pay, it PREPARES the unsigned mandate +
settlement, you route those to a **wallet MCP / the user's wallet** to sign, then the
MCP SUBMITS the signed result. Money moves only when the wallet signs — and the wallet
shows the user a decoded EIP-712 popup, so the human approval is the real gate.

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
   matches `item.method` with `item.params` (e.g. a wallet's `signTypedData` / `sendTransaction`).
   Collect, keyed by `id`:
   - `mandate` → the 0x signature,
   - `settlement` → the **txHash** (evm-transfer) OR, for x402, the EIP-3009 **signature** (carry the
     `relay` object through).

4. **Submit.** Call `hsp_submit_payment { paymentId, adapter, mandateBody, signed }` where
   `signed = { mandate: <sig>, settlement: <txHash | { authorization, signature, facilitatorUrl,
   merchantDomain, tokenName, tokenVersion }> }`. It re-verifies the mandate signature against the
   expected `paymentId` (a tampered body is REJECTED), registers it, relays the settlement, and
   returns `{ status, ship }`.

5. **Report.** `ship: true` (SETTLED + ACCEPT) → done; quote the amount/recipient back. Otherwise
   call `hsp_explain` on the resulting `(mandate, receipt)` to say why.

## Notes
- If no wallet MCP / wallet is connected, say so — the `hsp` MCP cannot sign on its own (by design).
- Spend limits / approvals live in the WALLET (its policy / session keys / popups), not in `hsp`.
- `x402` adapter is supported by prepare/submit; `evm-transfer` is the default direct payment.
