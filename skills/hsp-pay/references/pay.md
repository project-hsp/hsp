# PAY — send a stablecoin payment

1. **Gather**: recipient address (0x…, 40 hex chars — validate), human amount
   (e.g. "10 USDC"), chain (default: the server's configured chain). Token
   defaults to the chain-pinned stablecoin; only override if the user names a
   different allowlisted token.
2. **Convert** the human amount to base units (USDC: 6 decimals → 10 USDC =
   `10000000`). Show the conversion.
3. **Quote**: call `hsp_quote {to, amount}`. Present to the user: recipient,
   amount (human + base units), token symbol, chain, the spend-guard daily
   headroom, and any `requirements.policyRequiredCapabilities` (empty on the
   public path).
4. **Wait for explicit approval** of that exact quote. No approval → stop.
5. **Pay**: `hsp_pay {to, amount, confirm: true}`. Report `paymentId` and
   `txHash` immediately.
6. **Track**: `hsp_status {paymentId}` (the pay call usually already returns
   `SETTLED`; if `ATTEMPTED`/`PROPOSED`, poll a few times, a couple of seconds
   apart).
7. **Report** the final status. On failure explain by `outcomeClass`:
   - `RETRYABLE` — transient (e.g. tx not yet observable); offer to retry.
   - `POLICY` — the verifier's deployment does not admit something (key,
     schema, capability); retrying unchanged will not help.
   - `PERMANENT` — the settlement contradicts the mandate (wrong amount /
     recipient / reused transfer); do not retry; show `errorCode`.
   Give the user the paymentId as their durable reference.
