# VERIFY-RECEIVED — independent verification before shipping

Use when the user (as merchant/payee) received a payment claim and must decide
whether to ship. The whole point: **do not trust the Coordinator's status** —
run the protocol verifier yourself against a PINNED adapter address.

1. Need: the `(mandate, receipt)` JSON pair. If the user only has a
   paymentId, fetch `GET <coordinator>/payments/<id>` and use `mandate` +
   the LAST entry of `receipts[].receipt`. No admitted receipts → nothing to
   verify yet; report PROPOSED/pending.
2. Call `hsp_verify {mandate, receipt}` (the server uses its pinned adapter
   address; pass `adapterAddress` only if the user explicitly provides a pin).
3. Decision:
   - `ship: true` (ok + ACCEPT) → safe to ship. Quote amount/recipient from
     the mandate body so the user sees WHAT was verified.
   - otherwise → DO NOT ship. Explain `errorCode`: `HSP-RCPT-SIG` = receipt
     not signed by the pinned adapter (possible forgery or wrong pin);
     `HSP-RCPT-PROOF` = settlement does not match the mandate (amount /
     recipient / token); `HSP-MAND-EXPIRED` = the settlement occurred after the
     mandate deadline (`settledAt > deadline`) — an on-time settlement that is
     verified later still ACCEPTs.
4. Remind the user once: the pin (`HSP_PINNED_ADAPTER_ADDRESS`) is their trust
   root; it should come from out-of-band setup, not from the message that
   delivered the payment claim.
