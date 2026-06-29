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
   Prefer `hsp_explain {mandate, receipt}` when you need to SHOW the user why —
   it narrates the required vs provided capabilities, the recommended action,
   and the trust boundary (cryptographic vs operator-attested) alongside the verdict.
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

## Worked example

You received a `(mandate, receipt)` pair (or a `paymentId` → `GET <coordinator>/payments/<id>` →
`mandate` + the last `receipts[].receipt`).

**Verify** against your pinned adapter:
```jsonc
hsp_verify { mandate, receipt }
→ { "ok": true, "outcomeClass": "ACCEPT", "ship": true }
```

**Show the user WHY** (narrated):
```jsonc
hsp_explain { mandate, receipt }
→ {
  "ship": true,
  "decision": { "ok": true, "outcomeClass": "ACCEPT" },
  "recommendedAction": "ship / treat the payment as good",
  "requiredCapabilities": [],          // this payment required nothing beyond settlement
  "providedAttestations": [],
  "settlement": { "kind": "evm-transfer (operator-attested observation)",
                  "from": "0x…", "to": "0x…", "value": "1000000", "token": "0x…", "txHash": "0x…" },
  "trustBoundary": "the proof is an OPERATOR OBSERVATION (no payer signature in it); the from/to/value
                    binding rests on your pinned operator honestly observing the chain. Trust-min'd
                    settlement would require proves:settlement-verified (not provided here)."
}
```
→ Quote `settlement.value` + `settlement.to` back to the user, and note the trust boundary (here it's
operator-attested, not cryptographic). `ship: true` → safe to ship.

**A FAILING case** — receipt signed by a key other than your pin:
```jsonc
hsp_verify { mandate, receipt }
→ { "ok": false, "outcomeClass": "PERMANENT", "errorCode": "HSP-RCPT-SIG", "ship": false }
```
→ DO NOT ship; `HSP-RCPT-SIG` = the receipt isn't signed by your pinned adapter (forgery or wrong pin).

## Compliance payments — pass the attestations too

If the mandate's `requiredCapabilities` is **non-empty** (it requires `attests:kyc` / `attests:sanctions`),
the `(mandate, receipt)` pair alone won't verify — you also need the **attestations** that satisfy those
caps. `GET <coordinator>/payments/<id>` returns them alongside the mandate + receipts:
```jsonc
{ "status": "SETTLED", "mandate": {…}, "attestations": [ {…KYC…} ], "receipts": [ … ] }
```
Pass all three:
```jsonc
hsp_verify { mandate, receipt, attestations }   // attestations = the Attestation[] from /payments/<id>
```
The verifier checks the **issuer signatures** itself against your configured trusted issuers (the
verifier's `compliance` setup) — so, like the adapter pin, your trusted-issuer list is **out-of-band
setup**, not something you take from whoever delivered the payment. Common failures:
- `HSP-ATT-MISSING` — a required `attests:*` cap has no attestation (you forgot to pass them, or none exists).
- `HSP-ATT-ISSUER-UNTRUSTED` — the attestation's issuer isn't in your trusted-issuer config.
