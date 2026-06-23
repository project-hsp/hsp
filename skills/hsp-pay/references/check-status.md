# CHECK-STATUS — track a payment by paymentId

1. Need: the `paymentId` (a 0x… 32-byte hash — it IS the mandate hash, so the
   payer can recompute it locally; any party with the id may query).
2. Call `hsp_status {paymentId}`.
3. Explain the status in one line:
   - `PROPOSED` — mandate registered, no admitted settlement yet.
   - `ATTEMPTED` — settlement submitted, not final yet.
   - `SETTLED` — settled and verified (ACCEPT). Done.
   - `FAILED` — the adapter attested the payment failed.
   - `DISPUTED` — a previously settled receipt was reversed (reorg/dispute).
   - `EXPIRED` — mandate deadline passed without settlement (re-pay needs a
     fresh mandate — a new payment).
4. If `rejectedSubmissions > 0`, mention that some submissions were rejected
   by the verifier without affecting the payment (e.g. a wrong txHash) — the
   payment is still settleable while not EXPIRED.
5. For PROPOSED/ATTEMPTED the user may ask you to wait: poll every few
   seconds, up to ~a minute, then report.
