/**
 * Discovery + the envelope layer.
 *
 * Two objects, deliberately distinct (HSP.md §7.7 + HSP-bindings §3):
 *  - PayeeRequirement — the verifier/Coordinator's §7.7 advertisement
 *    (NORMATIVE format; policy projection; carries NO amount). Re-exported
 *    from @hsp/core.
 *  - PaymentRequest — a single invoice ("pay me X"): delivery-envelope layer,
 *    off-wire, owned by the SDK, optionally carrying the §7.7 ad it was built
 *    against. HSPClient.pay(paymentRequest) consumes it.
 */

import type { Address } from 'viem';
import type { PayeeRequirement } from '@hsp/core/policy/public';
import type { ChainConfig } from '@hsp/core/chains/index';

export type { PayeeRequirement };

export interface PaymentRequest {
  to: Address;
  token?: Address;
  amount: string; // base units, decimal string
  chainId: number;
  /** Coordinator chain-registry name (e.g. 'hashkey', 'anvil-dev'). */
  chain?: string;
  requirements?: PayeeRequirement;
}

/**
 * Payee-side invoicing helper: build the PaymentRequest your checkout hands to
 * payers ("pay me X on chain Y"), optionally carrying the deployment's §7.7
 * requirements ad. HSPClient.pay(paymentRequest) consumes it — the payer↔payee
 * handshake closes without either side hand-assembling fields.
 */
export function buildPaymentRequest(
  chain: ChainConfig,
  p: { to: Address; amount: bigint; token?: Address; requirements?: PayeeRequirement },
): PaymentRequest {
  const req: PaymentRequest = {
    to: p.to,
    token: p.token ?? chain.stablecoin.address,
    amount: p.amount.toString(),
    chainId: chain.chainId,
    chain: chain.name,
  };
  if (p.requirements) req.requirements = p.requirements;
  return req;
}

export async function fetchRequirements(coordinatorUrl: string, chain: string): Promise<PayeeRequirement> {
  const res = await fetch(`${coordinatorUrl.replace(/\/$/, '')}/requirements?chain=${encodeURIComponent(chain)}`);
  if (!res.ok) throw new Error(`requirements fetch failed: HTTP ${res.status}`);
  return (await res.json()) as PayeeRequirement;
}
