/**
 * §8.0 outcomeClass — the verifier's normative coarse client action.
 *
 * The class is computed from the NATURE of the result, not from the errorCode
 * string (most codes span classes). For ok==false the rejection site supplies the
 * class directly (it knows the nature); for ok==true the class follows the Receipt
 * outcome. Aggregation has two modes (§8.0).
 */

import { Outcome, type OutcomeValue } from '../core/index.js';
import type { OutcomeClass } from './contracts.js';

/** §8.0: ok==true → SETTLED=ACCEPT, ATTEMPTED=RETRYABLE, FAILED/DISPUTED=PERMANENT. */
export function outcomeClassForOk(receiptOutcome: OutcomeValue): OutcomeClass {
  switch (receiptOutcome) {
    case Outcome.SETTLED:
      return 'ACCEPT';
    case Outcome.ATTEMPTED:
      return 'RETRYABLE';
    case Outcome.FAILED:
    case Outcome.DISPUTED:
      return 'PERMANENT';
    default:
      return 'PERMANENT';
  }
}

// Recoverability orderings over the three FAILURE classes (§8.0 aggregation).
const MOST_RECOVERABLE: OutcomeClass[] = ['RETRYABLE', 'POLICY', 'PERMANENT'];
const LEAST_RECOVERABLE: OutcomeClass[] = ['PERMANENT', 'POLICY', 'RETRYABLE'];

function pickByOrder(classes: OutcomeClass[], order: OutcomeClass[], fallback: OutcomeClass): OutcomeClass {
  let best = fallback;
  let bestRank = order.indexOf(best);
  for (const c of classes) {
    const r = order.indexOf(c);
    if (r >= 0 && r < bestRank) {
      best = c;
      bestRank = r;
    }
  }
  return best;
}

/**
 * Alternatives for ONE obligation (e.g. several attestation entries for one cap):
 * take the most recoverable class any single path yields (RETRYABLE > POLICY > PERMANENT).
 */
export function mostRecoverable(classes: OutcomeClass[]): OutcomeClass {
  return pickByOrder(classes, MOST_RECOVERABLE, 'PERMANENT');
}

/**
 * Independent failures that must ALL hold: take the least recoverable class
 * (PERMANENT > POLICY > RETRYABLE) — one un-fixable failure makes the result terminal.
 */
export function leastRecoverable(classes: OutcomeClass[]): OutcomeClass {
  return pickByOrder(classes, LEAST_RECOVERABLE, 'RETRYABLE');
}
