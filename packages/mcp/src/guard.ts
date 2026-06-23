/**
 * SpendGuard — server-side guardrails for hsp_pay (mainnet real money):
 * per-tx cap, rolling daily cap (UTC day, in-memory), optional recipient
 * allowlist. The agent key is demo/small-amount scoped by policy; these caps
 * are the enforcement, independent of whatever the model decides to call.
 */

export class SpendGuard {
  private dayKey = '';
  private spentToday = 0n;

  constructor(
    private readonly maxPerTx: bigint | undefined,
    private readonly dailyCap: bigint | undefined,
    private readonly allowlist: Set<string> | undefined,
  ) {}

  /** Returns a refusal reason, or null when the spend is admissible. */
  check(to: string, amount: bigint): string | null {
    if (this.allowlist && !this.allowlist.has(to.toLowerCase())) {
      return 'recipient is not in HSP_RECIPIENT_ALLOWLIST';
    }
    if (this.maxPerTx !== undefined && amount > this.maxPerTx) {
      return `amount ${amount} exceeds per-tx cap HSP_MAX_AMOUNT_BASE_UNITS=${this.maxPerTx}`;
    }
    this.roll();
    if (this.dailyCap !== undefined && this.spentToday + amount > this.dailyCap) {
      return `daily cap HSP_DAILY_CAP_BASE_UNITS=${this.dailyCap} would be exceeded (spent today: ${this.spentToday})`;
    }
    return null;
  }

  commit(amount: bigint): void {
    this.roll();
    this.spentToday += amount;
  }

  remainingToday(): bigint | undefined {
    if (this.dailyCap === undefined) return undefined;
    this.roll();
    return this.dailyCap - this.spentToday;
  }

  private roll(): void {
    const today = new Date().toISOString().slice(0, 10);
    if (today !== this.dayKey) {
      this.dayKey = today;
      this.spentToday = 0n;
    }
  }
}
