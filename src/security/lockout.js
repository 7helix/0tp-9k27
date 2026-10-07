// Progressive lockout. After `maxFailures` wrong attempts the account is locked for `baseMs`,
// and the lock doubles with every further failure, up to `maxMs`.
const DAY_MS = 24 * 3_600_000;

export class LockoutPolicy {
  constructor({ store, maxFailures = 5, baseMs = 30_000, maxMs = 3_600_000, clock = Date.now }) {
    this.store = store;
    this.maxFailures = maxFailures;
    this.baseMs = baseMs;
    this.maxMs = maxMs;
    this.clock = clock;
  }

  #key(id) {
    return `lock:${id}`;
  }

  async status(id) {
    const record = await this.store.get(this.#key(id));
    const now = this.clock();
    if (record && record.lockedUntil > now) return { locked: true, retryAfterMs: record.lockedUntil - now };
    return { locked: false, retryAfterMs: 0 };
  }

  async recordFailure(id) {
    const now = this.clock();
    return this.store.update(this.#key(id), (record) => {
      const failures = (record?.failures || 0) + 1;
      let lockedUntil = record?.lockedUntil || 0;

      if (failures >= this.maxFailures) {
        const lockMs = this.baseMs * 2 ** (failures - this.maxFailures);
        lockedUntil = now + Math.min(this.maxMs, lockMs);
      }
      return { failures, lockedUntil };
    }, DAY_MS);
  }

  async reset(id) {
    await this.store.del(this.#key(id));
  }
}
