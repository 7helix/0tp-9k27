// Progressive lockout: after `maxFailures`, lock for baseMs, then double each further failure.
export class LockoutPolicy {
  constructor({ store, maxFailures = 5, baseMs = 30_000, maxMs = 3_600_000, clock = Date.now }) {
    Object.assign(this, { store, maxFailures, baseMs, maxMs, clock });
  }
  #key = (id) => `lock:${id}`;
  async status(id) {
    const s = await this.store.get(this.#key(id));
    const now = this.clock();
    return s && s.lockedUntil > now ? { locked: true, retryAfterMs: s.lockedUntil - now } : { locked: false, retryAfterMs: 0 };
  }
  async recordFailure(id) {
    const now = this.clock();
    return this.store.update(this.#key(id), (s) => {
      const failures = (s?.failures || 0) + 1;
      let lockedUntil = s?.lockedUntil || 0;
      if (failures >= this.maxFailures) {
        lockedUntil = now + Math.min(this.maxMs, this.baseMs * 2 ** (failures - this.maxFailures));
      }
      return { failures, lockedUntil };
    }, 24 * 3_600_000);
  }
  async reset(id) { await this.store.del(this.#key(id)); }
}
