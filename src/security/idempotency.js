// Idempotency keys. If a client retries "send me a code" after a timeout, it shouldn't cost a second
// SMS. The first request runs, and retries get the saved result.
export class Idempotency {
  constructor({ store, ttlMs = 600_000 }) {
    this.store = store;
    this.ttlMs = ttlMs;
  }

  async once(key, fn) {
    const storeKey = `idem:${key}`;

    let claimed = false;
    const record = await this.store.update(storeKey, (existing) => {
      if (existing) return undefined;
      claimed = true;
      return { state: 'pending' };
    }, this.ttlMs);

    if (!claimed) {
      if (record.state === 'done') return { ...record.result, replayed: true };
      return { ok: false, reason: 'in_progress' };
    }

    try {
      const result = await fn();
      await this.store.update(storeKey, () => ({ state: 'done', result }));
      return result;
    } catch (err) {
      await this.store.del(storeKey); // a failed attempt may be retried
      throw err;
    }
  }
}
