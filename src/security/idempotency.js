// Idempotency keys: a client retrying "send OTP" after a timeout must not trigger a second SMS
// (cost + user confusion). First request runs; retries get the cached result.
export class Idempotency {
  constructor({ store, ttlMs = 600_000 }) { Object.assign(this, { store, ttlMs }); }
  async once(key, fn) {
    const k = `idem:${key}`; let claimed = false;
    const rec = await this.store.update(k, (cur) => { if (cur) return undefined; claimed = true; return { state: 'pending' }; }, this.ttlMs);
    if (!claimed) return rec.state === 'done' ? { ...rec.result, replayed: true } : { ok: false, reason: 'in_progress' };
    try {
      const result = await fn();
      await this.store.update(k, () => ({ state: 'done', result }));
      return result;
    } catch (e) { await this.store.del(k); throw e; } // allow a genuine retry after failure
  }
}
