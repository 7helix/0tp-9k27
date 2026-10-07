// Adapter for an ioredis-style client (get/set/del/watch/multi/unwatch).
//
// Not tested against a real Redis by the author. CI runs the store conformance suite against one
// (see .github/workflows/stores.yml), so check that before relying on it.
export class RedisStore {
  constructor(client, { prefix = 'otpf:' } = {}) {
    this.client = client;
    this.prefix = prefix;
  }

  async get(key) {
    const raw = await this.client.get(this.prefix + key);
    return raw === null ? undefined : JSON.parse(raw);
  }

  async set(key, value, ttlMs = null) {
    const k = this.prefix + key;
    if (ttlMs) await this.client.set(k, JSON.stringify(value), 'PX', ttlMs);
    else await this.client.set(k, JSON.stringify(value));
  }

  async del(key) {
    await this.client.del(this.prefix + key);
  }

  // Optimistic locking: WATCH the key, and if anything touches it before EXEC, try again.
  async update(key, fn, ttlMs = null) {
    const k = this.prefix + key;

    for (let attempt = 0; attempt < 8; attempt++) {
      await this.client.watch(k);
      const raw = await this.client.get(k);
      const current = raw === null ? undefined : JSON.parse(raw);
      const next = fn(current);

      if (next === undefined) {
        await this.client.unwatch();
        return current;
      }

      const tx = this.client.multi();
      if (next === null) tx.del(k);
      else if (raw !== null) tx.set(k, JSON.stringify(next), 'KEEPTTL');
      else if (ttlMs) tx.set(k, JSON.stringify(next), 'PX', ttlMs);
      else tx.set(k, JSON.stringify(next));

      if (await tx.exec()) return next;
    }
    throw new Error('RedisStore.update: too much contention');
  }
}
