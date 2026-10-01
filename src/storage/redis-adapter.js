// REFERENCE adapter for an ioredis-compatible client (get/set/del/watch/multi/unwatch).
// NOTE: written as a learning template - test it against your own Redis before production use.
export class RedisStore {
  constructor(client, { prefix = 'otpf:' } = {}) { this.c = client; this.p = prefix; }
  async get(key) { const v = await this.c.get(this.p + key); return v === null ? undefined : JSON.parse(v); }
  async set(key, value, ttlMs = null) {
    if (ttlMs) await this.c.set(this.p + key, JSON.stringify(value), 'PX', ttlMs);
    else await this.c.set(this.p + key, JSON.stringify(value));
  }
  async del(key) { await this.c.del(this.p + key); }
  // Optimistic transaction: retry if the key changed between WATCH and EXEC.
  async update(key, fn, ttlMs = null) {
    const k = this.p + key;
    for (let attempt = 0; attempt < 8; attempt++) {
      await this.c.watch(k);
      const raw = await this.c.get(k);
      const next = fn(raw === null ? undefined : JSON.parse(raw));
      if (next === undefined) { await this.c.unwatch(); return raw === null ? undefined : JSON.parse(raw); }
      const tx = this.c.multi();
      if (next === null) tx.del(k);
      else if (raw !== null) tx.set(k, JSON.stringify(next), 'KEEPTTL');
      else if (ttlMs) tx.set(k, JSON.stringify(next), 'PX', ttlMs);
      else tx.set(k, JSON.stringify(next));
      if (await tx.exec()) return next;
    }
    throw new Error('RedisStore.update: too much contention');
  }
}
