// Store contract (implement this to plug in Redis / Postgres / DynamoDB ...):
//   async get(key)                 -> value | undefined
//   async set(key, value, ttlMs)   -> void
//   async del(key)                 -> void
//   async update(key, fn)          -> new value. `fn(current)` MUST be synchronous.
//        return undefined = no change, null = delete, anything else = new value.
//        The write keeps the existing TTL. It MUST be atomic (this is what stops
//        parallel-guess attacks from racing past the attempt counter).
export class MemoryStore {
  #map = new Map();
  constructor({ clock = Date.now } = {}) { this.clock = clock; }

  #live(key) {
    const e = this.#map.get(key);
    if (!e) return undefined;
    if (e.exp !== null && e.exp <= this.clock()) { this.#map.delete(key); return undefined; }
    return e;
  }
  async get(key) { return this.#live(key)?.value; }
  async set(key, value, ttlMs = null) {
    this.#map.set(key, { value, exp: ttlMs ? this.clock() + ttlMs : null });
    this._changed?.();
  }
  async del(key) { this.#map.delete(key); this._changed?.(); }
  async update(key, fn, ttlMs = null) {
    const e = this.#live(key);
    const next = fn(e?.value);
    if (next === undefined) return e?.value;
    if (next === null) { this.#map.delete(key); this._changed?.(); return null; }
    this.#map.set(key, { value: next, exp: e ? e.exp : (ttlMs ? this.clock() + ttlMs : null) });
    this._changed?.();
    return next;
  }
  _dump() { return [...this.#map.entries()]; }
  _load(entries) { this.#map = new Map(entries); }
}
