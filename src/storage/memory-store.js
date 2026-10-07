// The store interface. Anything that implements it (Redis, Postgres, DynamoDB, ...) can back the
// rest of the code. tests/helpers/store-conformance.js checks an implementation against it.
//
//   get(key)                -> value, or undefined
//   set(key, value, ttlMs)  -> stores a value, ttl is optional
//   del(key)
//   update(key, fn, ttlMs)  -> atomic read-modify-write, returns the new value.
//
// For update(), fn gets the current value (undefined if there isn't one) and must be synchronous.
// Return undefined to leave things as they are, null to delete, anything else to store it. The key
// keeps its existing TTL. The atomicity matters: attempt counters and replay guards depend on it.
//
// Values are copied on the way in and out, so callers can't change stored data by accident.
export class MemoryStore {
  #entries = new Map();

  constructor({ clock = Date.now } = {}) {
    this.clock = clock;
  }

  #live(key) {
    const entry = this.#entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt !== null && entry.expiresAt <= this.clock()) {
      this.#entries.delete(key);
      return undefined;
    }
    return entry;
  }

  async get(key) {
    const entry = this.#live(key);
    return entry ? structuredClone(entry.value) : undefined;
  }

  async set(key, value, ttlMs = null) {
    this.#entries.set(key, {
      value: structuredClone(value),
      expiresAt: ttlMs ? this.clock() + ttlMs : null,
    });
    this._changed?.();
  }

  async del(key) {
    this.#entries.delete(key);
    this._changed?.();
  }

  async update(key, fn, ttlMs = null) {
    const entry = this.#live(key);
    const next = fn(entry ? structuredClone(entry.value) : undefined);

    if (next === undefined) return entry ? structuredClone(entry.value) : undefined;
    if (next === null) {
      this.#entries.delete(key);
      this._changed?.();
      return null;
    }

    const expiresAt = entry ? entry.expiresAt : (ttlMs ? this.clock() + ttlMs : null);
    this.#entries.set(key, { value: structuredClone(next), expiresAt });
    this._changed?.();
    return structuredClone(next);
  }

  // used by FileStore to save and load
  _dump() {
    return [...this.#entries.entries()];
  }

  _load(entries) {
    this.#entries = new Map(entries);
  }
}
