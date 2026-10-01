// SQLite store using Node's built-in node:sqlite (Node >= 22.5). Durable, transactional, no deps.
// `update` runs inside BEGIN IMMEDIATE so it is atomic even with several processes on one DB file.
import { DatabaseSync } from 'node:sqlite';

export class SqliteStore {
  constructor(file = ':memory:', { clock = Date.now } = {}) {
    this.clock = clock;
    this.db = new DatabaseSync(file);
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;');
    this.db.exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, exp INTEGER)');
    this.q = {
      get: this.db.prepare('SELECT v, exp FROM kv WHERE k = ?'),
      put: this.db.prepare('INSERT INTO kv (k, v, exp) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, exp = excluded.exp'),
      del: this.db.prepare('DELETE FROM kv WHERE k = ?'),
      sweep: this.db.prepare('DELETE FROM kv WHERE exp IS NOT NULL AND exp <= ?'),
    };
  }
  #row(k) {
    const r = this.q.get.get(k);
    if (!r) return undefined;
    if (r.exp !== null && r.exp <= this.clock()) { this.q.del.run(k); return undefined; }
    return r;
  }
  async get(k) { const r = this.#row(k); return r ? JSON.parse(r.v) : undefined; }
  async set(k, v, ttlMs = null) { this.q.put.run(k, JSON.stringify(v), ttlMs ? this.clock() + ttlMs : null); }
  async del(k) { this.q.del.run(k); }
  async update(k, fn, ttlMs = null) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const r = this.#row(k);
      const next = fn(r ? JSON.parse(r.v) : undefined);
      let out;
      if (next === undefined) out = r ? JSON.parse(r.v) : undefined;
      else if (next === null) { this.q.del.run(k); out = null; }
      else { this.q.put.run(k, JSON.stringify(next), r ? r.exp : (ttlMs ? this.clock() + ttlMs : null)); out = next; }
      this.db.exec('COMMIT');
      return out;
    } catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  /** Delete expired rows (run from a timer). */
  sweep() { return this.q.sweep.run(this.clock()).changes; }
  close() { this.db.close(); }
}
