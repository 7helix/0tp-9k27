// SQLite store on top of Node's built-in node:sqlite (Node 22.5 or newer). Durable, no dependencies.
// update() runs inside BEGIN IMMEDIATE, so it stays atomic even with several processes on one file.
import { DatabaseSync } from 'node:sqlite';

export class SqliteStore {
  constructor(file = ':memory:', { clock = Date.now } = {}) {
    this.clock = clock;
    this.db = new DatabaseSync(file);
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;');
    this.db.exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, exp INTEGER)');

    this.queries = {
      get: this.db.prepare('SELECT v, exp FROM kv WHERE k = ?'),
      put: this.db.prepare(
        'INSERT INTO kv (k, v, exp) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, exp = excluded.exp',
      ),
      del: this.db.prepare('DELETE FROM kv WHERE k = ?'),
      sweep: this.db.prepare('DELETE FROM kv WHERE exp IS NOT NULL AND exp <= ?'),
    };
  }

  #row(key) {
    const row = this.queries.get.get(key);
    if (!row) return undefined;
    if (row.exp !== null && row.exp <= this.clock()) {
      this.queries.del.run(key);
      return undefined;
    }
    return row;
  }

  async get(key) {
    const row = this.#row(key);
    return row ? JSON.parse(row.v) : undefined;
  }

  async set(key, value, ttlMs = null) {
    this.queries.put.run(key, JSON.stringify(value), ttlMs ? this.clock() + ttlMs : null);
  }

  async del(key) {
    this.queries.del.run(key);
  }

  async update(key, fn, ttlMs = null) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#row(key);
      const current = row ? JSON.parse(row.v) : undefined;
      const next = fn(current);

      let result;
      if (next === undefined) {
        result = current;
      } else if (next === null) {
        this.queries.del.run(key);
        result = null;
      } else {
        const exp = row ? row.exp : (ttlMs ? this.clock() + ttlMs : null);
        this.queries.put.run(key, JSON.stringify(next), exp);
        result = next;
      }

      this.db.exec('COMMIT');
      return result;
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  // Removes expired rows. Call it from a timer.
  sweep() {
    return this.queries.sweep.run(this.clock()).changes;
  }

  close() {
    this.db.close();
  }
}
