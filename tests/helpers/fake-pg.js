// A small in-memory stand-in for a `pg` Pool. It understands exactly the statements PostgresStore
// sends and imitates pg_advisory_xact_lock (held until COMMIT or ROLLBACK).
//
// This tests our logic, not Postgres' SQL engine. The real engine is exercised by the CI job that
// runs the conformance suite against a live database.

const STATEMENTS = {
  select: /^SELECT v, exp FROM \w+ WHERE k = \$1$/,
  deleteExpiredKey: /^DELETE FROM \w+ WHERE k = \$1 AND exp <= \$2$/,
  deleteKey: /^DELETE FROM \w+ WHERE k = \$1$/,
  upsert: /^INSERT INTO \w+ \(k, v, exp\) VALUES \(\$1, \$2::jsonb, \$3\) ON CONFLICT \(k\) DO UPDATE SET v = EXCLUDED\.v, exp = EXCLUDED\.exp$/,
  sweep: /^DELETE FROM \w+ WHERE exp IS NOT NULL AND exp <= \$1$/,
  advisoryLock: /^SELECT pg_advisory_xact_lock/,
};

export class FakePool {
  constructor() {
    this.rows = new Map();
    this.locks = new Map(); // key -> promise that resolves when the current holder lets go
    this.log = []; // every [sql, params] seen, for assertions
    this.opened = 0;
    this.released = 0;
  }

  // Waits for whoever holds the lock for `key`, then returns the function that releases ours.
  async #acquire(key) {
    const previous = this.locks.get(key) || Promise.resolve();
    let release;
    const mine = new Promise((resolve) => { release = resolve; });
    this.locks.set(key, previous.then(() => mine));
    await previous;
    return release;
  }

  async query(text, params = []) {
    return this.#run(text, params, null);
  }

  async connect() {
    this.opened++;
    const held = { release: null };
    return {
      query: (text, params = []) => this.#run(text, params, held),
      release: () => { this.released++; },
    };
  }

  async #run(text, params, held) {
    const sql = text.replace(/\s+/g, ' ').trim();
    this.log.push([sql, params]);

    if (/^CREATE /.test(sql) || sql === 'BEGIN') return { rows: [] };

    if (sql === 'COMMIT' || sql === 'ROLLBACK') {
      if (held?.release) {
        held.release();
        held.release = null;
      }
      return { rows: [] };
    }

    if (STATEMENTS.advisoryLock.test(sql)) {
      held.release = await this.#acquire(params[0]);
      return { rows: [] };
    }

    if (STATEMENTS.select.test(sql)) {
      const row = this.rows.get(params[0]);
      if (!row) return { rows: [] };
      // pg returns bigint columns as strings
      return { rows: [{ v: structuredClone(row.v), exp: row.exp === null ? null : String(row.exp) }] };
    }

    if (STATEMENTS.deleteExpiredKey.test(sql)) {
      const row = this.rows.get(params[0]);
      if (row && row.exp !== null && row.exp <= params[1]) this.rows.delete(params[0]);
      return { rows: [] };
    }

    if (STATEMENTS.deleteKey.test(sql)) {
      this.rows.delete(params[0]);
      return { rows: [] };
    }

    if (STATEMENTS.upsert.test(sql)) {
      this.rows.set(params[0], { v: JSON.parse(params[1]), exp: params[2] });
      return { rows: [] };
    }

    if (STATEMENTS.sweep.test(sql)) {
      let removed = 0;
      for (const [key, row] of this.rows) {
        if (row.exp !== null && row.exp <= params[0]) {
          this.rows.delete(key);
          removed++;
        }
      }
      return { rows: [], rowCount: removed };
    }

    throw new Error(`FakePool: unsupported statement: ${sql}`);
  }
}
