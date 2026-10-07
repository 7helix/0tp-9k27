// PostgreSQL store, for running several app servers against one database (PostgreSQL 11 or newer).
// It takes any pg-compatible pool, so this repo doesn't depend on a driver:
//
//   import pg from 'pg';
//   const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
//   const store = new PostgresStore({ pool });
//   await store.init();
//
// How it stays atomic: every write runs in a transaction that first takes an advisory lock derived
// from the key. SELECT ... FOR UPDATE can't lock a row that doesn't exist yet, which is exactly the
// case where two requests both try to create a counter. The advisory lock covers that too, and
// different keys never wait for each other.
//
// Locally this is tested against a fake driver. The real SQL runs in CI (see stores.yml), and you
// should run `npm run test:stores` against your own database as well.
export class PostgresStore {
  constructor({ pool, table = 'otpf_kv', clock = Date.now }) {
    // table names can't be bound as parameters, so check it strictly
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(table)) throw new Error('invalid table name');
    this.pool = pool;
    this.table = table;
    this.clock = clock;
  }

  async init() {
    await this.pool.query(
      `CREATE TABLE IF NOT EXISTS ${this.table} (k text PRIMARY KEY, v jsonb NOT NULL, exp bigint)`,
    );
    await this.pool.query(
      `CREATE INDEX IF NOT EXISTS ${this.table}_exp_idx ON ${this.table} (exp) WHERE exp IS NOT NULL`,
    );
  }

  #isLive(row) {
    return Boolean(row) && (row.exp === null || Number(row.exp) > this.clock());
  }

  async get(key) {
    const { rows } = await this.pool.query(`SELECT v, exp FROM ${this.table} WHERE k = $1`, [key]);
    const row = rows[0];
    if (this.#isLive(row)) return row.v;

    if (row) {
      // clean up lazily. The exp check stops us deleting a row someone just replaced.
      await this.pool.query(`DELETE FROM ${this.table} WHERE k = $1 AND exp <= $2`, [key, this.clock()]);
    }
    return undefined;
  }

  async #inTransaction(key, work) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [key]);
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // the connection may already be gone
      }
      throw err;
    } finally {
      client.release();
    }
  }

  #write(client, key, value, exp) {
    return client.query(
      `INSERT INTO ${this.table} (k, v, exp) VALUES ($1, $2::jsonb, $3) `
      + 'ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, exp = EXCLUDED.exp',
      [key, JSON.stringify(value), exp],
    );
  }

  async set(key, value, ttlMs = null) {
    await this.#inTransaction(key, (client) => this.#write(client, key, value, ttlMs ? this.clock() + ttlMs : null));
  }

  async del(key) {
    await this.#inTransaction(key, (client) => client.query(`DELETE FROM ${this.table} WHERE k = $1`, [key]));
  }

  async update(key, fn, ttlMs = null) {
    return this.#inTransaction(key, async (client) => {
      const { rows } = await client.query(`SELECT v, exp FROM ${this.table} WHERE k = $1`, [key]);
      const row = this.#isLive(rows[0]) ? rows[0] : undefined;

      const next = fn(row ? row.v : undefined);
      if (next === undefined) return row ? row.v : undefined;
      if (next === null) {
        await client.query(`DELETE FROM ${this.table} WHERE k = $1`, [key]);
        return null;
      }

      // an existing key keeps its expiry, a new one gets the ttl we were given
      let exp = ttlMs ? this.clock() + ttlMs : null;
      if (row) exp = row.exp === null ? null : Number(row.exp);

      await this.#write(client, key, next, exp);
      return next;
    });
  }

  // Deletes expired rows. Call it from a timer.
  async sweep() {
    const result = await this.pool.query(
      `DELETE FROM ${this.table} WHERE exp IS NOT NULL AND exp <= $1`,
      [this.clock()],
    );
    return result.rowCount;
  }
}
