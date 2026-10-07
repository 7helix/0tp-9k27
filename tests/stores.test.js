// One behavioural contract, run against every store. The real Postgres and Redis suites only run when
// PG_URL / REDIS_URL are set (CI does that). To try them locally:
//   docker compose -f deploy/docker-compose.test-stores.yml up -d
//   npm install --no-save pg ioredis
//   PG_URL=... REDIS_URL=... npm run test:stores
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MemoryStore, FileStore, RedisStore, PostgresStore } from '../src/index.js';
import { storeConformance } from './helpers/store-conformance.js';
import { FakePool } from './helpers/fake-pg.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// a clock we can move forward by hand
function fakeClock() {
  let now = 1_000_000;
  return {
    now: () => now,
    advance: async (ms) => { now += ms; },
  };
}

storeConformance('MemoryStore', async () => {
  const clock = fakeClock();
  return { store: new MemoryStore({ clock: clock.now }), advance: clock.advance };
});

storeConformance('FileStore', async () => {
  const clock = fakeClock();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'conformance-'));
  return {
    store: new FileStore(path.join(dir, 'store.json'), { clock: clock.now }),
    advance: clock.advance,
    cleanup: async () => fs.rmSync(dir, { recursive: true, force: true }),
  };
});

let SqliteStore = null;
try {
  ({ SqliteStore } = await import('../src/storage/sqlite-store.js'));
} catch {
  // node:sqlite needs Node 22.5 or newer
}
storeConformance('SqliteStore', async () => {
  const clock = fakeClock();
  const store = new SqliteStore(':memory:', { clock: clock.now });
  return { store, advance: clock.advance, cleanup: async () => store.close() };
}, { skip: !SqliteStore });

storeConformance('PostgresStore (fake driver, logic only)', async () => {
  const clock = fakeClock();
  const pool = new FakePool();
  const store = new PostgresStore({ pool, clock: clock.now });
  await store.init();
  return {
    store,
    advance: clock.advance,
    cleanup: async () => assert.equal(pool.opened, pool.released, 'every connection must be released'),
  };
});

// ---- real servers, used in CI ----

let pgPool = null;
if (process.env.PG_URL) {
  try {
    const pg = (await import('pg')).default;
    pgPool = new pg.Pool({ connectionString: process.env.PG_URL });
  } catch (err) {
    console.warn(`PG_URL is set but the 'pg' driver is not installed: ${err.message}`);
  }
}

storeConformance('PostgresStore (real Postgres)', async () => {
  const table = `otpf_test_${Math.random().toString(36).slice(2, 10)}`;
  const store = new PostgresStore({ pool: pgPool, table });
  await store.init();
  return {
    store,
    ttl: 400,
    advance: sleep, // real time, since the TTL is checked against the real clock
    cleanup: async () => { await pgPool.query(`DROP TABLE IF EXISTS ${table}`); },
  };
}, { skip: !pgPool });

let redis = null;
if (process.env.REDIS_URL) {
  try {
    const Redis = (await import('ioredis')).default;
    redis = new Redis(process.env.REDIS_URL);
  } catch (err) {
    console.warn(`REDIS_URL is set but the 'ioredis' driver is not installed: ${err.message}`);
  }
}

storeConformance('RedisStore (real Redis)', async () => ({
  store: new RedisStore(redis, { prefix: `otpf-test-${Math.random().toString(36).slice(2)}:` }),
  ttl: 400,
  advance: sleep,
}), { skip: !redis });

test.after(async () => {
  await pgPool?.end();
  redis?.disconnect();
});

// ---- PostgresStore specifics ----

test('PostgresStore is injection-safe by construction', async () => {
  assert.throws(() => new PostgresStore({ pool: {}, table: 'x; DROP TABLE users' }), /invalid table/);
  assert.throws(() => new PostgresStore({ pool: {}, table: '1abc' }), /invalid table/);

  const pool = new FakePool();
  const store = new PostgresStore({ pool, table: 'otpf_kv' });
  await store.init();

  const evil = "k'); DELETE FROM otpf_kv;--";
  await store.set(evil, { a: 1 });
  await store.get(evil);
  await store.update(evil, (current) => current);
  await store.del(evil);

  for (const [sql] of pool.log) {
    assert.ok(!sql.includes(evil), `the key ended up in the SQL text: ${sql}`);
  }
  const lockedByKey = pool.log.some(([sql, params]) => /pg_advisory_xact_lock/.test(sql) && params[0] === evil);
  assert.ok(lockedByKey, 'the lock is taken per key, with the key passed as a parameter');
});

test('PostgresStore runs BEGIN, advisory lock, work, COMMIT, and rolls back and releases on error', async () => {
  const pool = new FakePool();
  const store = new PostgresStore({ pool });
  await store.init();
  pool.log.length = 0;

  await store.update('k', () => ({ n: 1 }));
  const steps = pool.log.map(([sql]) => sql.split(' ').slice(0, 2).join(' '));
  assert.deepEqual(
    steps,
    ['BEGIN', 'SELECT pg_advisory_xact_lock(hashtextextended($1,', 'SELECT v,', 'INSERT INTO', 'COMMIT'],
  );

  pool.log.length = 0;
  await assert.rejects(store.update('k', () => { throw new Error('x'); }), /x/);
  assert.equal(pool.log.at(-1)[0], 'ROLLBACK');
  assert.equal(pool.opened, pool.released);
});

test('PostgresStore.sweep removes only expired rows', async () => {
  const clock = fakeClock();
  const pool = new FakePool();
  const store = new PostgresStore({ pool, clock: clock.now });
  await store.init();

  await store.set('a', 1, 100);
  await store.set('b', 2, 100_000);
  await store.set('c', 3);
  await clock.advance(500);

  assert.equal(await store.sweep(), 1);
  assert.equal(await store.get('b'), 2);
  assert.equal(await store.get('c'), 3);
});
