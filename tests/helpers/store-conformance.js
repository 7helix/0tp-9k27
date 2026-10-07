// Run this against ANY store implementation:
//   storeConformance('MyStore', async () => ({ store, advance: (ms) => ..., ttl: 1000, cleanup: async () => {} }));
// `advance` must move the store's notion of time forward (fake clock) or really wait (real-time backends).
import test from 'node:test';
import assert from 'node:assert/strict';

export function storeConformance(name, factory, { skip = false } = {}) {
  const t = (title, fn) => test(`[${name}] ${title}`, { skip }, async () => {
    const ctx = await factory();
    const pre = `${Math.random().toString(36).slice(2)}:`;
    try { await fn({ ...ctx, k: (s) => pre + s, T: ctx.ttl ?? 1000 }); } finally { await ctx.cleanup?.(); }
  });

  t('set/get/del roundtrip of JSON values', async ({ store, k }) => {
    const v = { s: 'héllo 😀 \u0000', n: -1.5, b: true, arr: [1, [2, { x: null }]], o: { deep: { er: 'x' } }, big: 'x'.repeat(100_000) };
    assert.equal(await store.get(k('a')), undefined);
    await store.set(k('a'), v);
    assert.deepEqual(await store.get(k('a')), v);
    await store.set(k('a'), 7);
    assert.equal(await store.get(k('a')), 7, 'overwrite');
    await store.del(k('a'));
    assert.equal(await store.get(k('a')), undefined);
    await store.del(k('never-existed')); // deleting nothing is fine
  });
  t('hostile keys are plain data (unicode, quotes, SQL, long)', async ({ store, k }) => {
    for (const key of ["x'; DROP TABLE otpf_kv;--", 'a b\tc\n', '日本語', '%_\\', 'k'.repeat(500), '__proto__', 'constructor']) {
      await store.set(k(key), { key });
      assert.deepEqual(await store.get(k(key)), { key });
    }
    await store.set(k('still-works'), 1);
    assert.equal(await store.get(k('still-works')), 1);
  });
  t('values are copied: no aliasing in or out, and mutating the update callback argument changes nothing', async ({ store, k }) => {
    const src = { n: 1, list: [1] };
    await store.set(k('c'), src);
    src.n = 99;
    src.list.push(2);
    assert.deepEqual(await store.get(k('c')), { n: 1, list: [1] });
    const got = await store.get(k('c'));
    got.n = 42;
    got.list.length = 0;
    assert.deepEqual(await store.get(k('c')), { n: 1, list: [1] });
    await store.update(k('c'), (cur) => { cur.n = 1000; return undefined; });
    assert.equal((await store.get(k('c'))).n, 1);
    const out = await store.update(k('c'), (cur) => ({ ...cur, n: 2 }));
    out.n = 555;
    assert.equal((await store.get(k('c'))).n, 2);
  });
  t('TTL: expires, and absent keys read as undefined', async ({ store, k, advance, T }) => {
    await store.set(k('t'), 'v', T);
    await advance(T * 0.4);
    assert.equal(await store.get(k('t')), 'v');
    await advance(T * 0.8);
    assert.equal(await store.get(k('t')), undefined);
    await store.set(k('perm'), 'p');
    await advance(T * 5);
    assert.equal(await store.get(k('perm')), 'p', 'no TTL = no expiry');
  });
  t('re-setting a key replaces its TTL', async ({ store, k, advance, T }) => {
    await store.set(k('r'), 1, T * 0.5);
    await store.set(k('r'), 2, T * 5);
    await advance(T);
    assert.equal(await store.get(k('r')), 2);
    await store.set(k('r2'), 1, T * 0.5);
    await store.set(k('r2'), 2); // overwrite without ttl = permanent
    await advance(T);
    assert.equal(await store.get(k('r2')), 2);
  });
  t('update semantics: create-if-absent, undefined = no change, null = delete, returns the new value', async ({ store, k }) => {
    assert.equal(
      await store.update(k('u'), (cur) => { assert.equal(cur, undefined); return undefined; }),
      undefined,
    );
    assert.equal(await store.get(k('u')), undefined, 'no-change on a missing key must not create it');
    assert.deepEqual(await store.update(k('u'), () => ({ n: 1 })), { n: 1 });
    assert.deepEqual(await store.update(k('u'), (c) => ({ n: c.n + 1 })), { n: 2 });
    assert.deepEqual(await store.update(k('u'), () => undefined), { n: 2 });
    assert.equal(await store.update(k('u'), () => null), null);
    assert.equal(await store.get(k('u')), undefined);
    assert.equal(await store.update(k('u'), () => null), null, 'deleting a missing key is fine');
  });
  t('update keeps the EXISTING ttl (does not extend it) and applies ttl on create', async ({ store, k, advance, T }) => {
    await store.set(k('e'), { n: 0 }, T);
    await advance(T * 0.6);
    await store.update(k('e'), (c) => ({ n: c.n + 1 }), T * 10);
    await advance(T * 0.6);
    assert.equal(await store.get(k('e')), undefined, 'update must not extend an existing TTL');
    await store.update(k('f'), () => ({ n: 1 }), T);
    assert.deepEqual(await store.get(k('f')), { n: 1 });
    await advance(T * 1.2);
    assert.equal(await store.get(k('f')), undefined, 'ttl passed at creation applies');
    await store.update(k('g'), () => 'perm');
    await advance(T * 5);
    assert.equal(await store.get(k('g')), 'perm');
  });
  t('update on an EXPIRED key behaves like a missing key', async ({ store, k, advance, T }) => {
    await store.set(k('x'), { n: 5 }, T);
    await advance(T * 1.5);
    assert.deepEqual(
      await store.update(k('x'), (c) => { assert.equal(c, undefined); return { n: 1 }; }),
      { n: 1 },
    );
  });
  t('a throwing callback rolls back, rethrows, and leaves the store usable', async ({ store, k }) => {
    await store.set(k('boom'), { n: 1 });
    await assert.rejects(store.update(k('boom'), () => { throw new Error('boom'); }), /boom/);
    assert.deepEqual(await store.get(k('boom')), { n: 1 });
    assert.deepEqual(await store.update(k('boom'), (c) => ({ n: c.n + 1 })), { n: 2 });
    await assert.rejects(store.update(k('boom2'), () => { throw new Error('on-missing'); }), /on-missing/);
    assert.equal(await store.get(k('boom2')), undefined);
  });
  t('ATOMICITY: 150 concurrent increments lose nothing', async ({ store, k }) => {
    await store.set(k('ctr'), { n: 0 });
    await Promise.all(Array.from({ length: 150 }, () => store.update(k('ctr'), (c) => ({ n: c.n + 1 }))));
    assert.equal((await store.get(k('ctr'))).n, 150);
  });
  t('ATOMICITY: concurrent create-if-absent has exactly one winner (the row-does-not-exist-yet race)', async ({ store, k }) => {
    const wins = await Promise.all(Array.from({ length: 60 }, (_, i) => { let won = false; return store.update(k('claim'), (c) => { if (c) return undefined; won = true; return { by: i }; }).then(() => won); }));
    assert.equal(wins.filter(Boolean).length, 1);
  });
  t('ATOMICITY: concurrent set/del/update on one key never corrupt it', async ({ store, k }) => {
    await Promise.all(Array.from({ length: 90 }, (_, i) => (i % 3 === 0 ? store.set(k('mix'), { n: 1000 }) : i % 3 === 1 ? store.update(k('mix'), (c) => ({ n: (c?.n ?? 0) + 1 })) : store.del(k('mix')))));
    const v = await store.get(k('mix'));
    assert.ok(v === undefined || Number.isInteger(v.n));
  });
  t('different keys do not interfere (parallel updates on 40 keys)', async ({ store, k }) => {
    await Promise.all(Array.from({ length: 40 }, (_, i) => Promise.all(Array.from({ length: 5 }, () => store.update(k(`p${i}`), (c) => ({ n: (c?.n ?? 0) + 1 }))))));
    for (let i = 0; i < 40; i++) assert.equal((await store.get(k(`p${i}`))).n, 5);
  });
}
