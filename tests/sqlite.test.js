import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';

let SqliteStore = null;
try { ({ SqliteStore } = await import('../src/storage/sqlite-store.js')); } catch { /* Node < 22.5 */ }
const t = SqliteStore ? test : test.skip;

t('sqlite store: CRUD, TTL, atomic update, persistence', async () => {
  const c = { t: 0 }; const clock = () => c.t;
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'otpf-sql-')), 'kv.db');
  const s = new SqliteStore(file, { clock });
  await s.set('a', { n: 1 }, 1000); assert.deepEqual(await s.get('a'), { n: 1 });
  c.t = 1500; assert.equal(await s.get('a'), undefined);
  await s.set('cnt', { n: 0 });
  await Promise.all(Array.from({ length: 100 }, () => s.update('cnt', (v) => ({ n: v.n + 1 }))));
  assert.equal((await s.get('cnt')).n, 100);
  assert.equal(await s.update('nope', () => undefined), undefined);
  assert.equal(await s.update('cnt', () => null), null); assert.equal(await s.get('cnt'), undefined);
  await assert.rejects(s.update('x', () => { throw new Error('boom'); }), /boom/);
  await s.set('x', 1); // still usable after rollback
  await s.set('t', 1, 10); c.t += 100; assert.equal(s.sweep(), 1);
  s.close();
  const s2 = new SqliteStore(file, { clock }); assert.equal(await s2.get('x'), 1); s2.close();
});

t('sqlite store works as the backing store for the whole service', async () => {
  const { OtpService, MemoryProvider, randomBytes } = await import('../src/index.js');
  const provider = new MemoryProvider();
  const svc = new OtpService({ store: new SqliteStore(':memory:'), masterKey: randomBytes(32), pepper: 'z'.repeat(40), provider });
  await svc.sendOtp({ userId: 'u', channel: 'email', to: 'a@b.com' });
  const code = provider.last().message.text.match(/\b(\d{6})\b/)[1];
  assert.equal((await svc.verifyOtp({ userId: 'u', code })).ok, true);
  const codes = await svc.generateBackupCodes('u'); assert.equal((await svc.useBackupCode({ userId: 'u', code: codes[0] })).ok, true);
});
