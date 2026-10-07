import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MemoryStore,
  FileStore,
  SlidingWindowLimiter,
  LockoutPolicy,
  AuditLog,
  assessRisk,
  maskDestination,
} from '../src/index.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

test('sliding window limiter', async () => {
  const c = { t: 0 };
  const clock = () => c.t;
  const l = new SlidingWindowLimiter({ store: new MemoryStore({ clock }), limit: 3, windowMs: 1000, clock });
  for (let i = 0; i < 3; i++) assert.equal((await l.hit('a')).allowed, true);
  const blocked = await l.hit('a');
  assert.equal(blocked.allowed, false);
  assert.ok(blocked.retryAfterMs > 0);
  assert.equal((await l.hit('b')).allowed, true);
  c.t = 1001;
  assert.equal((await l.hit('a')).allowed, true);
});
test('progressive lockout doubles', async () => {
  const c = { t: 0 };
  const clock = () => c.t;
  const p = new LockoutPolicy({ store: new MemoryStore({ clock }), maxFailures: 3, baseMs: 1000, clock });
  for (let i = 0; i < 2; i++) await p.recordFailure('u');
  assert.equal((await p.status('u')).locked, false);
  await p.recordFailure('u');
  assert.equal((await p.status('u')).retryAfterMs, 1000);
  c.t = 1001;
  await p.recordFailure('u');
  assert.equal((await p.status('u')).retryAfterMs, 2000);
  await p.reset('u');
  assert.equal((await p.status('u')).locked, false);
});
test('audit log chain detects tampering and redacts secrets', () => {
  const a = new AuditLog();
  a.append('one', { userId: 'u', code: '123456', secret: 'x' });
  a.append('two');
  a.append('three');
  assert.equal(a.entries[0].data.code, '[REDACTED]');
  assert.equal(AuditLog.verify(a.entries).ok, true);
  const copy = structuredClone(a.entries);
  copy[1].event = 'evil';
  assert.deepEqual(AuditLog.verify(copy), { ok: false, brokenAt: 1 });
  assert.equal(AuditLog.verify(a.entries.slice(1)).ok, false);
});
test('risk engine levels', () => {
  assert.equal(assessRisk({}).level, 'low');
  assert.equal(assessRisk({ newDevice: true, highValue: true }).level, 'medium');
  assert.equal(assessRisk({ newDevice: true, impossibleTravel: true, recentFailures: 3 }).level, 'high');
});
test('mask destination', () => {
  assert.equal(maskDestination('alice@example.com'), 'a***@example.com');
  assert.equal(maskDestination('+919876543210'), '+91********10');
});
test('file store persists and honours TTL', async () => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'otpf-')), 's.json');
  const c = { t: 0 };
  const clock = () => c.t;
  const s1 = new FileStore(f, { clock });
  await s1.set('k', { a: 1 }, 1000);
  await s1.set('perm', 'v');
  const s2 = new FileStore(f, { clock });
  assert.deepEqual(await s2.get('k'), { a: 1 });
  c.t = 1500;
  assert.equal(await s2.get('k'), undefined);
  assert.equal(await s2.get('perm'), 'v');
  assert.equal(fs.statSync(f).mode & 0o777, 0o600);
});
