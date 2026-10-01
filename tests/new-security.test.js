import test from 'node:test';
import assert from 'node:assert/strict';
import { KeyRing, randomBytes, isUserId, isE164, isEmail, isOtpCode, validateDestination, ValidationError, Idempotency, MemoryStore, AnomalyDetector, CaptchaGate, SiteverifyCaptcha } from '../src/index.js';

test('key ring: encrypt, rotate, old keys still decrypt, wrong AAD fails', () => {
  const k1 = randomBytes(32), k2 = randomBytes(32);
  const old = new KeyRing({ keys: { 1: k1 }, current: 1 });
  const ct1 = old.encrypt(Buffer.from('seed'), 'u1');
  const ring = new KeyRing({ keys: { 1: k1, 2: k2 }, current: 2 });
  assert.equal(ring.needsRotation(ct1), true);
  assert.equal(ring.decrypt(ct1, 'u1').toString(), 'seed');
  const ct2 = ring.rotate(ct1, 'u1');
  assert.ok(ct2.startsWith('k2:')); assert.equal(ring.rotate(ct2, 'u1'), ct2);
  assert.throws(() => ring.decrypt(ct2, 'u2'));
  assert.throws(() => new KeyRing({ keys: { 1: k1 }, current: 2 }));
  assert.throws(() => new KeyRing({ keys: { 1: randomBytes(16) }, current: 1 }));
  assert.throws(() => old.decrypt(ct2, 'u1'), /unknown key id/); // retired-key safety
});

test('input validation', () => {
  assert.ok(isUserId('user_42@x')); assert.ok(!isUserId('a b')); assert.ok(!isUserId('x'.repeat(129))); assert.ok(!isUserId('../etc'));
  assert.ok(isE164('+919876543210')); assert.ok(!isE164('9876543210')); assert.ok(!isE164('+0123456789'));
  assert.ok(isEmail('a.b+c@example.co')); assert.ok(!isEmail('a@b')); assert.ok(!isEmail('a b@c.com')); assert.ok(!isEmail('<x>@y.com'));
  assert.ok(isOtpCode('123 456')); assert.ok(!isOtpCode('12')); assert.ok(!isOtpCode('1'.repeat(40)));
  assert.equal(validateDestination('sms', '+14155550123'), '+14155550123');
  assert.throws(() => validateDestination('fax', 'x'), ValidationError);
  assert.throws(() => validateDestination('email', 'nope'), (e) => e.status === 400 && e.field === 'to');
});

test('idempotency: one execution, replays cached, failures can retry, concurrent = in_progress', async () => {
  const idem = new Idempotency({ store: new MemoryStore() }); let runs = 0;
  const fn = async () => { runs++; await new Promise((r) => setTimeout(r, 10)); return { ok: true, n: runs }; };
  const [a, b] = await Promise.all([idem.once('k', fn), idem.once('k', fn)]);
  assert.equal(runs, 1);
  assert.ok([a, b].some((r) => r.reason === 'in_progress'));
  assert.deepEqual(await idem.once('k', fn), { ok: true, n: 1, replayed: true });
  await assert.rejects(idem.once('bad', async () => { throw new Error('boom'); }));
  assert.equal((await idem.once('bad', async () => ({ ok: true }))).ok, true);
});

test('anomaly detector: one IP failing across many accounts', async () => {
  const c = { t: 0 }; const clock = () => c.t;
  const a = new AnomalyDetector({ store: new MemoryStore({ clock }), distinctUsers: 3, windowMs: 1000, clock });
  for (const u of ['a', 'a', 'a', 'a']) await a.recordFailure({ ip: '1.1.1.1', userId: u });
  assert.equal(await a.isSuspicious('1.1.1.1'), false, 'same user repeatedly is lockout territory, not stuffing');
  await a.recordFailure({ ip: '1.1.1.1', userId: 'b' }); await a.recordFailure({ ip: '1.1.1.1', userId: 'c' });
  assert.equal(await a.isSuspicious('1.1.1.1'), true);
  c.t = 5000; assert.equal(await a.isSuspicious('1.1.1.1'), false);
});

test('captcha gate: free quota then captcha required', async () => {
  const seen = [];
  const fakeFetch = async (url, init) => { seen.push([url, init.body.get('response')]); return { ok: true, json: async () => ({ success: init.body.get('response') === 'good' }) }; };
  const gate = new CaptchaGate({ store: new MemoryStore(), verifier: new SiteverifyCaptcha({ url: 'https://captcha.test/verify', secret: 's', fetchImpl: fakeFetch }), freeRequests: 2 });
  assert.deepEqual(await gate.check({ key: 'k' }), { allowed: true, captchaRequired: false });
  await gate.check({ key: 'k' });
  assert.deepEqual(await gate.check({ key: 'k', captchaToken: 'bad' }), { allowed: false, captchaRequired: true });
  assert.deepEqual(await gate.check({ key: 'k', captchaToken: 'good' }), { allowed: true, captchaRequired: true });
  assert.deepEqual(await gate.check({ key: 'k' }), { allowed: false, captchaRequired: true }); // no token, no fetch
  assert.equal(seen.length, 2);
});
