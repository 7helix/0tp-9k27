import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryStore, HotpDevices, hotp, QrLogin, DeviceTrust, RecoveryRequest, StepUp, randomBytes } from '../src/index.js';

const clocked = () => { const c = { t: 1_700_000_000_000, now: () => c.t }; return c; };

test('HOTP devices: verify, no reuse, resync after button-mashing', async () => {
  const key = randomBytes(32); const secret = randomBytes(20);
  const d = new HotpDevices({ store: new MemoryStore(), key });
  await d.register('tok1', secret);
  assert.equal((await d.verify('tok1', hotp(secret, 0))).ok, true);
  assert.equal((await d.verify('tok1', hotp(secret, 0))).ok, false);
  assert.equal((await d.verify('nope', '123456')).reason, 'unknown_device');
  // user pressed the button 40 times: out of look-ahead range
  assert.equal((await d.verify('tok1', hotp(secret, 41))).ok, false);
  assert.deepEqual(await d.resync('tok1', hotp(secret, 40), hotp(secret, 41)), { ok: true, counter: 42 });
  assert.equal((await d.verify('tok1', hotp(secret, 42))).ok, true);
  assert.equal((await d.resync('tok1', '000000', '111111')).reason, 'no_match');
});

test('QR login: only the approving user, correct nonce, single claim, poll token secret', async () => {
  const c = clocked(); const q = new QrLogin({ store: new MemoryStore({ clock: c.now }), clock: c.now });
  const s = await q.create({ meta: { device: 'Chrome on Windows' } });
  assert.ok(!s.qrPayload.includes(s.pollToken));
  assert.equal((await q.claim({ sessionId: s.sessionId, pollToken: s.pollToken })).status, 'pending');
  assert.equal((await q.claim({ sessionId: s.sessionId, pollToken: 'attacker' })).status, 'forbidden');
  const nonce = new URL(s.qrPayload.replace('otpf://', 'https://')).searchParams.get('n');
  assert.equal((await q.approve({ sessionId: s.sessionId, nonce: 'wrong', userId: 'u1' })).reason, 'bad_nonce');
  assert.equal((await q.approve({ sessionId: s.sessionId, nonce, userId: 'u1' })).ok, true);
  assert.equal((await q.approve({ sessionId: s.sessionId, nonce, userId: 'evil' })).ok, false);
  assert.deepEqual(await q.claim({ sessionId: s.sessionId, pollToken: s.pollToken }), { ok: true, userId: 'u1' });
  assert.equal((await q.claim({ sessionId: s.sessionId, pollToken: s.pollToken })).ok, false);
  const s2 = await q.create({ ttlMs: 1000 }); c.t += 2000;
  assert.equal((await q.claim({ sessionId: s2.sessionId, pollToken: s2.pollToken })).status, 'expired');
});

test('device trust: bound to user, expires, revocable', async () => {
  const c = clocked(); const dt = new DeviceTrust({ store: new MemoryStore({ clock: c.now }), key: randomBytes(32), clock: c.now });
  const { id, token } = await dt.issue('u1', { label: 'Pixel 8' });
  assert.equal((await dt.check('u1', token)).trusted, true);
  assert.equal((await dt.check('u2', token)).trusted, false);
  assert.equal((await dt.list('u1'))[0].label, 'Pixel 8');
  await dt.revoke('u1', id); assert.equal((await dt.check('u1', token)).trusted, false);
  const t2 = await dt.issue('u1', { ttlDays: 1 }); c.t += 2 * 86_400_000;
  assert.equal((await dt.check('u1', t2.token)).trusted, false);
});

test('recovery request: waiting period, cancel by owner, notifications', async () => {
  const c = clocked(); const events = [];
  const r = new RecoveryRequest({ store: new MemoryStore({ clock: c.now }), key: randomBytes(32), delayMs: 1000, clock: c.now, notify: async (u, e) => events.push([u, e.type]) });
  const a = await r.start({ userId: 'u1' });
  const early = await r.complete({ requestId: a.requestId });
  assert.equal(early.reason, 'too_early'); assert.ok(early.retryAfterMs > 0);
  c.t += 1001;
  const done = await r.complete({ requestId: a.requestId });
  assert.equal(done.ok, true); assert.ok(done.token);
  assert.equal((await r.complete({ requestId: a.requestId })).reason, 'completed');
  const b = await r.start({ userId: 'u1' });
  assert.equal((await r.cancel({ requestId: b.requestId, userId: 'attacker' })).ok, false);
  assert.equal((await r.cancel({ requestId: b.requestId, userId: 'u1' })).ok, true);
  c.t += 5000; assert.equal((await r.complete({ requestId: b.requestId })).reason, 'cancelled');
  assert.deepEqual(events.map((e) => e[1]), ['recovery_started', 'recovery_completed', 'recovery_started', 'recovery_cancelled']);
});

test('step-up: bound to user+action, single use, expiry', async () => {
  const c = clocked(); const s = new StepUp({ store: new MemoryStore({ clock: c.now }), key: randomBytes(32), clock: c.now });
  const t = await s.grant({ userId: 'u1', action: 'change-email' });
  assert.equal((await s.check(t, { userId: 'u2', action: 'change-email' })).reason, 'wrong_user');
  assert.equal((await s.check(t, { userId: 'u1', action: 'withdraw' })).reason, 'wrong_action');
  assert.equal((await s.check(t, { userId: 'u1', action: 'change-email' })).ok, true);
  assert.equal((await s.check(t, { userId: 'u1', action: 'change-email' })).reason, 'already_used');
  const multi = await s.grant({ userId: 'u1', action: 'view', singleUse: false });
  assert.equal((await s.check(multi, { userId: 'u1', action: 'view' })).ok, true);
  assert.equal((await s.check(multi, { userId: 'u1', action: 'view' })).ok, true);
  c.t += 400_000; assert.equal((await s.check(multi, { userId: 'u1', action: 'view' })).ok, false);
});
