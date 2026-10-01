import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryStore, ChallengeOtp, MagicLink, BackupCodes, TransactionOtp, PushApproval, otpToSpeech, challengeResponse, signedToken, randomBytes } from '../src/index.js';

const PEPPER = 'p'.repeat(40);
function clocked() { const c = { t: 1_000_000, now: () => c.t }; return c; }

test('challenge OTP: success, single use, purpose binding', async () => {
  const c = clocked(); const store = new MemoryStore({ clock: c.now });
  const o = new ChallengeOtp({ store, pepper: PEPPER, clock: c.now });
  const { code } = await o.issue({ userId: 'u1', purpose: 'login' });
  assert.equal(code.length, 6);
  assert.equal((await o.verify({ userId: 'u1', purpose: 'reset', code })).ok, false);
  assert.equal((await o.verify({ userId: 'u1', purpose: 'login', code })).ok, true);
  assert.equal((await o.verify({ userId: 'u1', purpose: 'login', code })).ok, false);
});
test('challenge OTP: attempt cap, expiry, reissue invalidates', async () => {
  const c = clocked(); const store = new MemoryStore({ clock: c.now });
  const o = new ChallengeOtp({ store, pepper: PEPPER, clock: c.now });
  let { code } = await o.issue({ userId: 'u', purpose: 'p', maxAttempts: 3 });
  const wrong = code === '000000' ? '111111' : '000000';
  assert.equal((await o.verify({ userId: 'u', purpose: 'p', code: wrong })).attemptsLeft, 2);
  await o.verify({ userId: 'u', purpose: 'p', code: wrong });
  assert.equal((await o.verify({ userId: 'u', purpose: 'p', code: wrong })).reason, 'too_many_attempts');
  assert.equal((await o.verify({ userId: 'u', purpose: 'p', code })).ok, false, 'correct code dead after lockout');
  const first = await o.issue({ userId: 'u', purpose: 'p', ttlMs: 1000 });
  c.t += 2000;
  assert.equal((await o.verify({ userId: 'u', purpose: 'p', code: first.code })).ok, false);
  const a = await o.issue({ userId: 'u', purpose: 'q' }); const b = await o.issue({ userId: 'u', purpose: 'q' });
  if (a.code !== b.code) assert.equal((await o.verify({ userId: 'u', purpose: 'q', code: a.code })).ok, false);
});
test('challenge OTP: parallel guesses cannot beat the attempt cap', async () => {
  const store = new MemoryStore(); const o = new ChallengeOtp({ store, pepper: PEPPER });
  const { code } = await o.issue({ userId: 'u', purpose: 'p', maxAttempts: 5 });
  const wrong = code === '000000' ? '111111' : '000000';
  const results = await Promise.all(Array.from({ length: 50 }, () => o.verify({ userId: 'u', purpose: 'p', code: wrong })));
  assert.equal(results.filter((r) => r.reason === 'invalid').length, 4);
});
test('alphanumeric OTP uses unambiguous alphabet', async () => {
  const o = new ChallengeOtp({ store: new MemoryStore(), pepper: PEPPER });
  for (let i = 0; i < 50; i++) { const { code } = await o.issue({ userId: 'u', purpose: 'p', kind: 'alnum', length: 8 }); assert.match(code, /^[2-9A-HJKMNP-TW-Z]{8}$/); }
});

test('magic link: single use, purpose, expiry', async () => {
  const c = clocked(); const m = new MagicLink({ store: new MemoryStore({ clock: c.now }), pepper: PEPPER, baseUrl: 'https://x.io', clock: c.now });
  const { token, url } = await m.issue({ userId: 'u1' });
  assert.ok(url.startsWith('https://x.io/verify?token='));
  assert.equal((await m.consume(token, { purpose: 'reset' })).ok, false);
  assert.deepEqual(await m.consume(token), { ok: true, userId: 'u1' });
  assert.equal((await m.consume(token)).ok, false);
  const t2 = await m.issue({ userId: 'u1', ttlMs: 1000 }); c.t += 2000;
  assert.equal((await m.consume(t2.token)).ok, false);
});

test('backup codes: format, single use, regenerate invalidates', async () => {
  const b = new BackupCodes({ store: new MemoryStore() });
  const codes = await b.generate('u', 3);
  assert.match(codes[0], /^[2-9A-Z]{5}-[2-9A-Z]{5}$/);
  assert.equal((await b.consume('u', codes[0].toLowerCase())).ok, true);
  assert.equal((await b.consume('u', codes[0])).ok, false);
  assert.equal(await b.remaining('u'), 2);
  await b.generate('u', 3);
  assert.equal((await b.consume('u', codes[1])).ok, false);
});

test('transaction OTP: tampering with payee/amount fails', async () => {
  const t = new TransactionOtp({ store: new MemoryStore(), masterKey: randomBytes(32) });
  const tx = { amount: '100.00', currency: 'INR', payee: 'ACME-123' };
  const { nonce, code } = await t.issue({ userId: 'u', tx });
  assert.equal((await t.verify({ userId: 'u', tx: { ...tx, payee: 'EVIL-999' }, nonce, code })).ok, false);
  assert.equal((await t.verify({ userId: 'u', tx: { ...tx, amount: '9999' }, nonce, code })).ok, false);
  assert.equal((await t.verify({ userId: 'u', tx, nonce, code })).ok, true);
  assert.equal((await t.verify({ userId: 'u', tx, nonce, code })).ok, false);
});

test('push number matching: right tap approves, wrong tap denies for good', async () => {
  const p = new PushApproval({ store: new MemoryStore() });
  const r = await p.request({ userId: 'u' });
  assert.equal(r.deviceChoices.length, 3); assert.ok(r.deviceChoices.includes(r.displayNumber));
  assert.equal((await p.respond({ requestId: r.requestId, userId: 'other', choice: r.displayNumber })).ok, false);
  assert.equal((await p.respond({ requestId: r.requestId, userId: 'u', choice: r.displayNumber })).status, 'approved');
  const r2 = await p.request({ userId: 'u' });
  const wrong = r2.deviceChoices.find((n) => n !== r2.displayNumber);
  assert.equal((await p.respond({ requestId: r2.requestId, userId: 'u', choice: wrong })).status, 'denied');
  assert.equal((await p.respond({ requestId: r2.requestId, userId: 'u', choice: r2.displayNumber })).ok, false);
});

test('voice OTP text', () => {
  const s = otpToSpeech('4093', { brand: 'Acme' });
  assert.match(s, /four, zero, nine, three/); assert.match(s, /Again/);
});
test('challenge-response', () => {
  const k = randomBytes(32); const ch = challengeResponse.newChallenge();
  const r = challengeResponse.respond(k, ch);
  assert.equal(challengeResponse.verifyResponse(k, ch, r), true);
  assert.equal(challengeResponse.verifyResponse(k, '00000000' === ch ? '11111111' : '00000000', r), false);
});
test('signed token: tamper + expiry', () => {
  const k = randomBytes(32);
  const t = signedToken.sign(k, { sub: 'u1' }, { now: 1000, ttlMs: 500 });
  assert.equal(signedToken.verify(k, t, { now: 1200 }).payload.sub, 'u1');
  assert.equal(signedToken.verify(k, t, { now: 2000 }).ok, false);
  const [body, sig] = t.split('.');
  const forged = Buffer.from(JSON.stringify({ sub: 'admin', exp: 9e15 })).toString('base64url');
  assert.equal(signedToken.verify(k, `${forged}.${sig}`, { now: 1200 }).ok, false);
  assert.equal(signedToken.verify(randomBytes(32), t, { now: 1200 }).ok, false);
});
