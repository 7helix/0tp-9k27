import test from 'node:test';
import assert from 'node:assert/strict';
import {
  OtpService,
  MemoryStore,
  MemoryProvider,
  AuditLog,
  randomBytes,
  createServer,
  base32Decode,
  totp,
} from '../src/index.js';

function make() {
  const c = { t: 1_700_000_000_000, now: () => c.t };
  const provider = new MemoryProvider();
  const audit = new AuditLog({ clock: c.now });
  const svc = new OtpService({
    store: new MemoryStore({ clock: c.now }),
    masterKey: randomBytes(32),
    pepper: 'x'.repeat(40),
    provider,
    audit,
    brand: 'Acme',
    domain: 'acme.io',
    clock: c.now,
  });
  return { c, provider, audit, svc };
}

test('service: email OTP flow, masked response, rate limit, lockout', async () => {
  const { provider, svc, audit } = make();
  const r = await svc.sendOtp({ userId: 'u1', channel: 'email', to: 'alice@example.com' });
  assert.equal(r.sentTo, 'a***@example.com');
  const code = provider.last().message.text.match(/\b(\d{6})\b/)[1];
  assert.equal((await svc.verifyOtp({ userId: 'u1', code })).ok, true);
  await svc.sendOtp({ userId: 'u1', channel: 'email', to: 'alice@example.com' });
  await svc.sendOtp({ userId: 'u1', channel: 'email', to: 'alice@example.com' });
  assert.equal(
    (await svc.sendOtp({ userId: 'u1', channel: 'email', to: 'alice@example.com' })).reason,
    'rate_limited',
  );
  // audit never contains raw codes
  assert.ok(!JSON.stringify(audit.entries).includes(code));
  assert.equal(AuditLog.verify(audit.entries).ok, true);
});
test('service: SMS uses origin-bound format', async () => {
  const { provider, svc } = make();
  await svc.sendOtp({ userId: 'u', channel: 'sms', to: '+919876543210' });
  assert.match(provider.last().message.text, /@acme\.io #\d{6}$/);
});
test('service: TOTP enroll -> confirm -> verify, replay blocked, wrong codes lock out', async () => {
  const { c, svc } = make();
  const { secret, uri } = await svc.enrollTotp({ userId: 'u', account: 'a@b.com' });
  assert.match(uri, /^otpauth:\/\/totp\/Acme:/);
  assert.equal((await svc.verifyTotpCode({ userId: 'u', code: '123456' })).reason, 'not_enrolled');
  const code = totp(base32Decode(secret), { time: c.t });
  assert.equal((await svc.confirmTotp({ userId: 'u', code })).ok, true);
  assert.equal((await svc.verifyTotpCode({ userId: 'u', code })).reason, 'replayed');
  c.t += 30_000;
  assert.equal((await svc.verifyTotpCode({ userId: 'u', code: await svc._currentTotp('u') })).ok, true);
  c.t += 30_000;
  const good = await svc._currentTotp('u');
  for (let i = 0; i < 5; i++) await svc.verifyTotpCode({
    userId: 'u',
    code: '000000' === good ? '111111' : '000000',
  });
  assert.equal((await svc.verifyTotpCode({ userId: 'u', code: good })).reason, 'locked');
});
test('service: backup codes', async () => {
  const { svc } = make();
  const codes = await svc.generateBackupCodes('u');
  assert.equal(codes.length, 10);
  const r = await svc.useBackupCode({ userId: 'u', code: codes[0] });
  assert.deepEqual([r.ok, r.remaining], [true, 9]);
  assert.equal((await svc.useBackupCode({ userId: 'u', code: codes[0] })).ok, false);
});

test('HTTP API: auth, validation, happy path, oversize body', async () => {
  const { svc, provider } = make();
  const server = createServer(svc, { apiKey: 'k3y' });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = (path, body, key = 'k3y') => fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': key }, body: JSON.stringify(body) });
  try {
    assert.equal((await fetch(base + '/health')).status, 200);
    assert.equal((await call('/otp/send', {}, 'wrong')).status, 401);
    assert.equal((await call('/otp/send', { userId: 'u' })).status, 400);
    assert.equal((await call('/otp/send', { userId: 'u', channel: 'fax', to: 'x' })).status, 400);
    const sent = await call('/otp/send', { userId: 'u', channel: 'email', to: 'bob@x.com' });
    assert.equal(sent.status, 200);
    const code = provider.last().message.text.match(/\b(\d{6})\b/)[1];
    assert.deepEqual(await (await call('/otp/verify', { userId: 'u', code })).json(), { ok: true });
    assert.equal((await call('/otp/verify', { userId: 'u', code: 'x'.repeat(20000) })).status, 413);
    assert.equal((await fetch(base + '/nope')).status, 404);
  } finally {
    server.close(); server.closeAllConnections?.();
  }
});
