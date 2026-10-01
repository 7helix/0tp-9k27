import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { OtpService, MemoryStore, MemoryProvider, AuditLog, createServer, randomBytes, base32Decode } from '../src/index.js';

const rawStatus = (port, method, path, headers = {}, body = '') => new Promise((resolve, reject) => {
  const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  req.on('error', reject); req.end(body);
});
const clocked = () => { const c = { t: 1_700_000_000_000, now: () => c.t }; return c; };
function rig(svcOpts = {}) {
  const c = clocked(); const store = new MemoryStore({ clock: c.now }); const provider = new MemoryProvider(); const audit = new AuditLog({ clock: c.now });
  const svc = new OtpService({ store, masterKey: randomBytes(32), pepper: 'r'.repeat(40), provider, audit, clock: c.now, ...svcOpts });
  return { c, store, provider, audit, svc, lastCode: () => provider.last().message.text.match(/\b(\d{6})\b/)[1] };
}
const wrongFor = (code) => (code === '000000' ? '111111' : '000000');

test('RED TEAM: sequential brute force never succeeds, and the real code dies with the attempt budget', async () => {
  const { svc, lastCode } = rig();
  await svc.sendOtp({ userId: 'victim', channel: 'sms', to: '+919876543210' }); const code = lastCode();
  let ok = 0; for (let i = 0; i < 60; i++) if ((await svc.verifyOtp({ userId: 'victim', code: String(100000 + i * 7919) })).ok) ok++;
  assert.equal(ok, 0);
  assert.equal((await svc.verifyOtp({ userId: 'victim', code })).ok, false, 'attacker who finally guesses right is still locked out');
});
test('RED TEAM: parallel guess storm through HTTP cannot exceed the attempt budget', async () => {
  const { svc, lastCode } = rig();
  const server = createServer(svc, { apiKey: 'k' }); await new Promise((r) => server.listen(0, '127.0.0.1', r)); const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await svc.sendOtp({ userId: 'victim', channel: 'email', to: 'v@x.com' }); const code = lastCode();
    const results = await Promise.all(Array.from({ length: 60 }, () => fetch(base + '/otp/verify', { method: 'POST', headers: { 'x-api-key': 'k' }, body: JSON.stringify({ userId: 'victim', code: wrongFor(code) }) }).then((r) => r.json())));
    assert.ok(results.filter((r) => r.reason === 'invalid_or_expired').length <= 5, 'only the attempt budget may be "spent" on real comparisons');
    assert.ok(results.every((r) => r.ok === false));
  } finally { server.close(); server.closeAllConnections?.(); }
});
test('RED TEAM: a code for user A / purpose "login" is useless for user B or purpose "reset"', async () => {
  const { svc, provider, lastCode } = rig();
  await svc.sendOtp({ userId: 'alice', channel: 'email', to: 'a@x.com' }); const code = lastCode();
  assert.equal((await svc.verifyOtp({ userId: 'bob', code })).ok, false);
  assert.equal((await svc.verifyOtp({ userId: 'alice', code, purpose: 'password-reset' })).ok, false);
  assert.equal((await svc.verifyOtp({ userId: 'alice', code })).ok, true);
  assert.equal(provider.sent.length, 1);
});
test('RED TEAM: parallel replay of one valid TOTP code succeeds exactly once', async () => {
  const { c, svc } = rig();
  await svc.enrollTotp({ userId: 'u', account: 'u@x.com' });
  assert.equal((await svc.confirmTotp({ userId: 'u', code: await svc._currentTotp('u') })).ok, true);
  c.t += 30_000; const code = await svc._currentTotp('u');
  const results = await Promise.all(Array.from({ length: 9 }, () => svc.verifyTotpCode({ userId: 'u', code })));
  assert.equal(results.filter((r) => r.ok).length, 1);
});
test('RED TEAM: backup-code double spend (parallel) yields exactly one success', async () => {
  const { svc } = rig(); const codes = await svc.generateBackupCodes('u');
  const results = await Promise.all(Array.from({ length: 8 }, () => svc.useBackupCode({ userId: 'u', code: codes[3] })));
  assert.equal(results.filter((r) => r.ok).length, 1);
});
test('RED TEAM: nothing sensitive is stored in plaintext or written to the audit log', async () => {
  const { svc, store, audit, provider, lastCode } = rig();
  await svc.sendOtp({ userId: 'u', channel: 'email', to: 'secret.person@example.com' }); const otp = lastCode();
  const { secret } = await svc.enrollTotp({ userId: 'u', account: 'u@x.com' });
  const rawSecretHex = base32Decode(secret).toString('hex');
  const backup = await svc.generateBackupCodes('u');
  await svc.verifyOtp({ userId: 'u', code: otp }); await svc.verifyOtp({ userId: 'u', code: wrongFor(otp) });
  const dump = JSON.stringify(store._dump()); const log = JSON.stringify(audit.entries);
  for (const needle of [otp, secret, rawSecretHex, ...backup, ...backup.map((b) => b.replace('-', ''))]) {
    assert.ok(!dump.includes(needle), `store leaks ${needle.slice(0, 4)}...`);
    assert.ok(!log.includes(needle), `audit log leaks ${needle.slice(0, 4)}...`);
  }
  assert.ok(!log.includes('secret.person@example.com'), 'audit log must hold masked destinations only');
  assert.ok(provider.sent.length === 1);
});
test('RED TEAM: stolen DB alone cannot decrypt TOTP seeds (wrong master key fails, ciphertext bound to user)', async () => {
  const a = rig(); const { secret } = await a.svc.enrollTotp({ userId: 'u1', account: 'x@x.com' });
  await a.store.update('totp:u1', (r) => ({ ...r, confirmed: true }));   // a fully enrolled user
  const rec = await a.store.get('totp:u1');
  // attacker copies user1's ciphertext into user2's record on the same server -> AAD mismatch
  await a.store.set('totp:u2', { ...rec });
  await assert.rejects(a.svc.verifyTotpCode({ userId: 'u2', code: '123456' }));
  // attacker with only the DB and a different key
  const b = new OtpService({ store: a.store, masterKey: randomBytes(32), pepper: 'r'.repeat(40), provider: a.provider });
  await assert.rejects(b.verifyTotpCode({ userId: 'u1', code: '123456' }));
  assert.ok(secret.length >= 32);
});
test('RED TEAM: HTTP surface - method/path confusion, prototype pollution, oversize, auth bypass attempts', async () => {
  const { svc } = rig(); const server = createServer(svc, { apiKey: 'correct-key' }); await new Promise((r) => server.listen(0, '127.0.0.1', r)); const base = `http://127.0.0.1:${server.address().port}`;
  const st = async (path, init) => (await fetch(base + path, init)).status;
  try {
    const port = server.address().port;
    for (const p of ['/otp/verify/', '//otp/verify', '/OTP/verify', '/otp/verify%00', '/otp/../otp/verify', '/otp/./verify', '/otp/verify;x', '/otp%2Fverify']) assert.equal(await rawStatus(port, 'POST', p, { 'x-api-key': 'correct-key' }, '{}'), 404, p);
    assert.equal(await st('/otp/verify', { method: 'GET', headers: { 'x-api-key': 'correct-key' } }), 404);
    // (leading/trailing whitespace is stripped by HTTP itself, so ' correct-key' IS the correct key - not a bypass)
    for (const k of ['', 'correct-ke', 'correct-keyy', 'CORRECT-KEY', 'xcorrect-key', 'correct-key x', 'correct key']) assert.equal(await st('/totp/enroll', { method: 'POST', headers: { 'x-api-key': k }, body: '{}' }), 401, JSON.stringify(k));
    assert.equal(await st('/totp/enroll', { method: 'POST', body: '{}' }), 401);
    assert.equal(await st('/totp/enroll', { method: 'POST', headers: { authorization: 'Bearer correct-key' }, body: '{}' }), 401);
    assert.equal(await st('/totp/enroll?x-api-key=correct-key', { method: 'POST', body: '{}' }), 401, 'keys in the query string are not accepted');
    const pollute = await fetch(base + '/totp/enroll', { method: 'POST', headers: { 'x-api-key': 'correct-key' }, body: '{"userId":"u","account":"a@b.co","__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}' });
    assert.equal(pollute.status, 200); assert.equal({}.polluted, undefined);
    assert.equal(await st('/otp/verify', { method: 'POST', headers: { 'x-api-key': 'correct-key' }, body: 'x'.repeat(50_000) }), 413);
    assert.equal(await st('/otp/verify', { method: 'POST', headers: { 'x-api-key': 'correct-key' }, body: '[1,2]' }), 400, 'arrays are not objects');
    assert.equal(await st('/otp/verify', { method: 'POST', headers: { 'x-api-key': 'correct-key' }, body: '"str"' }), 400);
    const r = await fetch(base + '/nope'); for (const h of ['x-content-type-options', 'cache-control', 'referrer-policy']) assert.ok(r.headers.get(h), h); assert.ok(!r.headers.get('x-powered-by'));
  } finally { server.close(); server.closeAllConnections?.(); }
});
