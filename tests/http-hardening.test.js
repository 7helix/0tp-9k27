import test from 'node:test';
import assert from 'node:assert/strict';
import {
  OtpService,
  MemoryStore,
  MemoryProvider,
  AuditLog,
  AnomalyDetector,
  Metrics,
  createServer,
  randomBytes,
  signRequest,
  verifyRequest,
  parseIp,
  parseCidr,
  ipInCidr,
  matchesAny,
  clientIp,
} from '../src/index.js';

test('CIDR: IPv4, IPv6, IPv4-mapped, invalid input', () => {
  assert.ok(ipInCidr('10.1.2.3', '10.0.0.0/8'));
  assert.ok(!ipInCidr('11.0.0.1', '10.0.0.0/8'));
  assert.ok(ipInCidr('192.168.1.77', '192.168.1.77'));
  assert.ok(ipInCidr('1.2.3.4', '0.0.0.0/0'));
  assert.ok(ipInCidr('::ffff:10.9.9.9', '10.0.0.0/8'), 'mapped v4 matches v4 rule');
  assert.ok(ipInCidr('2001:db8::1', '2001:db8::/32'));
  assert.ok(!ipInCidr('2001:db9::1', '2001:db8::/32'));
  assert.ok(ipInCidr('::1', '::1/128'));
  assert.ok(!ipInCidr('::1', '10.0.0.0/8'));
  assert.ok(!ipInCidr('10.0.0.1', '::/0'));
  assert.equal(parseIp('999.1.1.1'), null);
  assert.equal(parseIp('1.2.3'), null);
  assert.equal(parseIp('zzz'), null);
  assert.equal(parseIp(null), null);
  assert.equal(parseIp('1:2:3:4:5:6:7:8:9'), null);
  assert.equal(parseIp('1::2::3'), null);
  assert.throws(() => parseCidr('10.0.0.0/33'));
  assert.throws(() => parseCidr('nope/8'));
  assert.ok(matchesAny('127.0.0.1', ['10.0.0.0/8', '127.0.0.0/8']));
});
test('clientIp trusts X-Forwarded-For only from trusted proxies, walking right to left', () => {
  const req = (peer, xff) => ({
    socket: { remoteAddress: peer },
    headers: xff ? { 'x-forwarded-for': xff } : {},
  });
  assert.equal(clientIp(req('203.0.113.9', '1.1.1.1'), []), '203.0.113.9');
  assert.equal(
    clientIp(req('203.0.113.9', '1.1.1.1'), ['10.0.0.0/8']),
    '203.0.113.9',
    'untrusted peer: header ignored',
  );
  assert.equal(clientIp(req('10.0.0.5', '198.51.100.7'), ['10.0.0.0/8']), '198.51.100.7');
  assert.equal(
    clientIp(req('10.0.0.5', '6.6.6.6, 198.51.100.7, 10.0.0.9'), ['10.0.0.0/8']),
    '198.51.100.7',
    'client-supplied left entries are spoofable',
  );
  assert.equal(clientIp(req('10.0.0.5', 'garbage'), ['10.0.0.0/8']), '10.0.0.5');
});

test('metrics text exposition + label escaping', () => {
  const m = new Metrics();
  m.inc('req_total', { route: '/a', status: 200 }, 1, 'Requests');
  m.inc('req_total', { route: '/a', status: 200 });
  m.inc('req_total', { route: 'we"ird\\\n' });
  const t = m.render();
  assert.match(t, /# TYPE req_total counter/);
  assert.match(t, /req_total\{route="\/a",status="200"\} 2/);
  assert.match(t, /route="we\\"ird\\\\\\n"/);
});

test('signed requests: valid, tampered body/path/method, stale, replay, unknown key, bad signature', async () => {
  const keys = { 'svc-backend-1': randomBytes(32) };
  const store = new MemoryStore();
  const now = 1_700_000_000_000;
  const body = JSON.stringify({ userId: 'u1' });
  const sign = (o = {}) => signRequest({
    method: 'POST',
    path: '/otp/send',
    body,
    keyId: 'svc-backend-1',
    secret: keys['svc-backend-1'],
    now,
    ...o,
  });
  const check = (headers, o = {}) => verifyRequest({
    method: 'POST',
    path: '/otp/send',
    body,
    headers,
    keys,
    store,
    now,
    ...o,
  });
  const h = sign();
  assert.deepEqual(await check(h), { ok: true, keyId: 'svc-backend-1' });
  assert.equal((await check(h)).reason, 'replayed');
  assert.equal((await check(sign(), { body: JSON.stringify({ userId: 'admin' }) })).reason, 'bad_signature');
  assert.equal((await check(sign(), { path: '/otp/verify' })).reason, 'bad_signature');
  assert.equal((await check(sign(), { method: 'GET' })).reason, 'bad_signature');
  assert.equal((await check(sign({ now: now - 120_000 }))).reason, 'stale');
  assert.equal((await check({ ...sign(), 'x-otpf-key-id': 'nope' })).reason, 'unknown_key');
  assert.equal((await check({ ...sign(), 'x-otpf-key-id': '__proto__' })).reason, 'unknown_key');
  assert.equal((await check({ ...sign(), 'x-otpf-signature': 'AAAA' })).reason, 'bad_signature');
  assert.equal((await check({})).reason, 'missing_or_malformed');
  // forged requests must not burn a legitimate nonce
  const good = sign({ nonce: 'legit-nonce-123456' });
  await check({ ...good, 'x-otpf-signature': 'forged' });
  assert.equal((await check(good)).ok, true);
});

function boot(opts = {}, svcOpts = {}) {
  const provider = new MemoryProvider();
  const audit = new AuditLog();
  const svc = new OtpService({
    store: new MemoryStore(),
    masterKey: randomBytes(32),
    pepper: 'h'.repeat(40),
    provider,
    audit,
    ...svcOpts,
  });
  const server = createServer(svc, opts);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, svc, provider, audit, base: `http://127.0.0.1:${server.address().port}` })));
}
const close = (s) => { s.close(); s.closeAllConnections?.(); };

test('server requires some authentication to be configured', () => { assert.throws(() => createServer({}, {}), /apiKey/); });

test('HTTP: HMAC-signed mode end to end (and static key is not accepted)', async () => {
  const secret = randomBytes(32);
  const hmac = { keys: { 'backend-key-1': secret }, store: new MemoryStore() };
  const { server, base, provider } = await boot({ hmac });
  try {
    const call = async (path, payload, { tamper = false, headers } = {}) => {
      const body = JSON.stringify(payload);
      const h = headers ?? signRequest({ method: 'POST', path, body, keyId: 'backend-key-1', secret });
      return fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', ...h }, body: tamper ? body.replace('u1', 'u2') : body });
    };
    assert.equal((await call('/otp/send', { userId: 'u1', channel: 'email', to: 'a@b.com' })).status, 200);
    const code = provider.last().message.text.match(/\b(\d{6})\b/)[1];
    const signed = signRequest({
      method: 'POST',
      path: '/otp/verify',
      body: JSON.stringify({ userId: 'u1', code }),
      keyId: 'backend-key-1',
      secret,
    });
    assert.equal((await call('/otp/verify', { userId: 'u1', code }, { headers: signed })).status, 200);
    assert.equal(
      (await call('/otp/verify', { userId: 'u1', code }, { headers: signed })).status,
      401,
      'replayed signature',
    );
    assert.equal(
      (await call('/otp/send', { userId: 'u1', channel: 'email', to: 'a@b.com' }, { tamper: true })).status,
      401,
      'body tampered in transit',
    );
    assert.equal(
      (await fetch(base + '/otp/send', { method: 'POST', headers: { 'x-api-key': 'anything' }, body: '{}' })).status,
      401,
    );
    assert.equal((await fetch(base + '/health')).status, 200);
  } finally {
    close(server);
  }
});

test('HTTP: IP allowlist, spoofed X-Forwarded-For, trusted proxy', async () => {
  const a = await boot({ apiKey: 'k', allowedCidrs: ['10.0.0.0/8'] });
  const b = await boot({ apiKey: 'k', allowedCidrs: ['127.0.0.0/8'] });
  const c = await boot({ apiKey: 'k', allowedCidrs: ['10.0.0.0/8'], trustedProxies: ['127.0.0.1'] });
  try {
    assert.equal((await fetch(a.base + '/health')).status, 403);
    assert.equal(
      (await fetch(a.base + '/health', { headers: { 'x-forwarded-for': '10.1.1.1' } })).status,
      403,
      'spoofed header ignored',
    );
    assert.equal((await fetch(b.base + '/health')).status, 200);
    assert.equal(
      (await fetch(c.base + '/health', { headers: { 'x-forwarded-for': '10.1.1.1' } })).status,
      200,
      'trusted proxy: header honoured',
    );
    assert.equal(
      (await fetch(c.base + '/health', { headers: { 'x-forwarded-for': '8.8.8.8' } })).status,
      403,
    );
  } finally {
    close(a.server); close(b.server); close(c.server);
  }
});

test('HTTP: uniform errors, strict mode, metrics endpoint auth + content', async () => {
  const metrics = new Metrics();
  const { server, base, provider } = await boot({ apiKey: 'k', metrics });
  const post = (p, b) => fetch(base + p, { method: 'POST', headers: { 'x-api-key': 'k', 'content-type': 'application/json' }, body: JSON.stringify(b) }).then((r) => r.json());
  try {
    const unknown = await post('/otp/verify', { userId: 'ghost', code: '123456' });
    await post('/otp/send', { userId: 'real', channel: 'email', to: 'r@x.com' });
    const wrong = await post('/otp/verify', { userId: 'real', code: '000000' });
    assert.deepEqual(unknown, { ok: false, reason: 'invalid_or_expired' });
    assert.deepEqual(wrong, unknown, 'unknown user and wrong code are indistinguishable');
    assert.equal((await post('/totp/verify', { userId: 'ghost', code: '123456' })).reason, 'not_enrolled');
    assert.equal((await fetch(base + '/metrics')).status, 401);
    const m = await (await fetch(base + '/metrics', { headers: { 'x-api-key': 'k' } })).text();
    assert.match(
      m,
      /otpf_verify_total\{result="invalid_or_expired",route="\/otp\/verify"\} 2|otpf_verify_total\{route="\/otp\/verify",result="invalid_or_expired"\} 2/,
    );
    assert.match(m, /otpf_http_requests_total/);
    assert.ok(!m.includes('/nonexistent'));
  } finally {
    close(server);
  }
  const strict = await boot({ apiKey: 'k', uniformErrors: 'strict' });
  try {
    const r = await fetch(strict.base + '/totp/verify', { method: 'POST', headers: { 'x-api-key': 'k' }, body: JSON.stringify({ userId: 'ghost', code: '123456' }) });
    assert.equal((await r.json()).reason, 'invalid_or_expired');
  } finally {
    close(strict.server);
  }
});

test('HTTP: response-time padding on verify routes only', async () => {
  const { server, base } = await boot({ apiKey: 'k', minVerifyMs: 80 });
  const t = async (p) => { const t0 = Date.now(); await fetch(base + p, { method: 'POST', headers: { 'x-api-key': 'k' }, body: JSON.stringify({ userId: 'u', code: '123456' }) }); return Date.now() - t0; };
  try {
    assert.ok(await t('/otp/verify') >= 75);
    assert.ok(await t('/totp/enroll') < 75, 'non-verify route not padded');
  } finally {
    close(server);
  }
});

test('HTTP: credential-stuffing IP is cut off; body-supplied "ip" cannot spoof or evade', async () => {
  const store = new MemoryStore();
  const anomaly = new AnomalyDetector({ store, distinctUsers: 3 });
  const { server, base } = await boot({ apiKey: 'k' }, { anomaly });
  const verify = (userId, extra = {}) => fetch(base + '/totp/verify', { method: 'POST', headers: { 'x-api-key': 'k' }, body: JSON.stringify({ userId, code: '123456', ...extra }) }).then((r) => r.json());
  try {
    // Enroll three users so that wrong codes count as real failures.
    for (const u of ['a1', 'b2', 'c3']) { await fetch(base + '/totp/enroll', { method: 'POST', headers: { 'x-api-key': 'k' }, body: JSON.stringify({ userId: u, account: `${u}@x.com` }) }); }
    // 'enrolled but unconfirmed' users yield nothing_to_confirm... confirm path counts failures:
    const conf = (u, extra = {}) => fetch(base + '/totp/confirm', { method: 'POST', headers: { 'x-api-key': 'k' }, body: JSON.stringify({ userId: u, code: '000000', ...extra }) }).then((r) => r.json());
    await conf('a1', { ip: '1.1.1.1' });
    await conf('b2', { ip: '2.2.2.2' });
    await conf('c3', { ip: '3.3.3.3' }); // spoofed ips are ignored
    assert.equal((await conf('a1', { ip: '9.9.9.9' })).reason, 'suspicious_ip');
    assert.equal((await verify('zz', { ip: '8.8.8.8' })).reason, 'suspicious_ip');
  } finally {
    close(server);
  }
});
