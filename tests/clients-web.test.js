import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile); // async: the server shares this process, so never block the event loop
import {
  OtpService,
  MemoryStore,
  MemoryProvider,
  randomBytes,
  createServer,
  base32Encode,
  base32Decode,
  totp,
} from '../src/index.js';
import { OtpFortressClient, OtpApiError } from '../clients/js-client.js';
import { base32ToBytes, hotpWeb, totpWeb } from '../web/totp-web.js';

test('web authenticator (WebCrypto) matches RFC vectors and the Node core', async () => {
  const S1 = new TextEncoder().encode('12345678901234567890');
  assert.equal(await hotpWeb(S1, 0), '755224');
  assert.equal(await totpWeb(S1, { time: 59_000, digits: 8 }), '94287082');
  const S256 = new TextEncoder().encode('12345678901234567890123456789012');
  assert.equal(await totpWeb(S256, { time: 59_000, digits: 8, algorithm: 'SHA-256' }), '46119246');
  const k = randomBytes(20), t = 1_700_000_123_000;
  assert.equal(await totpWeb(base32ToBytes(base32Encode(k)), { time: t }), totp(k, { time: t }));
  assert.throws(() => base32ToBytes('0189'));
});

test('JS client + Python client against a live server', async () => {
  const provider = new MemoryProvider();
  const svc = new OtpService({
    store: new MemoryStore(),
    masterKey: randomBytes(32),
    pepper: 'q'.repeat(40),
    provider,
  });
  const server = createServer(svc, { apiKey: 'k3y' });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const c = new OtpFortressClient({ baseUrl: base, apiKey: 'k3y' });
    const sent = await c.sendOtp('u1', 'email', 'bob@example.com');
    assert.equal(sent.ok, true);
    const code = provider.last().message.text.match(/\b(\d{6})\b/)[1];
    assert.deepEqual(await c.verifyOtp('u1', code), { ok: true });
    const enr = await c.enrollTotp('u2', 'x@y.com');
    assert.ok(base32Decode(enr.secret).length === 20);
    assert.equal((await c.verifyTotp('u2', '123456')).reason, 'not_enrolled');
    await assert.rejects(
      new OtpFortressClient({ baseUrl: base, apiKey: 'nope' }).verifyOtp('u1', '123456'),
      (e) => e instanceof OtpApiError && e.status === 401,
    );
    await assert.rejects(
      c.verifyOtp('bad user!', '123456'),
      (e) => e.status === 400 && e.message === 'invalid_userId',
    );
    // Python client, same server
    const py = await execFileAsync('python3', ['-c', `
import sys; sys.path.insert(0, 'clients')
from otp_fortress_client import OtpFortressClient, OtpApiError
c = OtpFortressClient('${base}', 'k3y')
r = c.generate_backup_codes('pyuser'); assert len(r['codes']) == 10
assert c.verify_backup_code('pyuser', r['codes'][0])['ok'] is True
assert c.verify_backup_code('pyuser', r['codes'][0])['ok'] is False
try:
    OtpFortressClient('${base}', 'wrong').verify_otp('u', '123456'); raise SystemExit('should have raised')
except OtpApiError as e:
    assert e.status == 401
print('python-client-ok')
`], { encoding: 'utf8' });
    assert.equal(py.stdout.trim(), 'python-client-ok');
  } finally {
    server.close(); server.closeAllConnections?.();
  }
});

test('Python port passes RFC vectors and agrees with JS', () => {
  const out = execFileSync('python3', ['-m', 'unittest', '-v'], { cwd: 'ports/python', encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  assert.ok(true, out); // unittest exits non-zero on failure, which execFileSync turns into a throw
});
