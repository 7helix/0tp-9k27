import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  AuditLog,
  OtpService,
  MemoryStore,
  MemoryProvider,
  createServer,
  randomBytes,
} from '../src/index.js';
import { OtpFortressClient } from '../clients/js-client.js';
const run = promisify(execFile);
const node = (file, ...args) => run(process.execPath, [file, ...args], { encoding: 'utf8' }).then((r) => ({ code: 0, out: r.stdout.trim() }), (e) => ({ code: e.code, out: (e.stdout + e.stderr).trim() }));

test('otp-cli: gen-key, gen-secret, totp, verify, uri', async () => {
  const k = await node('bin/otp-cli.js', 'gen-key');
  assert.match(k.out, /OTP_MASTER_KEY=[0-9a-f]{64}\nOTP_PEPPER=[0-9a-f]{64}\nOTP_API_KEY=[0-9a-f]{48}/);
  const secret = (await node('bin/otp-cli.js', 'gen-secret')).out;
  assert.match(secret, /^[A-Z2-7]{32}$/);
  const code = (await node('bin/otp-cli.js', 'totp', secret)).out;
  assert.match(code, /^\d{6}$/);
  assert.equal((await node('bin/otp-cli.js', 'verify', secret, code)).out, 'VALID');
  assert.equal(
    (await node('bin/otp-cli.js', 'verify', secret, code === '000000' ? '111111' : '000000')).out,
    'INVALID',
  );
  assert.match(
    (await node('bin/otp-cli.js', 'uri', 'My App', 'a@b.com', secret)).out,
    /^otpauth:\/\/totp\/My%20App:a%40b\.com\?secret=/,
  );
  assert.match((await node('bin/otp-cli.js')).out, /otp-fortress CLI/);
});

test('audit-tool: keygen, sign, verify; detects tampering, truncation and refuses to sign a broken chain', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-'));
  const log = path.join(dir, 'audit.jsonl');
  const a = new AuditLog({ filePath: log });
  for (let i = 0; i < 8; i++) a.append('ev', { userId: `u${i}`, code: '123456' });
  assert.match((await node('bin/audit-tool.js', 'keygen', dir)).out, /private\.pem/);
  assert.equal(fs.statSync(path.join(dir, 'private.pem')).mode & 0o777, 0o600);
  assert.match((await node('bin/audit-tool.js', 'verify', log)).out, /^OK 8 entries$/);
  fs.writeFileSync(path.join(dir, 'cp.json'), (await node('bin/audit-tool.js', 'sign', log, path.join(dir, 'private.pem'))).out);
  const v = ['verify', log, '--checkpoint', path.join(dir, 'cp.json'), '--pubkey', path.join(dir, 'public.pem')];
  assert.match((await node('bin/audit-tool.js', ...v)).out, /checkpoint valid/);
  a.append('later', {}); // legitimate growth after the checkpoint is fine
  assert.match((await node('bin/audit-tool.js', ...v)).out, /^OK 9 entries/);
  const lines = fs.readFileSync(log, 'utf8').split('\n').filter(Boolean);
  fs.writeFileSync(log, lines.slice(0, 3).join('\n') + '\n'); // attacker truncates the tail
  const t = await node('bin/audit-tool.js', ...v);
  assert.equal(t.code, 1);
  assert.match(t.out, /truncated/);
  const tampered = lines.map((l, i) => (i === 2 ? l.replace('"u2"', '"evil"') : l));
  fs.writeFileSync(log, tampered.join('\n') + '\n');
  const b = await node('bin/audit-tool.js', 'verify', log);
  assert.equal(b.code, 1);
  assert.match(b.out, /chain broken at entry 2/);
  assert.match(
    (await node('bin/audit-tool.js', 'sign', log, path.join(dir, 'private.pem'))).out,
    /REFUSING to sign/,
  );
});

test('HMAC-authenticated server accepts the JS client and the Python client (cross-language signature compatibility)', async () => {
  const secret = randomBytes(32);
  const store = new MemoryStore();
  const svc = new OtpService({
    store: new MemoryStore(),
    masterKey: randomBytes(32),
    pepper: 'c'.repeat(40),
    provider: new MemoryProvider(),
  });
  const server = createServer(svc, { hmac: { keys: { 'backend-1': secret }, store } });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const js = new OtpFortressClient({ baseUrl: base, hmac: { keyId: 'backend-1', secret } });
    assert.equal((await js.generateBackupCodes('jsuser')).codes.length, 10);
    await assert.rejects(
      new OtpFortressClient({ baseUrl: base, hmac: { keyId: 'backend-1', secret: randomBytes(32) } }).generateBackupCodes('x'),
      (e) => e.status === 401,
    );
    const py = await run('python3', ['-c', `
import sys; sys.path.insert(0, 'clients')
from otp_fortress_client import OtpFortressClient, OtpApiError
c = OtpFortressClient('${base}', hmac_key_id='backend-1', hmac_secret=bytes.fromhex('${secret.toString('hex')}'))
r = c.generate_backup_codes('pyuser'); assert len(r['codes']) == 10
assert c.verify_backup_code('pyuser', r['codes'][0])['ok'] is True
try:
    OtpFortressClient('${base}', hmac_key_id='backend-1', hmac_secret=b'wrong' * 8).generate_backup_codes('x'); raise SystemExit('should fail')
except OtpApiError as e:
    assert e.status == 401
print('py-hmac-ok')
`], { encoding: 'utf8' });
    assert.equal(py.stdout.trim(), 'py-hmac-ok');
  } finally {
    server.close(); server.closeAllConnections?.();
  }
});
